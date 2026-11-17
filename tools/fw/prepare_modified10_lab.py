"""Deterministically build and verify Modified10 from both Stock C3.80 and Modified9."""
from pathlib import Path
import argparse, binascii, hashlib, json
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
SIZE = 33502842
STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M9_SHA = "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def update_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    assert binascii.crc_hqx(bytes(buf), 0) == 0
    return f"{crc:04x}"


def disasm_snippet(md: Cs, blob: bytes, addr: int) -> list[str]:
    if addr == 0x1002d884:
        code = blob[:64]
        lit = blob[64:68].hex()
        ins = [f"0x{i.address:08x}: {i.mnemonic} {i.op_str}".strip() for i in md.disasm(code, addr)]
        ins.append(f"0x1002d8c4: .word 0x{int.from_bytes(blob[64:68], 'little'):08x} ({lit})")
        return ins
    return [f"0x{i.address:08x}: {i.mnemonic} {i.op_str}".strip() for i in md.disasm(blob, addr)]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m9 = (ROOT / "outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN").read_bytes()
    recipe = json.loads((ROOT / "patches/z6-c380-modified10-fullsize-convergence.json").read_text(encoding="utf8"))
    cand = recipe["candidates"][0]
    edits = cand["edits"]

    assert len(stock) == len(m9) == SIZE
    assert sha(stock) == STOCK_SHA and binascii.crc_hqx(stock, 0) == 0
    assert sha(m9) == M9_SHA and binascii.crc_hqx(m9, 0) == 0

    # Check non-overlapping sorted ranges within module body
    spans = []
    for e in edits:
        addr = int(e["address"], 16)
        old_b = bytes.fromhex(e["before"])
        new_b = bytes.fromhex(e["after"])
        assert len(old_b) == len(new_b) > 0
        off = addr - BASE
        assert 0 <= off and off + len(old_b) <= SIZE - 2
        spans.append((off, off + len(old_b), addr, e["group"], old_b, new_b, e))
    spans.sort()
    for (_, prev_end, *_), (cur_start, *_) in zip(spans, spans[1:]):
        assert prev_end <= cur_start, "Overlapping edit spans!"

    # Build A: directly from Stock C3.80
    from_stock = bytearray(stock)
    for off, end, addr, grp, old_b, new_b, _ in spans:
        assert bytes(from_stock[off:end]) == old_b, f"Stock anchor mismatch at {addr:#x}"
        from_stock[off:end] = new_b
    crc_hex = update_crc(from_stock)

    # Build B: incrementally from Modified9 using only the 7 new sites
    delta_groups = {"fullsize_front_raw_preserve", "modified2_vignette_neutral", "modified3_spatial17_neutral"}
    from_m9 = bytearray(m9)
    delta_sites = []
    for off, end, addr, grp, old_b, new_b, meta in spans:
        if grp in delta_groups:
            assert bytes(from_m9[off:end]) == old_b, f"Modified9 anchor mismatch at {addr:#x}"
            from_m9[off:end] = new_b
            delta_sites.append((off, end, addr, grp, old_b, new_b, meta))
        else:
            assert bytes(from_m9[off:end]) == new_b, f"Modified9 inherited site mismatch at {addr:#x}"
    crc_m9_delta = update_crc(from_m9)

    m10_bytes = bytes(from_stock)
    assert m10_bytes == bytes(from_m9), "Build from Stock vs Modified9 diverged!"
    m10_sha = sha(m10_bytes)
    assert crc_hex == crc_m9_delta

    # Exact byte-level rollback verification to Modified9 and Stock
    rev_m9 = bytearray(m10_bytes)
    for off, end, _, _, old_b, _, _ in delta_sites:
        rev_m9[off:end] = old_b
    update_crc(rev_m9)
    assert bytes(rev_m9) == m9, "Rollback to Modified9 failed!"

    rev_stock = bytearray(m10_bytes)
    for off, end, _, _, old_b, _, _ in spans:
        rev_stock[off:end] = old_b
    update_crc(rev_stock)
    assert bytes(rev_stock) == stock, "Rollback to Stock failed!"

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    site_details = []
    for off, end, addr, grp, old_b, new_b, meta in spans:
        diff_b = sum(x != y for x, y in zip(old_b, new_b))
        site_details.append({
            "address": f"0x{addr:08x}",
            "file_offset": f"0x{off:08x}",
            "group": grp,
            "span_bytes": len(old_b),
            "changed_bytes": diff_b,
            "before_hex": old_b.hex(),
            "after_hex": new_b.hex(),
            "disasm_before": ["zero_padding_68_bytes"] if addr == 0x1002d884 else disasm_snippet(md, old_b, addr),
            "disasm_after": disasm_snippet(md, new_b, addr),
        })

    diff_vs_stock = [i for i, (a, b) in enumerate(zip(stock, m10_bytes)) if a != b]
    diff_vs_m9 = [i for i, (a, b) in enumerate(zip(m9, m10_bytes)) if a != b]

    out_bin = args.output / "modified10-candidate.bi"
    out_bin.write_bytes(m10_bytes)
    (args.output / "prepare_modified10_lab.py").write_bytes(Path(__file__).read_bytes())

    manifest = {
        "ok": True,
        "candidate": "modified10",
        "candidate_id": cand["id"],
        "module_path": out_bin.relative_to(ROOT).as_posix(),
        "sha256": m10_sha,
        "bytes": SIZE,
        "crc16": crc_hex,
        "crc_residue": binascii.crc_hqx(m10_bytes, 0),
        "stock_sha256": STOCK_SHA,
        "parent_modified9_sha256": M9_SHA,
        "edit_site_count": len(spans),
        "delta_site_count_vs_modified9": len(delta_sites),
        "changed_code_bytes_vs_stock": sum(i < SIZE - 2 for i in diff_vs_stock),
        "total_changed_bytes_vs_stock": len(diff_vs_stock),
        "changed_code_bytes_vs_modified9": sum(i < SIZE - 2 for i in diff_vs_m9),
        "total_changed_bytes_vs_modified9": len(diff_vs_m9),
        "independent_dual_build_match": True,
        "exact_rollback_to_modified9": True,
        "exact_rollback_to_stock": True,
        "sites": site_details,
    }
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    print(json.dumps({
        "ok": True,
        "sha256": m10_sha,
        "crc16": crc_hex,
        "changed_vs_stock": len(diff_vs_stock),
        "changed_code_vs_m9": manifest["changed_code_bytes_vs_modified9"],
        "changed_total_vs_m9": len(diff_vs_m9),
    }))


if __name__ == "__main__":
    main()

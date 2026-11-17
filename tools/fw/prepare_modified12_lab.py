"""Deterministically build and verify Modified12 from Stock C3.80, Modified9, and Modified10."""
from pathlib import Path
import argparse, binascii, hashlib, json
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
SIZE = 33502842
STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M9_SHA = "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c"
M10_SHA = "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4"
M11_SHA = "4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a"


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
    out_dir = args.output.resolve()
    out_dir.mkdir(parents=True, exist_ok=False)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m9 = (ROOT / "outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN").read_bytes()
    m10 = (ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN").read_bytes()
    m11 = (ROOT / "outputs/Z6-C380-modified11-reviewed-2026-11-14/01_TEST_MODIFIED11/EG162080.BIN").read_bytes()
    recipe = json.loads((ROOT / "patches/z6-c380-modified12-production-convergence.json").read_text(encoding="utf8"))
    cand = recipe["candidates"][0]
    edits = cand["edits"]

    assert len(stock) == len(m9) == len(m10) == len(m11) == SIZE
    assert sha(stock) == STOCK_SHA and binascii.crc_hqx(stock, 0) == 0
    assert sha(m9) == M9_SHA and binascii.crc_hqx(m9, 0) == 0
    assert sha(m10) == M10_SHA and binascii.crc_hqx(m10, 0) == 0
    assert sha(m11) == M11_SHA and binascii.crc_hqx(m11, 0) == 0

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
    crc_stock = update_crc(from_stock)

    # Build B: incrementally from Modified10 using only the 1 new site (modified12_frontend_digital_gain_unity)
    from_m10 = bytearray(m10)
    delta_site_m10 = None
    for off, end, addr, grp, old_b, new_b, meta in spans:
        if grp.startswith("modified12_frontend_digital_gain_unity"):
            assert bytes(from_m10[off:end]) == old_b, f"Modified10 anchor mismatch at {addr:#x}"
            from_m10[off:end] = new_b
            delta_site_m10 = (off, end, addr, grp, old_b, new_b, meta)
        else:
            assert bytes(from_m10[off:end]) == new_b, f"Modified10 inherited site mismatch at {addr:#x}"
    crc_m10 = update_crc(from_m10)

    m11_bytes = bytes(from_stock)
    assert m11_bytes == bytes(from_m10), "Build from Stock vs Modified10 diverged!"
    m11_sha = sha(m11_bytes)
    assert crc_stock == crc_m10

    # Exact byte-level rollback verification to Modified10
    rev_m10 = bytearray(m11_bytes)
    off, end, _, _, old_b, _, _ = delta_site_m10
    rev_m10[off:end] = old_b
    update_crc(rev_m10)
    assert bytes(rev_m10) == m10, "Rollback to Modified10 failed!"

    # Exact byte-level rollback verification to Stock C3.80
    rev_stock = bytearray(m11_bytes)
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

    diff_vs_stock = [i for i, (a, b) in enumerate(zip(stock, m11_bytes)) if a != b]
    diff_vs_m10 = [i for i, (a, b) in enumerate(zip(m10, m11_bytes)) if a != b]

    out_bin = out_dir / "modified12-candidate.bi"
    out_bin.write_bytes(m11_bytes)
    (args.output / "prepare_modified12_lab.py").write_bytes(Path(__file__).read_bytes())

    manifest = {
        "ok": True,
        "candidate": "modified12",
        "candidate_id": cand["id"],
        "module_path": out_bin.relative_to(ROOT).as_posix(),
        "sha256": m11_sha,
        "size_bytes": len(m11_bytes),
        "crc16": crc_stock,
        "total_sites": len(spans),
        "total_spans_bytes": sum(s["span_bytes"] for s in site_details),
        "total_changed_bytes_vs_stock": len(diff_vs_stock),
        "total_changed_bytes_vs_m10": len(diff_vs_m10),
        "sites": site_details,
        "verified_dual_build": True,
        "verified_rollback_to_m10": True,
        "verified_rollback_to_stock": True,
    }
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    print(f"Modified12 successfully prepared: SHA256={m11_sha}, CRC16={crc_stock}")
    print(f"Sites: {len(spans)}, Changed bytes vs Stock: {len(diff_vs_stock)}, Changed bytes vs M10: {len(diff_vs_m10)}")


if __name__ == "__main__":
    main()

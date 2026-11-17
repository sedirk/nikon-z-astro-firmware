"""Deterministically build and verify Modified15 (Modified13 + 30-600s v2 preserving Stock <=109 0x204 cap)."""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
from pathlib import Path
import sys

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from z6_m600_tables import BASE, SIZE
from z6_m600_v2 import build_all_m600_v2_spans

ROOT = THIS_DIR.parents[1]
STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M12_SHA = "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c"
M13_SHA = "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749"
M14_SHA = "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def update_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    assert binascii.crc_hqx(bytes(buf), 0) == 0
    return f"{crc:04x}"


def collect_m15_edits(stock: bytes) -> list[dict]:
    m13_recipe = json.loads(
        (ROOT / "patches/z6-c380-modified13-production-convergence.json").read_text(encoding="utf8")
    )
    edits: list[dict] = []
    for e in m13_recipe["candidates"][0]["edits"]:
        edits.append(dict(e))

    m600_spans = build_all_m600_v2_spans(stock)
    for addr, grp, new_b, desc in m600_spans:
        off = addr - BASE
        assert 0 <= off and off + len(new_b) <= SIZE - 2
        old_b = stock[off : off + len(new_b)]
        edits.append(
            {
                "group": grp,
                "address": f"0x{addr:08x}",
                "before": old_b.hex(),
                "after": new_b.hex(),
                "description": desc,
            }
        )
    edits.sort(key=lambda item: int(item["address"], 16))
    return edits


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified15-preflash-2026-11-15/lab-build",
    )
    args = ap.parse_args()
    out_dir = args.output.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m12 = (ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN").read_bytes()
    m13_path = ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN"
    if not m13_path.is_file():
        m13_path = ROOT / "analysis/modified13-preflash-2026-11-14/lab-build/modified13-candidate.bi"
    m13 = m13_path.read_bytes()

    assert len(stock) == len(m12) == len(m13) == SIZE
    assert sha(stock) == STOCK_SHA and binascii.crc_hqx(stock, 0) == 0
    assert sha(m12) == M12_SHA and binascii.crc_hqx(m12, 0) == 0
    assert sha(m13) == M13_SHA and binascii.crc_hqx(m13, 0) == 0

    edits = collect_m15_edits(stock)
    spans = []
    for e in edits:
        addr = int(e["address"], 16)
        old_b = bytes.fromhex(e["before"])
        new_b = bytes.fromhex(e["after"])
        assert len(old_b) == len(new_b) > 0
        off = addr - BASE
        assert 0 <= off and off + len(old_b) <= SIZE - 2
        spans.append((off, off + len(old_b), addr, e["group"], old_b, new_b, e))

    for (_, prev_end, *_), (cur_start, *_) in zip(spans, spans[1:]):
        assert prev_end <= cur_start, f"Overlapping edit spans: {prev_end:#x} > {cur_start:#x}"

    recipe_doc = {
        "schema": 1,
        "model": "Nikon Z6 (first generation)",
        "version": "C3.80",
        "module": "eg1620_038000.bi",
        "load_base": "0x10020000",
        "source_size": SIZE,
        "source_sha256": STOCK_SHA,
        "parent_candidate": "modified13-production-convergence",
        "parent_sha256": M13_SHA,
        "supersedes_candidate": "modified14-production-600s",
        "supersedes_sha256": M14_SHA,
        "status": "preflash candidate; fixes Modified14 1/3-EV 0x204 109-entry cap T-mode lock while preserving Modified13 astro RAW convergence and 60s-600s M-still shutter speeds",
        "candidates": [
            {
                "id": "modified15-production-600s-v2",
                "scope": "Inherit Modified13 (14 sites) + 84-site native ROM 30-600s v2 M-mode still shutter extension preserving Stock <=109-entry 0x204 property ceiling.",
                "edits": edits,
            }
        ],
    }
    recipe_path = ROOT / "patches/z6-c380-modified15-production-600s.json"
    recipe_path.write_text(json.dumps(recipe_doc, indent=2), encoding="utf8")

    # Build A: directly from Stock C3.80
    from_stock = bytearray(stock)
    for off, end, addr, _, old_b, new_b, _ in spans:
        assert bytes(from_stock[off:end]) == old_b, f"Stock anchor mismatch at {addr:#x}"
        from_stock[off:end] = new_b
    crc_stock = update_crc(from_stock)

    # Build B: incrementally from Modified13 using only m600_* sites
    from_m13 = bytearray(m13)
    m600_deltas = []
    for off, end, addr, grp, old_b, new_b, meta in spans:
        if grp.startswith("m600_"):
            assert bytes(from_m13[off:end]) == old_b, f"Modified13 anchor mismatch at {addr:#x}"
            from_m13[off:end] = new_b
            m600_deltas.append((off, end, old_b))
        else:
            assert bytes(from_m13[off:end]) == new_b, f"Modified13 inherited mismatch at {addr:#x}"
    crc_m13 = update_crc(from_m13)

    m15_bytes = bytes(from_stock)
    assert m15_bytes == bytes(from_m13), "Build from Stock vs Modified13 diverged!"
    assert crc_stock == crc_m13
    m15_sha = sha(m15_bytes)
    assert m15_sha != M14_SHA

    # Exact rollback checks to Modified13 and Stock C3.80
    rev_m13 = bytearray(m15_bytes)
    for off, end, old_b in m600_deltas:
        rev_m13[off:end] = old_b
    update_crc(rev_m13)
    assert bytes(rev_m13) == m13, "Rollback to Modified13 failed!"

    rev_stock = bytearray(m15_bytes)
    for off, end, _, _, old_b, _, _ in spans:
        rev_stock[off:end] = old_b
    update_crc(rev_stock)
    assert bytes(rev_stock) == stock, "Rollback to Stock failed!"

    site_details = []
    for off, end, addr, grp, old_b, new_b, meta in spans:
        site_details.append(
            {
                "address": f"0x{addr:08x}",
                "file_offset": f"0x{off:08x}",
                "group": grp,
                "span_bytes": len(old_b),
                "changed_bytes": sum(x != y for x, y in zip(old_b, new_b)),
                "description": meta.get("description") or meta.get("instruction_after", ""),
            }
        )

    diff_vs_stock = sum(a != b for a, b in zip(stock, m15_bytes))
    diff_vs_m13 = sum(a != b for a, b in zip(m13, m15_bytes))

    out_bin = out_dir / "modified15-candidate.bi"
    out_bin.write_bytes(m15_bytes)
    (out_dir / "prepare_modified15_lab.py").write_bytes(Path(__file__).read_bytes())

    manifest = {
        "ok": True,
        "candidate": "modified15",
        "candidate_id": "modified15-production-600s-v2",
        "supersedes": "modified14",
        "recipe_path": recipe_path.relative_to(ROOT).as_posix(),
        " recipe_sha256": sha(recipe_path.read_bytes()),
        "module_path": out_bin.relative_to(ROOT).as_posix(),
        "sha256": m15_sha,
        "size_bytes": len(m15_bytes),
        "crc16": crc_stock,
        "total_sites": len(spans),
        "inherited_m13_sites": len(spans) - len(m600_deltas),
        "m600_sites": len(m600_deltas),
        "total_spans_bytes": sum(s["span_bytes"] for s in site_details),
        "total_changed_bytes_vs_stock": diff_vs_stock,
        "total_changed_bytes_vs_m13": diff_vs_m13,
        "verified_dual_build": True,
        "verified_rollback_to_m13": True,
        "verified_rollback_to_stock": True,
        "sites": site_details,
    }
    manifest["recipe_sha256"] = manifest.pop(" recipe_sha256")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    print(f"Modified15 prepared: SHA256={m15_sha} CRC16={crc_stock} RecipeSHA256={manifest['recipe_sha256']}")
    print(f"Sites={len(spans)} (M13={len(spans)-len(m600_deltas)}, M600={len(m600_deltas)}) ChangedVsStock={diff_vs_stock} ChangedVsM13={diff_vs_m13}")


if __name__ == "__main__":
    main()

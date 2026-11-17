"""Read-only static analysis of official Nikon Z6 C3.80 container (Z_6_0380.bin).

Input firmware is never modified or executed. Uses input-derived zero-span XOR
mask recovery (tools/fw/z6_c380_container.py) with no bundled third-party XOR tables.
"""
from __future__ import annotations

import argparse
import binascii
from pathlib import Path
import json
import re
import sys

PROJECT = Path(__file__).resolve().parents[1]
FW_TOOLS = PROJECT / "tools" / "fw"
if str(FW_TOOLS) not in sys.path:
    sys.path.insert(0, str(FW_TOOLS))

from z6_c380_container import (  # noqa: E402
    CONTAINER_SHA256,
     apply_mask,
    decode_c380_container,
    sha256_hex,
)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--input",
        type=Path,
        default=PROJECT / "firmware/original/Z_6_0380.bin",
        help="Path to official Nikon Z6 C3.80 Z_6_0380.bin",
    )
    ap.add_argument(
        "--decoded-dir",
        type=Path,
        default=PROJECT / "firmware/decoded",
        help="Directory to write decoded module binaries",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT / "analysis/c380-static-decode",
        help="Directory to write static analysis JSON/string reports",
    )
    args = ap.parse_args()

    src = args.input.resolve()
    raw = src.read_bytes()
    body, mods, masks = decode_c380_container(raw)

    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    decoded_dir = args.decoded_dir.resolve()
    decoded_dir.mkdir(parents=True, exist_ok=True)

    try:
        src_label = src.relative_to(PROJECT).as_posix()
    except ValueError:
        src_label = src.name

    report: dict = {
        "source": src_label,
        "size": len(raw),
        "sha256": CONTAINER_SHA256,
        "outer_prefix_hex": raw[:32].hex(),
        "body_size": len(body),
        "module_count": len(mods),
        "body_crc_calculated": f"{binascii.crc_hqx(body[:-16], 0):04x}",
        "body_crc_stored": body[-16:-14].hex(),
        "trailing_14_zero": body[-14:] == bytes(14),
        "notes": [
            "Static decoding only; no patch or camera execution.",
            "Offsets in module table are relative to decoded body (input offset minus 32).",
        ],
        "modules": [],
    }

    for m in mods:
        data = m["data"]
        name = m["name"]
        (decoded_dir / name).write_bytes(data)
        report["modules"].append(
            {
                "name": name,
                "body_offset": m["body_offset"],
                "body_offset_hex": hex(m["body_offset"]),
                "size": m["size"],
                "sha256": m["sha256"],
                "crc_remainder": binascii.crc_hqx(data, 0),
                "header_hex": data[:64].hex(),
            }
        )
        if name.startswith("eg"):
            strings = [(hit.start(), hit[0].decode("ascii")) for hit in re.finditer(rb"[\x20-\x7e]{6,}", data)]
            (out_dir / "z6_strings.txt").write_text(
                "\n".join(f"{off:08x}\t{txt}" for off, txt in strings),
                encoding="utf-8",
            )
            keywords = r"dark|shading|shade|black.?level|defect|pixel.?map|hot.?pixel|vignett|correc|noise|raw|NEF|NR_|BLC|DSNU|PRNU|OBCL|LensComp"
            hits = [{"offset_hex": hex(off), "text": txt} for off, txt in strings if re.search(keywords, txt, re.I)]
            (out_dir / "z6_candidate_strings.json").write_text(
                json.dumps(hits, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            report["eg_printable_string_count"] = len(strings)
            report["candidate_string_count"] = len(hits)

    recoded = apply_mask(body, masks)
    report["unmodified_roundtrip_byte_identical"] = (raw[:32] + recoded == raw)
    assert report["unmodified_roundtrip_byte_identical"]
    assert sha256_hex(raw[:32] + recoded) == CONTAINER_SHA256

    (out_dir / "z6_analysis.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

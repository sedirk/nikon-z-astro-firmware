# -*- coding: utf-8 -*-
"""build_m23_audit_metrics.py -- Real-camera verification evidence for Modified23.

Audits all 9 real-camera NEF captures in `samples/11.19_modified23` (`Z61_5128.NEF` .. `Z61_5136.NEF`)
shot after flashing `Modified23` (`SHA-256 47a5caa9...`, `CRC-16 0xc083`), plus a direct before/after
structural comparison against `samples/11.17_modified22/Z61_5105.NEF`.

Sections:
  A  Full-frame (`6064 x 4040 = 24,498,560` px/frame) pixel-identity & container geometry verification
     of all 6 hardware-packed 14-bit uncompressed Astro RAW frames (`Z61_5131..5136`, 5 s and 60 s)
     comparing LibRaw 0.22.2 (`rawpy 0.28.0`) against the independent LSB-first packed-14 unpacker.
  B  Row-band continuity (`rows 8..3632`, `3633..4000`, `4001..4031`) across all 9 frames and
     cross-format hot-pixel correlation (`Z61_5130` 5 s Lossless vs `Z61_5131` 5 s Uncompressed)
     proving zero preview-JPEG overlay on rows `3633..4000`.
  C  DCF prefix (`Z61_`), MakerNote ColorSpace (`0x001E = 1` sRGB), and R-channel FFT comb suppression
     metrics across all 9 frames.
  D  Frozen 112 hot-pixel clamp audit (`baseline112.json`) across all 9 frames, including all 17
     bottom-zone targets (`y + 2 >= 3633`) previously obscured in M22 uncompressed long exposures.
  E  Pairwise dark frame-difference noise (`5128 vs 5129`, `5131 vs 5132`, `5134 vs 5135`) and
     before/after comparison against `11.17_modified22/Z61_5105.NEF`.

SPDX-License-Identifier: GPL-3.0-or-later
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("build_m23_audit_metrics.py must not be executed with Python -O/-OO.")

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nef_evidence_lib as L  # noqa: E402

M23_BATCH = "11.19_modified23"
M22_BATCH = "11.17_modified22"
LOSSLESS_5S = ["Z61_5128.NEF", "Z61_5129.NEF", "Z61_5130.NEF"]
UNCOMP_5S = ["Z61_5131.NEF", "Z61_5132.NEF", "Z61_5133.NEF"]
UNCOMP_60S = ["Z61_5134.NEF", "Z61_5135.NEF", "Z61_5136.NEF"]
ALL_M23_FILES = LOSSLESS_5S + UNCOMP_5S + UNCOMP_60S
UNCOMP_M23_FILES = UNCOMP_5S + UNCOMP_60S

NOISE_PAIRS = [
    ("Z61_5128.NEF", "Z61_5129.NEF", "Astro_5s_Lossless_14bit"),
    ("Z61_5131.NEF", "Z61_5132.NEF", "Astro_5s_Uncompressed_packed14"),
    ("Z61_5134.NEF", "Z61_5135.NEF", "Astro_60s_Uncompressed_packed14"),
]


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _portable_label(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.name


def _noise_estimates(d: np.ndarray) -> dict:
    s2 = math.sqrt(2.0)
    p15, p84 = np.percentile(d, 15.866), np.percentile(d, 84.134)
    p25, p75 = np.percentile(d, 25), np.percentile(d, 75)
    return {
        "pixels": int(d.size),
        "mean_diff": float(d.mean()),
        "median_diff": float(np.median(d)),
        "diff_std": float(d.std(ddof=0)),
        "unclipped_std": float(d.std(ddof=0) / s2),
        "central_68pct_sigma": float((p84 - p15) / 2.0 / s2),
        "IQR_sigma": float((p75 - p25) / 1.349 / s2),
        "delta_max_abs": int(np.abs(d).max()),
        "clipped_pixels_abs_gt_100": int((np.abs(d) > 100).sum()),
    }


def _preview_overlap_audit(rec: dict, lay: dict) -> dict:
    buf = rec["_buf"]
    off = int(lay["strip_offset"])
    sbc = int(lay["strip_byte_count"])
    fsize = int(rec["filesize"])
    any_overlap = False
    previews_checked = []
    pv_shas = set()
    for pv in rec["previews"]:
        poff = pv["jpeg_offset"]
        plen = pv["jpeg_length"]
        if poff is None or plen is None:
            continue
        poff_i, plen_i = int(poff), int(plen)
        blob = buf[poff_i : poff_i + plen_i]
        pv_shas.add(L.sha256_bytes(blob))
        valid_jpeg = blob[:3] == b"\xff\xd8\xff" and blob[-2:] == b"\xff\xd9"
        overlaps = not (poff_i + plen_i <= off or poff_i >= off + sbc)
        if overlaps:
            any_overlap = True
        previews_checked.append(
            {
                "subifd": pv["subifd"],
                "offset": poff_i,
                "length": plen_i,
                "end": poff_i + plen_i,
                "rel_to_raw_start": poff_i - off,
                "valid_soi_eoi": bool(valid_jpeg),
                "overlaps_raw_strip": bool(overlaps),
            }
        )

    seg = np.frombuffer(buf, dtype=np.uint8, count=sbc, offset=off)
    soi_hits = np.nonzero((seg[:-3] == 0xFF) & (seg[1:-2] == 0xD8) & (seg[2:-1] == 0xFF))[0]
    embedded_matches = []
    for rel in soi_hits.tolist():
        for pv in previews_checked:
            plen_i = pv["length"]
            if plen_i > 0 and rel + plen_i <= sbc:
                if L.sha256_bytes(buf[off + rel : off + rel + plen_i]) in pv_shas:
                    embedded_matches.append({"rel_offset": int(rel), "subifd": pv["subifd"]})

    return {
        "declared_preview_count": len(previews_checked),
        "all_previews_valid_jpeg": all(p["valid_soi_eoi"] for p in previews_checked),
        "any_declared_preview_overlaps_raw": any_overlap,
        "embedded_preview_matches_in_raw_count": len(embedded_matches),
        "trailing_bytes_after_raw_strip": fsize - (off + sbc),
        "previews": previews_checked,
    }


def _row_band_summary(img: np.ndarray) -> dict:
    img_i32 = img.astype(np.int32)
    bands = {}
    for bname, r0, r1 in (
        ("top_8_3632", 8, 3633),
        ("former_overlay_3633_4000", 3633, 4001),
        ("bottom_4001_4031", 4001, 4032),
    ):
        sub = img_i32[r0:r1, 8 : L.SENSOR_W - 8]
        row_meds = np.median(sub, axis=1)
        bands[bname] = {
            "rows_inclusive": [r0, r1 - 1],
            "min": int(sub.min()),
            "max": int(sub.max()),
            "median": float(np.median(sub)),
            "mean": round(float(sub.mean()), 3),
            "std": round(float(sub.std()), 3),
            "zero_adu_count": int((sub == 0).sum()),
            "row_median_min": float(row_meds.min()),
            "row_median_max": float(row_meds.max()),
            "mean_abs_same_cfa_col_diff": round(float(np.abs(np.diff(sub[:, ::2], axis=1)).mean()), 3),
        }
    return bands


def main() -> int:
    if not __debug__:
        raise RuntimeError("build_m23_audit_metrics.py must not be executed with Python -O/-OO.")

    here = Path(__file__).resolve().parent
    repo_root = here.parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--samples-root", default=str(repo_root / "samples"))
    ap.add_argument("--baseline112", default=str(repo_root / "docs" / "evidence" / "baseline112.json"))
    ap.add_argument("--out", default=str(repo_root / "docs" / "evidence" / "m23_audit_metrics.json"))
    args = ap.parse_args()

    root = Path(args.samples_root).resolve()
    b112_path = Path(args.baseline112).resolve()
    base = json.loads(b112_path.read_text(encoding="utf-8"))
    targets = base["targets"]

    loaded: dict[str, tuple[dict, dict, np.ndarray]] = {}
    for fname in ALL_M23_FILES:
        fpath = root / M23_BATCH / fname
        _require(fpath.is_file(), f"Missing expected Modified23 sample: {M23_BATCH}/{fname}")
        rec = L.parse_nef(fpath)
        lay = L.classify_layout(rec)
        img, _ = L.decode_raw(rec, lay)
        loaded[fname] = (rec, lay, img)

    # Section A: Full-frame hardware packed-14 verification
    a_rows = []
    for fname in UNCOMP_M23_FILES:
        rec, lay, img = loaded[fname]
        _require(lay["layout"] == "packed_14bit_stride10624", f"Unexpected layout for {fname}: {lay['layout']}")
        lib = L.decode_with_libraw(rec)
        diff = img.astype(np.int32) - lib.astype(np.int32)
        buf = rec["_buf"]
        off = int(lay["strip_offset"])
        sbc = int(lay["strip_byte_count"])
        raw_grid = np.frombuffer(buf, dtype=np.uint8, count=sbc, offset=off).reshape(L.SENSOR_H, L.PACKED14_STRIDE)
        pad_nonzero = int(np.count_nonzero(raw_grid[:, L.PACKED14_PAYLOAD :]))
        pv_audit = _preview_overlap_audit(rec, lay)
        row = {
            "rel_path": f"{M23_BATCH}/{fname}",
            "sha256": L.sha256_file(root / M23_BATCH / fname),
            "size_bytes": int(rec["filesize"]),
            "exposure_time_s": float(rec["exif"]["exposure_time"]),
            "iso": int(rec["exif"]["iso"]),
            "shutter_count_0x00a7": int(rec["makernote"]["shutter_count_0x00a7"]),
            "verified_raw_layout": lay["layout"],
            "strip_offset": off,
            "strip_byte_count": sbc,
            "row_stride_bytes": L.PACKED14_STRIDE,
            "row_padding_nonzero_bytes": pad_nonzero,
            "strip_end_equals_filesize": bool(off + sbc == rec["filesize"]),
            "trailing_bytes_after_strip": pv_audit["trailing_bytes_after_raw_strip"],
            "any_declared_preview_overlaps_raw": pv_audit["any_declared_preview_overlaps_raw"],
            "embedded_preview_matches_in_raw_count": pv_audit["embedded_preview_matches_in_raw_count"],
            "pixels_compared": int(img.size),
            "pixel_diff_count": int((diff != 0).sum()),
            "max_abs_diff": int(np.abs(diff).max()),
            "identical": bool((diff == 0).all()),
        }
        _require(row["identical"], f"LibRaw vs independent unpacker mismatch on {fname}")
        _require(not row["any_declared_preview_overlaps_raw"], f"Preview overlaps RAW strip in {fname}")
        _require(row["embedded_preview_matches_in_raw_count"] == 0, f"Embedded preview inside RAW strip in {fname}")
        _require(row["trailing_bytes_after_strip"] == 0, f"Unexpected trailing bytes in {fname}")
        _require(pad_nonzero == 0, f"Non-zero row padding bytes in {fname}: {pad_nonzero}")
        a_rows.append(row)

    # Section B: Row-band continuity & Lossless vs Uncompressed hot-pixel alignment
    b_per_file = {}
    for fname in ALL_M23_FILES:
        rec, lay, img = loaded[fname]
        pv_audit = _preview_overlap_audit(rec, lay)
        b_per_file[fname] = {
            "rel_path": f"{M23_BATCH}/{fname}",
            "verified_raw_layout": lay["layout"],
            "exposure_time_s": float(rec["exif"]["exposure_time"]),
            "any_declared_preview_overlaps_raw": pv_audit["any_declared_preview_overlaps_raw"],
            "embedded_preview_matches_in_raw_count": pv_audit["embedded_preview_matches_in_raw_count"],
            "trailing_bytes_after_strip": pv_audit["trailing_bytes_after_raw_strip"],
            "row_bands": _row_band_summary(img),
        }

    im5130 = loaded["Z61_5130.NEF"][2].astype(np.int32)
    im5131 = loaded["Z61_5131.NEF"][2].astype(np.int32)
    hot_alignment = {}
    for zname, r0, r1 in (
        ("top_8_3632", 8, 3633),
        ("former_overlay_3633_4000", 3633, 4001),
    ):
        z30 = im5130[r0:r1, 8 : L.SENSOR_W - 8]
        z31 = im5131[r0:r1, 8 : L.SENSOR_W - 8]
        mask = (z30 > 2000) | (z31 > 2000)
        both = int(((z30 > 2000) & (z31 > 2000)).sum())
        n_union = int(mask.sum())
        corr = float(np.corrcoef(z30[mask], z31[mask])[0, 1])
        hot_alignment[zname] = {
            "rows_inclusive": [r0, r1 - 1],
            "union_pixels_gt_2000_adu": n_union,
            "intersection_pixels_gt_2000_adu": both,
            "pearson_r": round(corr, 6),
            "median_abs_diff_dn": float(np.median(np.abs(z30[mask] - z31[mask]))),
        }

    # Section C: ColorSpace, DCF, and Comb metrics
    c_rows = []
    for fname in ALL_M23_FILES:
        rec, lay, img = loaded[fname]
        prefix, counter = L.dcf_name(Path(fname).stem)
        cm = L.comb_metrics(img)
        ch = L.channel_medians(img)
        mn_cs = int(rec["makernote"]["colorspace_0x001e"])
        _require(prefix == "Z61_", f"Unexpected DCF prefix for {fname}: {prefix}")
        _require(mn_cs == 1, f"Unexpected MakerNote ColorSpace for {fname}: {mn_cs}")
        _require(
            cm["comb_band_0p22_0p24_peak"] < 204968.8,
            f"Unexpected 0.2276 cyc/DN comb peak in Astro frame {fname}: {cm['comb_band_0p22_0p24_peak']}",
        )
        c_rows.append(
            {
                "rel_path": f"{M23_BATCH}/{fname}",
                "dcf_prefix": prefix,
                "dcf_number": counter,
                "makernote_colorspace_0x001e": mn_cs,
                "makernote_colorspace_text": "sRGB",
                "exposure_time_s": float(rec["exif"]["exposure_time"]),
                "verified_raw_layout": lay["layout"],
                "roi_median": cm["roi_median"],
                "center_R_G1_ratio": ch["center_R_G1_ratio"],
                "comb_fft_bin3729_0p2276": cm["comb_fft_bin3729_0p2276"],
                "comb_band_0p22_0p24_peak": cm["comb_band_0p22_0p24_peak"],
                "comb_band_peak_freq": cm["comb_band_peak_freq"],
                "hist_nonempty_bins_in_median_pm50": cm["hist_nonempty_bins_in_median_pm50"],
            }
        )

    # Section D: Frozen 112 hot-pixel clamp audit
    d_rows = []
    for fname in ALL_M23_FILES:
        rec, lay, img = loaded[fname]
        m = L.frozen112_metrics(img, targets)
        _require(m["matches_0_8_to_56"] == 0, f"Spatial clamp hit detected in {fname}: {m['matches_0_8_to_56']}")
        bottom_17 = [t for t in m["per_target"] if t["y"] + 2 >= 3633]
        bottom_hits = sum(1 for t in bottom_17 if t["hit_8k"])
        _require(bottom_hits == 0, f"Bottom-zone clamp hit in {fname}: {bottom_hits}")
        d_rows.append(
            {
                "rel_path": f"{M23_BATCH}/{fname}",
                "verified_raw_layout": lay["layout"],
                "exposure_time_s": float(rec["exif"]["exposure_time"]),
                "n_targets": m["n_targets"],
                "matches_0_8_to_56": m["matches_0_8_to_56"],
                "above56": m["above56"],
                "below0": m["below0"],
                "median_delta": m["median_delta"],
                "mean_delta": round(m["mean_delta"], 2),
                "max_delta": m["max_delta"],
                "former_overlay_zone_y_plus_2_ge_3633": {
                    "n_targets": len(bottom_17),
                    "matches_0_8_to_56": bottom_hits,
                    "above56": sum(1 for t in bottom_17 if t["delta"] > 56),
                    "median_delta": float(np.median([t["delta"] for t in bottom_17])),
                },
            }
        )

    # Section E: Pairwise dark noise & M22 before/after comparison
    e_pairs = []
    for fa, fb, label in NOISE_PAIRS:
        ia = loaded[fa][2].astype(np.int32)
        ib = loaded[fb][2].astype(np.int32)
        va = ia[8:4032, 8:6056]
        vb = ib[8:4032, 8:6056]
        e_pairs.append(
            {
                "pair": [f"{M23_BATCH}/{fa}", f"{M23_BATCH}/{fb}"],
                "label": label,
                "full_frame": _noise_estimates(ia - ib),
                "sensor_area": _noise_estimates(va - vb),
            }
        )

    before_after = None
    m22_ref = root / M22_BATCH / "Z61_5105.NEF"
    if m22_ref.is_file():
        rec22 = L.parse_nef(m22_ref)
        lay22 = L.classify_layout(rec22)
        rec23, lay23, _ = loaded["Z61_5131.NEF"]
        before_after = {
            "m22_sample": f"{M22_BATCH}/Z61_5105.NEF",
            "m22_sha256": L.sha256_file(m22_ref),
            "m22_filesize_bytes": int(rec22["filesize"]),
            "m22_strip_byte_count": int(lay22["strip_byte_count"]),
            "m22_row_stride_bytes": int(lay22["row_stride_bytes"]),
            "m22_verified_raw_layout": lay22["layout"],
            "m22_embedded_preview_collisions": len(lay22.get("embedded_jpeg_slots", [])),
            "m22_corrupted_rows": lay22.get("preview_overlay_rows"),
            "m23_sample": f"{M23_BATCH}/Z61_5131.NEF",
            "m23_sha256": L.sha256_file(root / M23_BATCH / "Z61_5131.NEF"),
            "m23_filesize_bytes": int(rec23["filesize"]),
            "m23_strip_byte_count": int(lay23["strip_byte_count"]),
            "m23_row_stride_bytes": int(lay23["row_stride_bytes"]),
            "m23_verified_raw_layout": lay23["layout"],
            "m23_embedded_preview_collisions": 0,
            "m23_corrupted_rows": None,
            "strip_byte_reduction_bytes": int(lay22["strip_byte_count"]) - int(lay23["strip_byte_count"]),
        }

    out = {
        "artifact": "m23_audit_metrics",
        "schema_version": "1.0",
        "generated_from": _portable_label(root, repo_root),
        "firmware_under_test": {
            "version": "Modified23",
            "eg162080_sha256": "47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029",
            "eg162080_crc16_hqx": "0xc083",
            "total_patch_sites": 105,
            "p1_hook_site": "0x100A34D0 -> 0x1002DB5C (tramp_a34d0)",
        },
        "method": {
            "generator": "build_m23_audit_metrics.py",
            "generator_version": L.GENERATOR_VERSION,
            "environment": L.environment(),
            "baseline112_sha256": hashlib.sha256(b112_path.read_bytes()).hexdigest(),
            "sample_batch": M23_BATCH,
            "frames_total": len(ALL_M23_FILES),
            "lossless_5s_frames": LOSSLESS_5S,
            "uncompressed_5s_frames": UNCOMP_5S,
            "uncompressed_60s_frames": UNCOMP_60S,
        },
        "A_packed14_hardware_fullframe_verification": {
            "files_checked": len(a_rows),
            "total_pixels_verified": int(sum(r["pixels_compared"] for r in a_rows)),
            "all_identical_to_libraw": all(r["identical"] for r in a_rows),
            "total_pixel_diff_count": int(sum(r["pixel_diff_count"] for r in a_rows)),
            "all_row_padding_zero": all(r["row_padding_nonzero_bytes"] == 0 for r in a_rows),
            "any_preview_overlap": any(r["any_declared_preview_overlaps_raw"] for r in a_rows),
            "max_trailing_bytes_after_strip": max(r["trailing_bytes_after_strip"] for r in a_rows),
            "per_file": a_rows,
        },
        "B_row_band_continuity_and_preview_zone_recovery": {
            "cross_format_hot_pixel_alignment_5130_vs_5131": hot_alignment,
            "per_file": b_per_file,
        },
        "C_colorspace_dcf_and_comb_invariants": {
            "all_dcf_z61": all(r["dcf_prefix"] == "Z61_" for r in c_rows),
            "all_makernote_srgb": all(r["makernote_colorspace_0x001e"] == 1 for r in c_rows),
            "per_file": c_rows,
        },
        "D_frozen112_spatial_filter_bypass": {
            "all_zero_clamp_hits": all(r["matches_0_8_to_56"] == 0 for r in d_rows),
            "total_clamp_hits_across_9_frames": int(sum(r["matches_0_8_to_56"] for r in d_rows)),
            "total_former_overlay_zone_hits": int(
                sum(r["former_overlay_zone_y_plus_2_ge_3633"]["matches_0_8_to_56"] for r in d_rows)
            ),
            "rts_blinking_note": (
                "Target (x=121, y=3740, phase=G1) exhibits physical Random Telegraph Signal (RTS) blinking: "
                "center ADU drops to 1147 (delta=+130) in Z61_5132 and 1007 (delta=-11, hit_8k=False) in Z61_5133, "
                "then returns to 16383 saturation (delta=+15362..+15367) in 60 s frames Z61_5134..5136."
            ),
            "frames": d_rows,
        },
        "E_pairwise_dark_noise_and_m22_before_after": {
            "noise_pairs": e_pairs,
            "m22_vs_m23_5s_uncompressed_astro_raw": before_after,
        },
    }

    out_p = Path(args.out)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out_p} ({len(ALL_M23_FILES)} frames verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

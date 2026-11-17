# -*- coding: utf-8 -*-
"""
build_sample_catalog.py -- item 2: SAMPLE_EVIDENCE_CATALOG.json

Scans every *.NEF under --samples-root (read-only), extracts metadata, verifies the
RAW strip layout, decodes each frame with the *correct* decoder, and records pixel
statistics + the 0.2276 cyc/DN R-channel comb metrics.

Usage:
  python build_sample_catalog.py --samples-root <dir> --baseline112 <file> --out <file.json>
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nef_evidence_lib as L

BLACK = L.BLACK_LEVEL_DEFAULT
DARK_LEVEL = BLACK + 128          # 1136 ADU
DARK_FRAC_MAX = 1e-3              # illumination absent if < 0.1 % of pixels exceed DARK_LEVEL
SHORT_EXPOSURE_MAX = 0.5          # s

# --- capture_mode anchors ----------------------------------------------------
# comb_band_0p22_0p24_peak values measured on the 11.17_modified22 batch, whose Astro /
# Standard split is independently established (audit report + centre R/G1 ratio + capture
# time order).  The per-category threshold is the geometric mean of max(Astro) and
# min(Standard), so every anchor keeps the same relative margin on both sides.
M22_ANCHORS = {
    "Bias": {"Astro": [61550.9, 64061.0, 63311.9],
             "Standard": [422469.0, 421015.6, 421913.1]},
    "Dark": {"Astro": [100339.9, 101078.1, 98133.9],
             "Standard": [415227.9, 416552.4, 414180.5]},
    "Flat": {"Astro": [28450.9, 27019.4, 28628.4],
             "Standard": [278093.3, 279979.4, 278369.0]},
}
CAPTURE_THRESHOLDS = {k: math.sqrt(max(v["Astro"]) * min(v["Standard"]))
                      for k, v in M22_ANCHORS.items()}
CAPTURE_THRESHOLDS["Scene"] = 40000.0   # no M22 anchor; provenance decides for every scene frame

# provenance: batches whose frames are original-firmware captures
STOCK_BATCHES = {"nas-2026-11-09"}      # manifest.json: "Verified byte-identical copies"
ANCHORED_BATCHES = {"11.17_modified22"}


def category(exp_s, dark_frac):
    if exp_s is None:
        return "Scene"
    if dark_frac <= DARK_FRAC_MAX:
        return "Bias" if exp_s < SHORT_EXPOSURE_MAX else "Dark"
    return "Flat" if exp_s < SHORT_EXPOSURE_MAX else "Scene"


def _portable_label(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.name


def main():
    ap = argparse.ArgumentParser()
    here = Path(__file__).resolve().parent
    repo_root = here.parents[1]
    ap.add_argument("--samples-root", default=str(repo_root / "samples"))
    ap.add_argument("--baseline112", default=str(repo_root / "docs" / "evidence" / "baseline112.json"))
    ap.add_argument("--out", default=str(repo_root / "docs" / "SAMPLE_EVIDENCE_CATALOG.json"))
    args = ap.parse_args()

    root = Path(args.samples_root).resolve()
    stock_sha = {}
    base_doc = None
    bp = Path(args.baseline112)
    if bp.exists():
        base_doc = json.loads(bp.read_text(encoding="utf-8"))
        for rel, sha in (base_doc.get("source_sha256") or {}).items():
            stock_sha[sha] = rel.replace("\\", "/")

    nefs, aux = [], []
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        if p.suffix.upper() == ".NEF":
            nefs.append(p)
        else:
            aux.append({"rel_path": p.relative_to(root).as_posix(),
                        "size_bytes": p.stat().st_size,
                        "sha256": L.sha256_file(p),
                        "role": "auxiliary non-NEF file (excluded from the NEF count)"})

    files = []
    for i, p in enumerate(nefs, 1):
        rec = L.parse_nef(p)
        lay = L.classify_layout(rec)
        img, clean = L.decode_raw(rec, lay)
        x, y, w, h = L.SENSOR_AREA
        sub = img[y:y + h, x:x + w]
        rows_ok = clean[y:y + h]
        vi = sub[rows_ok].astype(np.int32)
        st = L.basic_stats(vi)
        dark_frac = float((vi > DARK_LEVEL).mean())
        exp_s = rec["exif"]["exposure_time"]
        cat = category(exp_s, dark_frac)
        ch = L.channel_medians(img)
        cm = L.comb_metrics(img)
        thr = CAPTURE_THRESHOLDS[cat]
        comb_class = "Astro" if cm["comb_band_0p22_0p24_peak"] < thr else "Standard"
        sha = L.sha256_file(p)
        batch = p.parent.relative_to(root).as_posix() if p.parent != root else "."
        prefix, number = L.dcf_name(p.stem)

        rg = ch["center_R_G1_ratio"]
        if cat in ("Flat", "Scene") and rg is not None:
            rg_class = "Astro" if rg < 0.98 else "Standard"
            agree = "agree" if rg_class == comb_class else "conflict"
        else:
            rg_class, agree = None, "n/a (dark frame: R/G1 == 1.0000 by construction)"

        if sha in stock_sha:
            mode, conf = "Stock", "provenance"
            basis = "byte-identical to baseline112.json source_sha256 entry for samples/%s" % stock_sha[sha]
        elif batch in STOCK_BATCHES:
            mode, conf = "Stock", "provenance"
            basis = ("listed in %s/manifest.json as a verified byte-identical copy of an original-firmware "
                     "NAS capture (stock body, unmodified firmware)" % batch)
        else:
            mode = comb_class
            if batch in ANCHORED_BATCHES:
                conf = "anchored"
                basis = ("11.17_modified22 Astro/Standard split is independently established; comb band peak "
                         "%.1f vs %.1f threshold -> %s" % (cm["comb_band_0p22_0p24_peak"], thr, comb_class))
            elif agree == "agree":
                conf = "corroborated"
                basis = ("comb band peak %.1f vs %.1f threshold -> %s, and centre R/G1 %.4f -> %s (two "
                         "independent criteria agree)" % (cm["comb_band_0p22_0p24_peak"], thr, comb_class,
                                                          rg, rg_class))
            elif agree == "conflict":
                conf = "conflict"
                basis = ("comb band peak %.1f vs %.1f threshold -> %s but centre R/G1 %.4f -> %s; the comb "
                         "criterion is reported as capture_mode and the R/G1 reading is kept in "
                         "capture_mode_corroboration" % (cm["comb_band_0p22_0p24_peak"], thr, comb_class,
                                                         rg, rg_class))
            else:
                conf = "threshold_only"
                basis = ("comb band peak %.1f vs %.1f threshold -> %s (no R/G1 corroboration available for a "
                         "dark frame)" % (cm["comb_band_0p22_0p24_peak"], thr, comb_class))

        entry = {
            "rel_path": p.relative_to(root).as_posix(),
            "size_bytes": rec["filesize"],
            "sha256": sha,
            "sample_batch": batch,
            "firmware_tag": "IFD0.Software=%s; MakerNote.header=%s" % (
                rec["software"], rec["makernote"].get("mn_header_version")),
            "firmware_tag_source": "IFD0 0x0131 Software + MakerNote header version bytes (identical in all files)",
            "datetime_original": rec["exif"]["datetime_original"],
            "exposure_time": exp_s,
            "exposure_time_text": ("1/%d" % round(1 / exp_s)) if exp_s and exp_s < 0.5 else (
                ("%g s" % exp_s) if exp_s is not None else None),
            "iso": rec["exif"]["iso"],
            "f_number": rec["exif"]["f_number"],
            "focal_length_mm": rec["exif"]["focal_length_mm"],
            "shutter_count_0x00a7": rec["makernote"]["shutter_count_0x00a7"],
            "dcf_prefix": prefix,
            "dcf_number": number,
            "makernote_colorspace_0x001e": rec["makernote"]["colorspace_0x001e"],
            "makernote_colorspace_0x001e_text": {1: "sRGB", 2: "AdobeRGB"}.get(
                rec["makernote"]["colorspace_0x001e"], "unknown"),
            "black_level": rec["makernote"]["blacklevel_0x003d"],
            "tiff_compression": int(rec["tiff_compression"]),
            "bits_per_sample": (rec["bits_per_sample"] or [None])[0]
                               if isinstance(rec["bits_per_sample"], list) else rec["bits_per_sample"],
            "raw_strip_offset": rec["raw_strip_offset"],
            "raw_strip_byte_count": rec["raw_strip_byte_count"],
            "rows_per_strip": rec["raw_rows_per_strip"],
            "verified_raw_layout": lay["layout"],
            "raw_layout_verification": lay,
            "frame_category": cat,
            "frame_category_basis": {
                "exposure_time_s": exp_s,
                "valid_area_median_adu": st["median"],
                "fraction_pixels_gt_black_plus_128_ADU": dark_frac,
                "rule": ("no illumination (fraction > 1136 ADU <= 1e-3) -> Bias if exposure < 0.5 s else Dark; "
                         "with illumination -> Flat if exposure < 0.5 s else Scene"),
            },
            "capture_mode": mode,
            "capture_mode_confidence": conf,
            "capture_mode_basis": basis,
            "capture_mode_corroboration": {
                "comb_band_threshold": thr,
                "comb_band_class": comb_class,
                "center_R_G1_ratio": rg,
                "center_R_G1_class": rg_class,
                "agreement": agree,
            },
            "pixel_stats": st,
            "center_roi_channel_medians": {"R": ch["R"], "G1": ch["G1"], "G2": ch["G2"], "B": ch["B"]},
            "center_R_G1_ratio": rg,
            "center_roi": {
                "coord_space": "channel_plane",
                "rows": [505, 1515],
                "cols": [758, 2274],
                "pixels_per_channel": cm["roi_pixels"],
            },
            "comb_fft_bin3729_0p2276": cm["comb_fft_bin3729_0p2276"],
            "comb_band_0p22_0p24_peak": cm["comb_band_0p22_0p24_peak"],
            "comb_band_peak_freq": cm["comb_band_peak_freq"],
            "comb_dominant_freq_0p05_0p45": cm["comb_dominant_freq_0p05_0p45"],
            "comb_dominant_spacing_dn": cm["comb_dominant_spacing_dn"],
            "comb_dominant_amp": cm["comb_dominant_amp"],
            "comb_dominant_prominence": cm["comb_dominant_prominence"],
            "hist_nonempty_bins_in_median_pm50": cm["hist_nonempty_bins_in_median_pm50"],
            "libraw_packed14_misdecode_artifact": False,
        }

        if lay["layout"] == "uncompressed_16bit_le_with_preview_overlay":
            r0, r1 = lay["preview_overlay_rows"]
            entry["libraw_packed14_misdecode_artifact"] = True
            entry["preview_overlay_rows"] = [r0, r1]
            entry["pixel_stats_note"] = ("16-bit LE decode; rows %d-%d (embedded preview JPEGs) are excluded "
                                         "from pixel_stats" % (r0, r1))
            entry["pixel_stats_full_including_overlay_rows"] = L.basic_stats(sub.astype(np.int32))
            lib = L.decode_with_libraw(rec)
            entry["libraw_misdecode_artifact_stats"] = L.basic_stats(lib[y:y + h, x:x + w].astype(np.int32))
            entry["preview_overlay"] = {"slots": lay["embedded_jpeg_slots"],
                                        "clean_rows": lay["clean_rows"],
                                        "clean_valid_area_rows": int(rows_ok.sum())}
        files.append(entry)
        print("[%3d/%3d] %-42s %-42s %-5s %-9s %-6s comb=%10.1f rg=%s" % (
            i, len(nefs), entry["rel_path"], entry["verified_raw_layout"], cat, mode, conf,
            cm["comb_band_0p22_0p24_peak"], ("%.4f" % rg) if rg else "n/a"), flush=True)

    summary = {}
    for e in files:
        summary.setdefault(e["sample_batch"], {}).setdefault(
            e["capture_mode"], []).append(e["rel_path"].split("/")[-1])

    method = {
        "generator": "build_sample_catalog.py",
        "generator_version": L.GENERATOR_VERSION,
        "environment": L.environment(),
        "samples_root": _portable_label(root, repo_root),
        "baseline112_source": _portable_label(bp, repo_root) if base_doc is not None else None,
        "nef_count": len(nefs),
        "auxiliary_non_nef_count": len(aux),
        "decoding": {
            "lossless_14bit": "LibRaw 0.22.2 via rawpy 0.28.0 raw_image (Nikon lossless Huffman)",
            "packed_14bit_stride10624": "independent Python LSB-first packed-14 unpacker, 10,624 B row stride, "
                                        "10,612 B payload (7 bytes -> 4 pixels); verified pixel-identical to "
                                        "LibRaw on all 20 packed-14 files in the tree",
            "uncompressed_16bit_le_with_preview_overlay": "independent numpy '<u2' read at 12,128 B rows; rows "
                                                          "overlapping the embedded preview JPEGs are excluded",
        },
        "geometry": {
            "stored_grid_wh": [L.SENSOR_W, L.SENSOR_H],
            "sensor_area_xywh": list(L.SENSOR_AREA),
            "valid_area_rows": [8, 4031],
            "valid_area_cols": [8, 6055],
            "cfa_pattern": L.CFA_PATTERN,
            "cfa_phase_map": {"R": "row even, col even", "G1": "row even, col odd",
                              "G2": "row odd, col even", "B": "row odd, col odd"},
            "black_level": BLACK,
            "center_roi": ("middle half of each 2020x3032 channel plane: rows 505:1515, cols 758:2274 -> "
                           "1010 x 1516 = 1,531,160 px per channel"),
        },
        "comb_metric": {
            "channel": "R (CFA top-left phase, img[0::2,0::2])",
            "roi": "middle half of each axis of the R plane (plane rows 505:1515, cols 758:2274; full-frame even rows 1010:3030:2, even cols 1516:4548:2)",
            "histogram": "np.bincount(np.clip(roi,0,16383), minlength=16384)",
            "spectrum": "np.abs(np.fft.rfft(hist, 16384)) -- NOT normalised",
            "target_bin": L.TARGET_BIN,
            "target_freq_cyc_per_dn": L.TARGET_FREQ,
            "target_freq_exact": "3729/16384 = 0.22760009765625 cyc/DN",
            "band": [L.BAND_LO, L.BAND_HI],
            "band_peak": "max |rfft| over freqs in [0.22, 0.24]; the reported frequency is argmax_bin/16384",
            "dominant_comb": "max |rfft| over freqs in [0.05, 0.45]; spacing = 1/frequency, in DN",
        },
        "capture_mode_rule": {
            "thresholds_comb_band_peak": CAPTURE_THRESHOLDS,
            "anchors": M22_ANCHORS,
            "method": "geometric mean of max(Astro) and min(Standard) over the 11.17_modified22 anchor triples",
            "stock_provenance": {"baseline112_source_sha256": sorted(stock_sha),
                                 "stock_batches": sorted(STOCK_BATCHES)},
            "caveat": ("comb_band_0p22_0p24_peak is a per-frame diagnostic, not a build fingerprint: the "
                       "original-firmware 5 s dark Z61_4854 (407,063) and Z61_4855 (98,408) differ 4.1x because "
                       "their histogram combs sit at different frequencies (0.2278 vs 0.1586 cyc/DN, i.e. 4.39 vs "
                       "6.31 DN spacing).  capture_mode is therefore reported together with "
                       "capture_mode_confidence and capture_mode_corroboration, and Stock is decided by provenance."),
        },
        "packed14_layout": {
            "strip_byte_count": L.PACKED14_STRIP,
            "row_stride_bytes": L.PACKED14_STRIDE,
            "payload_bytes_per_row": L.PACKED14_PAYLOAD,
            "bit_order": "LSB-first, 7 stored bytes -> 4 fourteen-bit pixels",
            "padding": "12 trailing bytes per row (10,612 -> 10,624, 32-byte alignment)",
            "discriminator": "unpacking at stride 10,612 instead of 10,624 turns the frame into noise "
                             "(mean |neighbour diff| jumps from ~7 DN to thousands of DN)",
        },
        "u16_overlay_layout": {
            "strip_byte_count": L.U16_STRIP,
            "row_stride_bytes": L.U16_STRIDE,
            "encoding": "16-bit little-endian, every value < 16384 (14-bit in a 16-bit container)",
            "relative_jpeg_slots": [{"rel_offset": a, "declared_as": b} for a, b in L.U16_OVERLAY_SLOTS],
            "overlap_rows": [3633, 4000],
            "note": ("three preview JPEGs (byte-identical copies of the file's own SubIFD1 large preview, IFD0 "
                     "thumbnail and SubIFD3 medium preview) are embedded inside the declared RAW strip; rows "
                     "3633-4000 must be dropped"),
        },
        "field_notes": {
            "pixel_stats": "over the SensorArea (8,8,6048,4024) crop of the correctly decoded frame; for the "
                           "three 16-bit LE files the preview-overlay rows are excluded",
            "zero_adu_count/below_1008_*": "same pixel set as pixel_stats",
            "frame_category": "Bias/Dark/Flat/Scene from exposure_time and the fraction of valid-area pixels "
                              "above black_level+128 = 1136 ADU",
            "libraw_packed14_misdecode_artifact": "True only for the 5 s Astro frames stored as uncompressed "
                                                  "16-bit LE, which LibRaw mis-decodes as packed-14",
        },
    }

    out = {
        "artifact": "SAMPLE_EVIDENCE_CATALOG",
        "schema_version": "1.0",
        "generated_from": _portable_label(root, repo_root),
        "method": method,
        "nef_file_count": len(nefs),
        "auxiliary_non_nef_files": aux,
        "capture_mode_summary_by_batch": summary,
        "files": files,
    }
    Path(args.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
    print("wrote", args.out, len(files), "NEF records,", len(aux), "auxiliary files")
    print("thresholds", CAPTURE_THRESHOLDS)


if __name__ == "__main__":
    main()

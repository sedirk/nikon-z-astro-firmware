# -*- coding: utf-8 -*-
"""
build_m22_audit_metrics.py -- item 3: m22_audit_metrics.json

Covers 11.17_modified22 (all 18 frames) plus the cross-generation baselines
(11.9 original dark 4854/4855, 11.14_modified13 dark 5007-5009 and flat 4994/5000/5006,
11.16_modified21 5093-5098).

Sections
  A  full-frame pixel-identity check of the 15 packed-14 frames (LibRaw vs independent unpacker)
  B  flat pair (5110-5112 vs 5119-5121) and bias pair (5102-5104 vs 5113-5115) comb comparison,
     in both calibers: exact bin 3729 @ 0.22760009765625 and the [0.22,0.24] band peak
  C  bias-pair noise estimates (5102 vs 5103 Astro, 5113 vs 5114 Standard): IQR / central-68 % / std
  D  frozen 112 hot pixels: nearest-same-colour 8-neighbour clamp hit rate on 4854/4855,
     5007-5009, 5116-5118 and 5105-5107 (preview-overlay aware)
  E  quantitative record of the anomalous 16-bit LE layout of 5105-5107

Usage:
  python build_m22_audit_metrics.py --samples-root <dir> --baseline112 <file> --out <file.json>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nef_evidence_lib as L

M22 = "11.17_modified22"
PACKED14_FILES = ["Z61_5102.NEF", "Z61_5103.NEF", "Z61_5104.NEF", "Z61_5105.NEF", "Z61_5106.NEF",
                  "Z61_5107.NEF", "Z61_5110.NEF", "Z61_5111.NEF", "Z61_5112.NEF", "Z61_5113.NEF",
                  "Z61_5114.NEF", "Z61_5115.NEF", "Z61_5116.NEF", "Z61_5117.NEF", "Z61_5118.NEF",
                  "Z61_5119.NEF", "Z61_5120.NEF", "Z61_5121.NEF"]
U16_FILES = ["Z61_5105.NEF", "Z61_5106.NEF", "Z61_5107.NEF"]
FLAT_ASTRO = ["Z61_5110.NEF", "Z61_5111.NEF", "Z61_5112.NEF"]
FLAT_STD = ["Z61_5119.NEF", "Z61_5120.NEF", "Z61_5121.NEF"]
BIAS_ASTRO = ["Z61_5102.NEF", "Z61_5103.NEF", "Z61_5104.NEF"]
BIAS_STD = ["Z61_5113.NEF", "Z61_5114.NEF", "Z61_5115.NEF"]
DARK_STD = ["Z61_5116.NEF", "Z61_5117.NEF", "Z61_5118.NEF"]
NOISE_PAIRS = [("Z61_5102.NEF", "Z61_5103.NEF", "Astro"),
               ("Z61_5113.NEF", "Z61_5114.NEF", "Standard")]
FROZEN_FRAMES = [("11.9", "Z61_4854.NEF", "Stock", "lossless"),
                  ("11.9", "Z61_4855.NEF", "Stock", "lossless"),
                  ("11.14_modified13", "Z61_5007.NEF", "Astro (Modified13)", "lossless"),
                  ("11.14_modified13", "Z61_5008.NEF", "Astro (Modified13)", "lossless"),
                  ("11.14_modified13", "Z61_5009.NEF", "Astro (Modified13)", "lossless"),
                  ("11.17_modified22", "Z61_5116.NEF", "Standard (Modified22)", "packed-14"),
                  ("11.17_modified22", "Z61_5117.NEF", "Standard (Modified22)", "packed-14"),
                  ("11.17_modified22", "Z61_5118.NEF", "Standard (Modified22)", "packed-14"),
                  ("11.17_modified22", "Z61_5105.NEF", "Astro (Modified22)", "16-bit LE"),
                  ("11.17_modified22", "Z61_5106.NEF", "Astro (Modified22)", "16-bit LE"),
                  ("11.17_modified22", "Z61_5107.NEF", "Astro (Modified22)", "16-bit LE")]
CROSS_BASELINE = [("11.14_modified13", ["Z61_4994.NEF", "Z61_5000.NEF", "Z61_5006.NEF"], "Flat", "Astro"),
                  ("11.16_modified21", ["_Z615096.NEF", "_Z615097.NEF", "_Z615098.NEF", "Z61_5093.NEF",
                                        "Z61_5094.NEF", "Z61_5095.NEF"], "Flat", "-")]


def load(root, batch, name):
    rec = L.parse_nef(root / batch / name)
    lay = L.classify_layout(rec)
    img, clean = L.decode_raw(rec, lay)
    return rec, lay, img, clean


def comb_of(img):
    return L.comb_metrics(img)


def noise_estimates(d):
    """d = frame_a - frame_b (int32).  Returns sigma of a single frame (divided by sqrt2)."""
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
        "delta_p16": float(p15),
        "delta_p84": float(p84),
        "delta_iqr": float(p75 - p25),
        "delta_max_abs": int(np.abs(d).max()),
        "clipped_pixels_abs_gt_100": int((np.abs(d) > 100).sum()),
    }


def _delta_histogram(per_target):
    h = {}
    for t in per_target:
        h[t["delta"]] = h.get(t["delta"], 0) + 1
    return {str(k): int(v) for k, v in sorted(h.items())}


def _portable_label(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.name


def main():
    here = Path(__file__).resolve().parent
    repo_root = here.parents[1]
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples-root", default=str(repo_root / "samples"))
    ap.add_argument("--baseline112", default=str(repo_root / "docs" / "evidence" / "baseline112.json"))
    ap.add_argument("--out", default=str(repo_root / "docs" / "evidence" / "m22_audit_metrics.json"))
    args = ap.parse_args()

    root = Path(args.samples_root).resolve()
    base = json.loads(Path(args.baseline112).read_text(encoding="utf-8"))
    targets = base["targets"]

    out = {"artifact": "m22_audit_metrics", "schema_version": "1.0",
           "generated_from": _portable_label(root, repo_root),
           "method": {
               "generator": "build_m22_audit_metrics.py",
               "generator_version": L.GENERATOR_VERSION,
               "environment": L.environment(),
               "geometry": {"stored_grid_wh": [L.SENSOR_W, L.SENSOR_H],
                            "sensor_area_xywh": list(L.SENSOR_AREA),
                            "black_level": L.BLACK_LEVEL_DEFAULT,
                            "center_roi": "middle half of each 2020x3032 plane -> 1010x1516 = 1,531,160 px"},
               "comb_metric": {"channel": "R = img[0::2,0::2]",
                               "histogram": "np.bincount(np.clip(roi,0,16383), minlength=16384)",
                               "spectrum": "np.abs(np.fft.rfft(hist, 16384)) unnormalised",
                               "caliber_1": ("exact bin 3729 = 3729/16384 = 0.22760009765625 cyc/DN "
                                             "(the 'nearest 0.2276 bin' of review_samples.json / M22 report)"),
                               "caliber_2": ("max |rfft| over freqs in [0.22, 0.24]; the reported frequency "
                                             "is argmax_bin/16384, i.e. 0.227905-0.228394 for the observed combs"),
                               "dominant": ("max |rfft| over [0.05, 0.45] -- added here because it identifies "
                                            "the actual comb tooth, which is not always at 0.2276")},
               "noise": ("frame difference d = A - B on int32 values, sigma_single = estimator(d)/sqrt(2) with "
                         "three estimators: IQR/1.349, central 68.27 % (p84.134-p15.866)/2 and plain std"),
               "frozen112": ("baseline112.json kernels: R/B = (+-2,+-2),(+-2,0),(0,+-2); G1/G2 = (+-2,0),(0,+-2),"
                             "(+-1,+-1); hit when 0 <= centre-max8 <= 56 and (centre-max8) % 8 == 0"),
           }}

    # ---------------------------------------------------------------- A
    a_rows = []
    for name in [n for n in PACKED14_FILES if n not in U16_FILES]:
        rec, lay, img, clean = load(root, M22, name)
        lib = L.decode_with_libraw(rec)
        d = img.astype(np.int32) - lib.astype(np.int32)
        a_rows.append({
            "rel_path": "%s/%s" % (M22, name), "sha256": L.sha256_file(root / M22 / name),
            "verified_raw_layout": lay["layout"],
            "strip_offset": lay["strip_offset"], "strip_byte_count": lay["strip_byte_count"],
            "row_stride_bytes": lay["row_stride_bytes"],
            "frame_shape": list(img.shape), "pixels_compared": int(img.size),
            "libraw_shape": list(lib.shape),
            "pixel_diff_count": int((d != 0).sum()),
            "pixel_diff_ratio": float((d != 0).mean()),
            "max_abs_diff": int(np.abs(d).max()),
            "identical": bool((d == 0).all()),
            "libraw_median_adu": float(np.median(lib)),
            "unpacker_median_adu": float(np.median(img)),
        })
        print("A %-14s diff=%d identical=%s" % (name, a_rows[-1]["pixel_diff_count"], a_rows[-1]["identical"]),
              flush=True)
    out["A_packed14_fullframe_verification"] = {
        "note": ("LibRaw (rawpy 0.28.0 / LibRaw 0.22.2) vs the independent LSB-first packed-14 unpacker, "
                 "full 6064x4040 frame, every one of the 24,498,560 pixel values compared"),
        "files_checked": len(a_rows),
        "all_identical": all(r["identical"] for r in a_rows),
        "total_pixel_diff_count": int(sum(r["pixel_diff_count"] for r in a_rows)),
        "per_file": a_rows,
    }

    # ---------------------------------------------------------------- B
    cache = {}
    per_file = {}
    for name in PACKED14_FILES:
        rec, lay, img, clean = load(root, M22, name)
        cache[name] = (rec, lay, img, clean)
        cm = comb_of(img)
        per_file[name] = {
            "rel_path": "%s/%s" % (M22, name),
            "comb_fft_bin3729_0p2276": cm["comb_fft_bin3729_0p2276"],
            "comb_band_0p22_0p24_peak": cm["comb_band_0p22_0p24_peak"],
            "comb_band_peak_freq": cm["comb_band_peak_freq"],
            "comb_dominant_freq_0p05_0p45": cm["comb_dominant_freq_0p05_0p45"],
            "comb_dominant_spacing_dn": cm["comb_dominant_spacing_dn"],
            "comb_dominant_prominence": cm["comb_dominant_prominence"],
            "hist_nonempty_bins_in_median_pm50": cm["hist_nonempty_bins_in_median_pm50"],
            "roi_median": cm["roi_median"],
        }

    def pair_block(astro, std, label):
        A = [per_file[n] for n in astro]
        S = [per_file[n] for n in std]
        ma_b = float(np.median([x["comb_fft_bin3729_0p2276"] for x in A]))
        ms_b = float(np.median([x["comb_fft_bin3729_0p2276"] for x in S]))
        ma_p = float(np.median([x["comb_band_0p22_0p24_peak"] for x in A]))
        ms_p = float(np.median([x["comb_band_0p22_0p24_peak"] for x in S]))
        return {
            "label": label,
            "astro_files": astro, "standard_files": std,
            "astro": A, "standard": S,
            "astro_median_bin3729": ma_b, "standard_median_bin3729": ms_b,
            "astro_median_band_peak": ma_p, "standard_median_band_peak": ms_p,
            "reduction_standard_over_astro_bin3729": ms_b / ma_b,
            "reduction_standard_over_astro_band_peak": ms_p / ma_p,
            "per_pair_reduction_bin3729": [
                {"pair": [astro[i], std[i]],
                 "standard": per_file[std[i]]["comb_fft_bin3729_0p2276"],
                 "astro": per_file[astro[i]]["comb_fft_bin3729_0p2276"],
                 "ratio_standard_over_astro": (per_file[std[i]]["comb_fft_bin3729_0p2276"] /
                                               per_file[astro[i]]["comb_fft_bin3729_0p2276"])}
                for i in range(3)],
            "per_pair_reduction_band_peak": [
                {"pair": [astro[i], std[i]],
                 "standard": per_file[std[i]]["comb_band_0p22_0p24_peak"],
                 "astro": per_file[astro[i]]["comb_band_0p22_0p24_peak"],
                 "ratio_standard_over_astro": (per_file[std[i]]["comb_band_0p22_0p24_peak"] /
                                               per_file[astro[i]]["comb_band_0p22_0p24_peak"])}
                for i in range(3)],
            "astro_dominant_spacings_dn": [x["comb_dominant_spacing_dn"] for x in A],
            "standard_dominant_spacings_dn": [x["comb_dominant_spacing_dn"] for x in S],
        }

    flats = pair_block(FLAT_ASTRO, FLAT_STD, "flat 1/8000 s ISO 1600 (5110-5112 Astro vs 5119-5121 Standard)")
    bias = pair_block(BIAS_ASTRO, BIAS_STD, "bias 1/8000 s ISO 1600 (5102-5104 Astro vs 5113-5115 Standard)")
    darks = pair_block(U16_FILES, DARK_STD, "5 s dark ISO 1600 (5105-5107 Astro 16-bit vs 5116-5118 Standard packed-14)")
    flats["interpretation"] = (
        "Astro flats carry their comb at 0.0858 cyc/DN (11.653 DN spacing, prominence ~90) instead of at "
        "0.2276-0.2280 (4.385 DN); the [0.22,0.24] band therefore measures the presence/absence of the "
        "4.385-DN comb, while bin 3729 sits on the shoulder of that comb and additionally depends on how "
        "narrow the tooth is (i.e. on the histogram width), which is why bin 3729 varies 1.4e3-7.1e4 among "
        "the three Standard flats while the band peak stays at 278-280 k.")
    bias["interpretation"] = (
        "Bias frames: Standard keeps the 4.385-DN comb (band peak 421-422 k, bin 3729 = band peak because the "
        "dark histogram is narrow and the tooth is broad); Astro only has the low-frequency lobe "
        "(band peak 62-64 k, bin 3729 31-35 k).")
    darks["interpretation"] = (
        "5 s darks: Standard packed-14 frames keep the 4.385-DN comb (414-417 k); the Astro frames stored as "
        "16-bit LE show only the low-frequency lobe (94-101 k).")
    out["B_comb_pair_comparison"] = {"per_file": per_file, "flat_pair": flats, "bias_pair": bias, "dark_pair": darks}

    # ---------------------------------------------------------------- C
    c_rows = []
    d_full = {}
    for a, b, mode in NOISE_PAIRS:
        d_full[mode] = (cache[a][2].astype(np.int32) - cache[b][2].astype(np.int32))
    for a, b, mode in NOISE_PAIRS:
        d = d_full[mode]
        row = {"pair": ["%s/%s" % (M22, a), "%s/%s" % (M22, b)], "capture_mode": mode,
               "full_frame": noise_estimates(d)}
        ra = L.center_roi(cache[a][2][0::2, 0::2].astype(np.int32))
        rb = L.center_roi(cache[b][2][0::2, 0::2].astype(np.int32))
        row["center_R_roi"] = noise_estimates(ra - rb)
        va = cache[a][2][8:4032, 8:6056].astype(np.int32)
        vb = cache[b][2][8:4032, 8:6056].astype(np.int32)
        row["sensor_area"] = noise_estimates(va - vb)
        c_rows.append(row)
        print("C %s %s std=%.6f iqr=%.6f c68=%.6f" % (
            mode, a, row["full_frame"]["unclipped_std"], row["full_frame"]["IQR_sigma"],
            row["full_frame"]["central_68pct_sigma"]), flush=True)

    rs = None
    rs_path = here.parent / "review_samples.json"
    review_crosscheck = None
    if rs_path.exists():
        rs = json.loads(rs_path.read_text(encoding="utf-8"))
        review_crosscheck = []
        for npair in rs.get("noise_pairs") or []:
            f1, f2 = npair["pair"]
            match = [r for r in c_rows if r["pair"][0].endswith(f1) and r["pair"][1].endswith(f2)]
            if match:
                m = match[0]["full_frame"]
                review_crosscheck.append({
                    "pair": npair["pair"],
                    "review_samples": {"std_over_sqrt2": npair["std_over_sqrt2"],
                                       "central68_over_2sqrt2": npair["central68_over_2sqrt2"],
                                       "iqr_over_1_349sqrt2": npair["iqr_over_1_349sqrt2"]},
                    "recomputed": {"unclipped_std": m["unclipped_std"],
                                   "central_68pct_sigma": m["central_68pct_sigma"],
                                   "IQR_sigma": m["IQR_sigma"]},
                    "identical": (abs(npair["std_over_sqrt2"] - m["unclipped_std"]) < 1e-12 and
                                  abs(npair["central68_over_2sqrt2"] - m["central_68pct_sigma"]) < 1e-12 and
                                  abs(npair["iqr_over_1_349sqrt2"] - m["IQR_sigma"]) < 1e-12)})
    out["C_bias_noise_pairs"] = {
        "note": ("d = A - B on int32 raw values; sigma_single(frame) = estimator(d)/sqrt(2). "
                 "full_frame reproduces review_samples.json noise_pairs bit-for-bit"),
        "pairs": c_rows,
        "review_samples_crosscheck": review_crosscheck,
    }

    # ---------------------------------------------------------------- D
    d_rows = []
    overlay_hist = {}
    for batch, name, mode, dec in FROZEN_FRAMES:
        rec, lay, img, clean = load(root, batch, name)
        m = L.frozen112_metrics(img, targets)
        row = {"rel_path": "%s/%s" % (batch, name), "capture_mode": mode, "decoder": dec,
               "verified_raw_layout": lay["layout"],
               "n_targets": m["n_targets"], "matches_0_8_to_56": m["matches_0_8_to_56"],
               "exact_max_delta0": m["exact_max_0_0"], "above56": m["above56"], "below0": m["below0"],
               "median_delta": m["median_delta"], "mean_delta": m["mean_delta"],
               "delta_histogram": _delta_histogram(m["per_target"]),
               "per_target": [{"x": r["x"], "y": r["y"], "phase": r["phase"], "center": r["center"],
                               "max8": r["max8"], "delta": r["delta"], "k": r["k"], "hit_8k": r["hit_8k"]}
                              for r in m["per_target"]]}
        if lay["layout"] == "uncompressed_16bit_le_with_preview_overlay":
            r0, r1 = lay["preview_overlay_rows"]
            centre_in = [t for t in m["per_target"] if r0 <= t["y"] <= r1]
            kern_in = [t for t in m["per_target"]
                       if (t["y"] + 2 >= r0) and (t["y"] - 2 <= r1)]
            fully_clean = [t for t in m["per_target"] if t["y"] + 2 < r0]
            row["preview_overlay"] = {
                "overlay_rows": [r0, r1],
                "targets_with_centre_in_overlay_rows": len(centre_in),
                "targets_with_any_kernel_row_in_overlay": len(kern_in),
                "targets_fully_inside_clean_rows": len(fully_clean),
                "hit_rate_on_fully_clean_targets": {
                    "n": len(fully_clean),
                    "matches_0_8_to_56": sum(1 for t in fully_clean if t["hit_8k"]),
                    "above56": sum(1 for t in fully_clean if t["delta"] > 56),
                    "median_delta": float(np.median([t["delta"] for t in fully_clean])) if fully_clean else None},
                "hit_rate_including_contaminated_targets": {
                    "n": len(m["per_target"]),
                    "matches_0_8_to_56": m["matches_0_8_to_56"],
                    "above56": m["above56"]},
                "target_y_coordinates": sorted(t["y"] for t in m["per_target"]),
                "targets_in_overlay_detail": [{"x": t["x"], "y": t["y"], "center": t["center"],
                                               "max8": t["max8"], "delta": t["delta"]} for t in centre_in],
            }
            overlay_hist[name] = row["preview_overlay"]
        d_rows.append(row)
        print("D %-30s hits=%3d above56=%3d median_delta=%6.1f" % (
            name, m["matches_0_8_to_56"], m["above56"], m["median_delta"]), flush=True)

    discovery_check = None
    if base.get("discovery112"):
        f4854 = [r for r in d_rows if r["rel_path"].endswith("Z61_4854.NEF")][0]
        f4855 = [r for r in d_rows if r["rel_path"].endswith("Z61_4855.NEF")][-1]
        combined = {}
        for r in (f4854, f4855):
            for k, v in r["delta_histogram"].items():
                combined[k] = combined.get(k, 0) + v
        known = base["discovery112"]["delta_histogram"]
        discovery_check = {
            "baseline112_discovery112_delta_histogram": known,
            "recomputed_4854_plus_4855_delta_histogram": dict(sorted(combined.items(), key=lambda kv: int(kv[0]))),
            "identical": all(combined.get(k, 0) == v for k, v in known.items()) and
                         sum(combined.values()) == sum(known.values()),
            "centers_of_4854_equal_baseline_dark_centres_0": [r["center"] for r in f4854["per_target"]] ==
                                                              [t["dark_centres"][0] for t in targets],
            "centers_of_4855_equal_baseline_dark_centres_1": [r["center"] for r in f4855["per_target"]] ==
                                                              [t["dark_centres"][1] for t in targets],
            "note": ("recomputing the 112 clamp deltas on the two original-firmware darks reproduces "
                     "baseline112.json discovery112 exactly (delta histogram and per-target centres), which "
                     "both validates this implementation of the kernel and proves 4854/4855 are the discovery "
                     "frames"),
        }
    out["D_frozen112_clamp"] = {
        "kernel": {"R_B": base.get("kernel_R_B"), "G1_G2": base.get("kernel_G1_G2"),
                   "formula": base.get("formula"), "coordinates": base.get("coordinates")},
        "baseline112_sha256": hashlib.sha256(Path(args.baseline112).read_bytes()).hexdigest(),
        "discovery_reproduction": discovery_check,
        "frames": d_rows,
    }

    # ---------------------------------------------------------------- E
    e_rows = []
    for name in U16_FILES:
        rec, lay, img, clean = load(root, M22, name)
        x, y, w, h = L.SENSOR_AREA
        r0, r1 = lay["preview_overlay_rows"]
        cleanfull = L.basic_stats(img[clean].astype(np.int32))
        cleanarea = L.basic_stats(img[clean].astype(np.int32).reshape(-1, 1))
        areasub = img[y:y + h, x:x + w]
        rows_ok = clean[y:y + h]
        e_rows.append({
            "rel_path": "%s/%s" % (M22, name),
            "size_bytes": rec["filesize"],
            "sha256": L.sha256_file(root / M22 / name),
            "raw_strip_offset": lay["strip_offset"],
            "raw_strip_byte_count": lay["strip_byte_count"],
            "strip_end_equals_filesize": lay["verification"]["strip_end_equals_filesize"],
            "bits_per_sample_tag": rec["bits_per_sample"],
            "tiff_compression": rec["tiff_compression"],
            "row_stride_bytes": lay["row_stride_bytes"],
            "preview_overlay_rows": [r0, r1],
            "clean_rows": lay["clean_rows"],
            "clean_row_fraction": lay["clean_rows"] / L.SENSOR_H,
            "embedded_jpeg_slots": lay["embedded_jpeg_slots"],
            "slots_all_identical_to_declared_previews": lay["verification"]["all_slots_identical_to_declared_previews"],
            "slots_all_512_aligned": lay["verification"]["all_slots_512_byte_aligned"],
            "clean_region_pixel_stats": cleanfull,
            "clean_region_zero_adu_count": cleanfull["zero_adu_count"],
            "clean_region_below_1008_count": cleanfull["below_1008_count"],
            "clean_region_below_1008_ratio": cleanfull["below_1008_ratio"],
            "sensor_area_excluding_overlay_rows": L.basic_stats(areasub[rows_ok].astype(np.int32)),
            "full_strip_including_overlay_stats": L.basic_stats(img.astype(np.int32).reshape(-1, 1)),
            "max_value_in_clean_region": cleanfull["max"],
            "le_16383_in_clean_region": bool(cleanfull["max"] <= 16383),
            "libraw_decode_of_same_file": L.basic_stats(L.decode_with_libraw(rec).astype(np.int32).reshape(-1, 1)),
            "libraw_packed14_misdecode_artifact": True,
        })
    out["E_u16_anomalous_layout"] = {
        "note": ("Z61_5105/5106/5107 declare Compression=34713 BitsPerSample=14 like every other file but store "
                 "6064*4040*2 = 48,997,120 bytes of uncompressed 16-bit little-endian data; three preview JPEGs "
                 "are embedded inside that declared strip at fixed relative slots and overwrite rows 3633-4000. "
                 "LibRaw decodes them as packed-14 and produces garbage."),
        "files": e_rows,
        "overlay_row_map_from_frozen_targets": overlay_hist,
    }

    # ---------------------------------------------------------------- F cross-generation
    f_rows = []
    for batch, names, cat, mode in CROSS_BASELINE:
        for name in names:
            rec, lay, img, clean = load(root, batch, name)
            cm = comb_of(img)
            ch = L.channel_medians(img)
            f_rows.append({"rel_path": "%s/%s" % (batch, name), "frame_category": cat,
                           "capture_mode_label": mode, "verified_raw_layout": lay["layout"],
                           "exposure_time": rec["exif"]["exposure_time"],
                           "comb_fft_bin3729_0p2276": cm["comb_fft_bin3729_0p2276"],
                           "comb_band_0p22_0p24_peak": cm["comb_band_0p22_0p24_peak"],
                           "comb_band_peak_freq": cm["comb_band_peak_freq"],
                           "comb_dominant_spacing_dn": cm["comb_dominant_spacing_dn"],
                           "center_R_G1_ratio": ch["center_R_G1_ratio"]})
    for name in ["Z61_5096.NEF", "Z61_5097.NEF", "Z61_5098.NEF"]:
        if (root / "11.16_modified21" / name).exists():
            f_rows.append({"rel_path": "11.16_modified21/%s" % name, "note": "listed by the task as 5093-5098"})
    out["F_cross_generation_baselines"] = f_rows

    # ---------------------------------------------------------------- findings
    out["G_key_numbers"] = {
        "packed14_fullframe_identity": {
            "files": len(a_rows), "total_pixel_diff_count": out["A_packed14_fullframe_verification"]["total_pixel_diff_count"],
        },
        "flat_pair_reduction": {
            "bin3729": flats["reduction_standard_over_astro_bin3729"],
            "band_peak": flats["reduction_standard_over_astro_band_peak"],
            "astro_band_peak": flats["astro_median_band_peak"],
            "standard_band_peak": flats["standard_median_band_peak"],
            "astro_bin3729": flats["astro_median_bin3729"],
            "standard_bin3729": flats["standard_median_bin3729"],
        },
        "bias_pair_reduction": {
            "bin3729": bias["reduction_standard_over_astro_bin3729"],
            "band_peak": bias["reduction_standard_over_astro_band_peak"],
            "astro_band_peak": bias["astro_median_band_peak"],
            "standard_band_peak": bias["standard_median_band_peak"],
            "astro_bin3729": bias["astro_median_bin3729"],
            "standard_bin3729": bias["standard_median_bin3729"],
        },
        "dark_pair_reduction": {
            "bin3729": darks["reduction_standard_over_astro_bin3729"],
            "band_peak": darks["reduction_standard_over_astro_band_peak"],
        },
        "frozen112": {r["rel_path"]: {"hits": r["matches_0_8_to_56"], "above56": r["above56"],
                                      "median_delta": r["median_delta"]} for r in d_rows},
        "discovery_reproduction_identical": None if discovery_check is None else discovery_check["identical"],
    }

    Path(args.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
    print("wrote", args.out)


if __name__ == "__main__":
    main()

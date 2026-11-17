# Nikon Z6 C3.80 Modified22 — Independent 18-NEF Pixel-Level Audit & Uncompressed Dark Layout Analysis (2026-11-17)

> 🌐 **Language / 语言**: **[简体中文](MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

This report documents the byte- and pixel-level audit of **18 real-camera NEF frames** (capture batch `samples/11.17_modified22`) shot on a physical Nikon Z6 running **`Modified22`** (`EG162080.BIN`, SHA-256 `c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771`, CRC-16/XMODEM `0x48f3`).

Pinned machine-readable datasets:
- [docs/evidence/m22_audit_metrics.json](evidence/m22_audit_metrics.json) (`Modified22` per-frame comb FFT, bias readout noise estimators, frozen-112 hot-pixel retention, and 16-bit LE embedded preview-slot audit)
- [docs/evidence/baseline112.json](evidence/baseline112.json) (112 hot-pixel coordinates and $3\times 3$ same-color neighborhood kernel frozen on Stock C3.80 frames `Z61_4854/4855`)
- [docs/SAMPLE_EVIDENCE_CATALOG.json](SAMPLE_EVIDENCE_CATALOG.json) (SHA-256 digests, EXIF/MakerNote tags, raw storage layouts, and spectral metrics for all 121 real-camera NEF frames)

---

## 1. Executive Summary

1. **Menu Switch, Standard DCF Naming & `sRGB` Lock Verified End-to-End**:
   - Across all 18 real-camera NEFs (shutter count `480719..480738`, lens `Viltrox AF 16/1.8 Z`, manual `M` mode, `ISO 1600`, `f/1.8`), **18/18 filenames retain the standard `Z61_` prefix** (completely eliminating the `_Z61` Adobe RGB prefix seen in `Modified21`);
   - MakerNote `ColorSpace (0x001E)` is **`1 (sRGB)` on 18/18 frames**, and `BlackLevel (0x003D)` is `[1008, 1008, 1008, 1008]` across all frames;
   - Confirms on physical hardware that the `PID 0x0526` (`RAM 0xC24CDEA0`) UI gate and `0x1014BB28` effective color space lock (`PID 0x130A = 0`) operate as designed.
2. **Frontend ISP Missing-Code Comb (Concentric Rings Root Cause) Decisively Suppressed**:
   - Under identical exposure and raw layout (`1/8000s`, `ISO 1600`, `packed_14bit_stride10624`):
     - **Flat-Field Pairs** (`Astro` `Z61_5110..5112` vs `Standard` `Z61_5119..5121`): Center-ROI R-channel 16384-bin unnormalized `|rfft|` at `0.2276001 cyc/DN` (`bin 3729`) drops in batch median from **`33,437.7` to `4,650.4`** (**7.2× reduction**; representative pair `5119` vs `5110` drops from **`27,241.6` to `2,012.4`**, **13.5× reduction**); `[0.22, 0.24] cyc/DN` band peak median drops from **`278,369.0` to `28,450.9`** (**9.8× reduction**); center `R/G1` median ratio returns from in-camera pre-scaled `1.0101~1.0105` (median `1.0103`) to native sensor QE ratio `0.8985~0.9035` (median `0.8997`).
     - **Bias Pairs** (`Astro` `Z61_5102..5104` vs `Standard` `Z61_5113..5115`): `bin 3729` batch median drops from **`420,840.8` to `34,012.9`** (**12.4× reduction**; `5113` vs `5102`: **13.4× reduction**); `[0.22, 0.24]` band peak median drops from **`421,913.1` to `63,311.9`** (**6.7× reduction**).
3. **Dark-Frame Hot-Pixel Retention & Readout Noise**:
   - **Single-Frame Bias Readout Noise** ($\sigma = \text{estimator}(A - B)/\sqrt{2}$, full `6064×4040` grid): `Astro` pair `5102 vs 5103` measures **`3.5355 DN`** (central 68.27%), **`3.1450 DN`** (IQR), and **`4.1133 DN`** (unclipped std); `Standard` pair `5113 vs 5114` (inflated by digital gain step widening) measures **`3.5355 DN`**, **`4.1934 DN`**, and **`4.5945 DN`**. Active-area `0 ADU` count is **`0`** in both modes, preserving full negative noise excursions below `1008 DN`.
   - **Frozen-112 Hot-Pixel Clamp Benchmark**: M22 `Standard` 5s darks (`Z61_5116..5118`) hit the stock `max8 + 8k` clamp rule on **`102~107 / 112` (`91.1%~95.5%`, per-frame `105, 102, 107 / 112`)**; M22 `Astro` 5s darks (`Z61_5105..5107`) evaluated across the **95 frozen targets in the clean upper row region (`y+2 < 3633`)** record **`0 / 95 (0%)` clamp hits** and **`95 / 95 (100%)` above `+56 DN`** (median `center - max8` delta `+14,448 ~ +15,230 DN`, matching `Modified13` lossless 5s darks `Z61_5007..5009` at `0 / 112` clamp hits and `112 / 112` above `+56 DN` with `+10,715 ~ +11,340 DN`).
4. **Key Operational Constraint — `Astro RAW + 5s Uncompressed NEF` 16-Bit LE Stream & Preview Overlay**:
   - All 12 `1/8000s` frames plus the 3 `Standard` 5s darks (15 frames total) write standard `42,920,960` B (`packed-14`, row stride `10,624` B) payloads, matching LibRaw 0.22.2 with **zero pixel discrepancies across `15 × 24,498,560` pixels**.
   - Exclusively in **`Z61_5105 / 5106 / 5107` (`Astro RAW + 5s + Uncompressed`)**, although TIFF tags still declare `Compression=34713, BitsPerSample=14`, the camera writes a **`48,997,120` B (`6064×4040×2`) uncompressed 16-bit LE stream**, and writes three embedded preview JPEG copies at fixed offsets derived from the `42,920,960` B template—overwriting bottom rows **`3633..4000`** and causing LibRaw/rawpy to misdecode the strip as packed-14.
   - **Mandatory User Guideline**: When shooting **`>= 1s` exposures** in **`Astro RAW (sRGB)`**, always set **`NEF (RAW) compression`** to **`Lossless compressed`** (verified 100% clean with zero preview overlap on 5s lossless darks `Z61_5007..5009`).

---

## 2. Per-Frame Inventory & Quantitative Metrics (18 Real-Camera NEFs)

Measurement definitions (`tools/evidence/nef_evidence_lib.py`):
- **Sensor Grid / Active Area**: Full grid `6064 × 4040`; MakerNote `SensorArea (0x0045)` = `(8, 8, 6048, 4024)`; CFA phase `[[R, G1], [G2, B]]`.
- **Center ROI**: Central 50% along each axis of each Bayer plane (`2020 × 3032` -> rows `[505, 1515]`, cols `[758, 2274]`, `1010 × 1516 = 1,531,160` pixels/channel).
- **Histogram Comb Metric**: 16384-bin histogram (`0..16383`) of Center-ROI R-channel pixels, evaluated via unnormalized `np.abs(np.fft.rfft(hist, 16384))` at fixed **`bin 3729` (`0.2276001 cyc/DN`)** and the **`[0.22, 0.24] cyc/DN` band peak**.

| Filename | Shutter # | Exposure | Verified RAW Layout | Category | Mode | Center R Median | Center R/G1 | `bin 3729` (`0.2276`) | `[0.22, 0.24]` Peak (Freq) |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Z61_5102.NEF` | 480719 | 1/8000s | `packed_14bit_stride10624` | Bias | Astro | 1008.0 | 1.0000 | 31,507.7 | 61,550.9 (`0.23999`) |
| `Z61_5103.NEF` | 480720 | 1/8000s | `packed_14bit_stride10624` | Bias | Astro | 1008.0 | 1.0000 | 34,628.2 | 64,061.0 (`0.23999`) |
| `Z61_5104.NEF` | 480721 | 1/8000s | `packed_14bit_stride10624` | Bias | Astro | 1008.0 | 1.0000 | 34,012.9 | 63,311.9 (`0.23999`) |
| `Z61_5105.NEF` | 480722 | 5s | `uncompressed_16bit_le_with_preview_overlay` | Dark | Astro | 1009.0 | 1.0000 | 67,129.2 | 100,339.9 (`0.23999`) |
| `Z61_5106.NEF` | 480723 | 5s | `uncompressed_16bit_le_with_preview_overlay` | Dark | Astro | 1008.0 | 1.0000 | 61,791.0 | 101,078.1 (`0.23999`) |
| `Z61_5107.NEF` | 480724 | 5s | `uncompressed_16bit_le_with_preview_overlay` | Dark | Astro | 1009.0 | 1.0000 | 63,894.3 | 98,133.9 (`0.23999`) |
| `Z61_5110.NEF` | 480727 | 1/8000s | `packed_14bit_stride10624` | Flat | Astro | 2933.0 | **0.8997** | **2,012.4** | **28,450.9** (`0.22858`) |
| `Z61_5111.NEF` | 480728 | 1/8000s | `packed_14bit_stride10624` | Flat | Astro | 2688.0 | **0.9035** | **4,668.7** | **27,019.4** (`0.22858`) |
| `Z61_5112.NEF` | 480729 | 1/8000s | `packed_14bit_stride10624` | Flat | Astro | 2983.0 | **0.8985** | **4,650.4** | **28,628.4** (`0.22858`) |
| `Z61_5113.NEF` | 480730 | 1/8000s | `packed_14bit_stride10624` | Bias | Standard | 1008.0 | 1.0000 | 421,261.8 | 422,469.0 (`0.22998`) |
| `Z61_5114.NEF` | 480731 | 1/8000s | `packed_14bit_stride10624` | Bias | Standard | 1008.0 | 1.0000 | 419,849.7 | 421,015.6 (`0.22992`) |
| `Z61_5115.NEF` | 480732 | 1/8000s | `packed_14bit_stride10624` | Bias | Standard | 1008.0 | 1.0000 | 420,840.8 | 421,913.1 (`0.22986`) |
| `Z61_5116.NEF` | 480733 | 5s | `packed_14bit_stride10624` | Dark | Standard | 1009.0 | 1.0000 | 415,174.3 | 415,227.9 (`0.22791`) |
| `Z61_5117.NEF` | 480734 | 5s | `packed_14bit_stride10624` | Dark | Standard | 1009.0 | 1.0010 | 416,269.5 | 416,552.4 (`0.22839`) |
| `Z61_5118.NEF` | 480735 | 5s | `packed_14bit_stride10624` | Dark | Standard | 1009.0 | 1.0010 | 413,978.0 | 414,180.5 (`0.22827`) |
| `Z61_5119.NEF` | 480736 | 1/8000s | `packed_14bit_stride10624` | Flat | Standard | 3316.0 | **1.0101** | **27,241.6** | **278,093.3** (`0.22803`) |
| `Z61_5120.NEF` | 480737 | 1/8000s | `packed_14bit_stride10624` | Flat | Standard | 3274.0 | **1.0105** | **33,437.7** | **279,979.4** (`0.22803`) |
| `Z61_5121.NEF` | 480738 | 1/8000s | `packed_14bit_stride10624` | Flat | Standard | 3237.0 | **1.0103** | **35,212.8** | **278,369.0** (`0.22803`) |

*(Note: Shutter counts `480725` and `480726` correspond to `Z61_5108/5109` deleted in-camera during the test session; full SHA-256 digests are listed in `docs/SAMPLE_EVIDENCE_CATALOG.json`.)*

---

## 3. Bias Readout Noise & Frozen-112 Cross-Generation Verification

### 3.1 Single-Frame Bias Readout Noise (`ISO 1600`, `1/8000s`)

| Frame Pair | Mode | Region | Central 68.27% $\sigma$ | IQR $\sigma$ (`/1.349`) | Unclipped `std` $\sigma$ | Active-Area `0 ADU` Pixels |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: |
| `Z61_5102` vs `5103` | Astro | Full `6064×4040` | `3.5355 DN` | `3.1450 DN` | `4.1133 DN` | `0` |
| `Z61_5113` vs `5114` | Standard | Full `6064×4040` | `3.5355 DN` | `4.1934 DN` | `4.5945 DN` | `0` |

### 3.2 Frozen-112 Hot-Pixel Neighborhood Clamp Hit Rate (5s Dark Frames)

| Batch & Frames | Mode & Firmware | RAW Layout | Targets | `max8 + 8k` Hits (`0..56`) | Above `+56 DN` | Median `center - max8` |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| `11.9 / Z61_4854, 4855` | Stock C3.80 | `lossless_14bit` | 112 | **112 / 112 (100%)** | 0 / 112 | `0.0 DN` (mean `+6.4 ~ +7.1 DN`) |
| `11.14 / Z61_5007..5009` | M13 Astro | `lossless_14bit` | 112 | **0 / 112 (0%)** | **112 / 112 (100%)** | `+10,715 ~ +11,340 DN` |
| `11.17 / Z61_5116..5118` | M22 Standard | `packed_14bit_stride10624` | 112 | **102~107 / 112 (91.1%~95.5%)** | 5~10 / 112 | `0.0 DN` (mean `+13.1 ~ +19.6 DN`) |
| `11.17 / Z61_5105..5107` | M22 Astro | `uncompressed_16bit_le` (clean rows `y+2 < 3633`) | **95** | **0 / 95 (0%)** | **95 / 95 (100%)** | `+14,448 ~ +15,230 DN` |

---

## 4. `Z61_5105 / 5106 / 5107` Uncompressed 16-Bit LE Layout & Embedded Preview Overlay

Within `samples/11.17_modified22`, `Z61_5105`, `Z61_5106`, and `Z61_5107` (`Astro RAW + 5s + Uncompressed`) exhibit a distinct physical strip layout compared with the 15 `packed-14` frames:

1. **True Pixel Stream Is `16-bit little-endian` (Despite `packed-14` TIFF Tags)**:
   - `SubIFD2` still writes `Compression = 34713` and `BitsPerSample = 14`, yet `StripByteCounts = 48,997,120 = 6064 × 4040 × 2` (versus `42,920,960 = 4040 × 10,624` in the other 15 frames), with `StripOffset + StripByteCounts == filesize`.
   - Decoding the clean upper rows as `16-bit LE` (`12,128` B/row) yields median `1008~1009 DN`, mean adjacent-pixel absolute difference `~7.6 DN` (matching `7.0 DN` on standard 5s dark `Z61_5116`), maximum `<= 16383`, and `0 ADU` count = **`0`**.
   - LibRaw 0.22.2 / `rawpy 0.28.0` trusts `Compression=34713` + `BitsPerSample=14` and misdecodes the 16-bit stream as `packed-14`, shifting the median to `3840~3856 DN`, leaving only 7 populated codes within `median ± 50`, and fabricating `41,144 ~ 54,156` false zero pixels.
2. **Three Embedded Preview JPEG Copies Overwrite Bottom Rows `3633..4000`**:
   - Relative to `SubIFD2 StripOffset`, all three files contain byte-for-byte SHA-256-identical copies of the file's own preview JPEGs at 512-byte-aligned offsets:
     - `+44,072,448` (`0x02A07E00` = `42,920,960 [packed-14 strip] + ceil(1,151,400 [SubIFD5] / 512) × 512`): `SubIFD1` large preview JPEG copy (`~536~567 KB`);
     - `+48,027,648` (`0x02DCC000`): `MakerNote PreviewIFD` thumbnail JPEG copy (`~35~40 KB`);
     - `+48,204,288` (`0x02DF8000`): `SubIFD3` medium preview JPEG copy (`~266~311 KB`).
   - Because preview buffer offsets remain anchored to the `42,920,960` B `packed-14` strip size while the uncompressed RAW stream expands to `48,997,120` B, rows **`3633..4000`** (`3633..4000`, `3633..3996`, `3633..3998` per file) are overwritten, leaving `3672~3676 / 4040 = 90.9%~91.0%` total non-overwritten rows intact (including the contiguous upper clean region `0..3632`).

---

## 5. Verification Boundaries & Practical Recommendations

- **Recommended Long-Exposure Setting**: Always select **`Lossless compressed`** under `NEF (RAW) compression` when shooting **`>= 1s` exposures** in **`Astro RAW (sRGB)`**. This delivers 14-bit linear dark-current preservation, smaller file sizes, zero preview overlap, and clean standard Nikon 14-bit lossless decoding (verified in `LibRaw 0.22.2 / rawpy` on `Z61_5007..5009`).
- **Scope & Non-Extrapolation Statement**:
  1. The `16-bit LE` + preview-overlay layout was observed solely under `Astro RAW + 5s + Uncompressed`; the internal firmware branch triggering 16-bit output under long uncompressed astro exposures has not yet been isolated separately.
  2. M-mode `60"~600"` extended shutter steps were verified at the instruction and timer-divider table level; microsecond mechanical shutter timing accuracy, power-loss recovery, and astronomical photometric linearity remain outside the scope of these indoor calibration frames.

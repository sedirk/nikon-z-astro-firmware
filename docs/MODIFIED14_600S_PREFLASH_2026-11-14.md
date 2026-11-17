# Nikon Z6 C3.80 `Modified14` (`30–600s` Extended Shutter + Astro RAW Convergence) Preflash Report

> [!WARNING]
> **SUPERSEDED / DO NOT FLASH (`Modified14`, SHA-256 `6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b`)**:
> Real-camera testing on 2026-11-15 revealed that `Modified14` locks the M-mode shutter dial in its pre-flash NVRAM shutter state (e.g. `Time` / `T` 门). Forensic Unicorn execution (`tools/fw/z6_m600_v2_emu_e2e.py`) confirmed two architectural defects in `Modified14`'s `0x204` property list hook:
> 1. `ADDR_PROP_DESC` (`0x1002F5F4`, referenced at `0x114D3518`) inserted a duplicate `0x204` at index `1` of the 46-entry dependency list (`0x114CB95C`), shifting `ctx[1..45]` by `+4` bytes inside `0x10150602` (`ctx+0x60` read `0x565 = 0` instead of `0x2 = 0x20` M-mode), causing `0x10150858..0x1015087C` to publish `0x204` with `err = 1` (`disabled_flag = 1`), which in turn caused `0x1012D4AC` inside `0x1012D464` to disable **all 120 `mtbl` entries (`enabled = 0`)**.
> 2. `0xC18BD7C4[0]` (`max_count = 109`), staging buffer `0xC236BEBC..0xC236C070` (`0x1B4` bytes), and `0x1B4`-byte stack callers enforce a hard ceiling of `<= 109` entries on `0x204`.
>
> Use **[`Modified15`](MODIFIED15_600S_FIX_PREFLASH_2026-11-15.md)** (`outputs/Z6-C380-modified15-reviewed-2026-11-15/`, SHA-256 `0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c`) instead.

- **Date**: 2026-11-14
- **Target Model**: Nikon Z6 (1st Gen), Official Firmware Base `C3.80` (`EG162080.BIN`, `33,502,842` bytes)
- **Candidate**: `modified14-production-600s`
  - **SHA-256**: `6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b`
  - **CRC16-HQX**: `0x55ed` (`crc_hqx(full_file, 0) == 0`)
  - **Total Patch Sites**: `98` (`14` inherited unchanged from camera-verified `Modified13` + `84` native ROM `30–600s` sites)
- **Delivery Kit**: `outputs/Z6-C380-modified14-reviewed-2026-11-14/` and `outputs/Z6-C380-modified14-reviewed-2026-11-14.zip`

---

## 1. Root-Cause Analysis of `Modified13` Real Flat-Field (`FLAT`) `R/G` & `B/G` Residuals

Independent review (`reviewer-gpt`) of the 9 real-camera NEFs in `samples/11.14_modified13` (`analysis/modified13-real-2026-11-14/samples/assessment.json`) confirmed that **color-ring high-pass modulation (`R/G hp6` and `B/G hp6`) dropped below both `Modified10` and `Modified12`**, while low-frequency radial color variation (`broad`, $r \in [0.15, 0.90]$) remained non-zero and `broad B/G` rose slightly (`+0.086 pp` vs `M10`, `+0.141 pp` vs `M12`):

| Metric ($r \in [0.15, 0.90]$, 3-frame mean) | `Modified10` | `Modified12` | `Modified13` | Delta (`M13` vs `M12`) |
| --- | ---: | ---: | ---: | ---: |
| **`R/G hp6` ptp** (concentric ring band) | `0.241375%` | `0.222826%` | **`0.175481%`** | **`-21.25%`** (`-27.30%` vs `M10`) |
| **`B/G hp6` ptp** (concentric ring band) | `0.1759%` | `0.1583%` | **`0.1546%`** | **`-2.34%`** (`-12.11%` vs `M10`) |
| **`G1/G2 hp6` ptp** | `0.0450%` | `0.0509%` | **`0.0474%`** | **`-6.88%`** (`+0.0024 pp` vs `M10` noise floor) |
| **`R/G broad` ptp** (low-order radial slope) | `1.632546%` | `1.583046%` | **`1.131867%`** | **`-28.50%`** (`-30.67%` vs `M10`) |
| **`B/G broad` ptp** (low-order radial slope) | `1.467419%` | `1.413009%` | **`1.553782%`** | **`+0.1408 pp`** (optical baseline) |

### Three Quantitative Physical & Firmware Causes
1. **Ultra-Wide Fast-Aperture Optics + Interference Filter Angle Shift (`Viltrox AF 16mm f/1.8 Z` @ `f/1.8`, `1/8000s`, `ISO 1600`)**:
   - EXIF inspection of `Z61_5088..5090.NEF` confirms all flats were captured with an ultra-wide **16mm rectilinear lens wide-open at f/1.8** and **1/8000s** electronic/mechanical high-speed shutter (note: an earlier summary table listed `ISO 100, 1/10s` in prose; actual NEF EXIF is `ISO 1600, 1/8000s, f/1.8, 16mm`).
   - Off-axis chief ray angles (CRA) on full-frame 16mm f/1.8 shift the sensor's dichroic UV/IR-cut interference filter cutoff toward shorter wavelengths ($\lambda(\theta) = \lambda_0 \sqrt{1 - (\sin\theta / n_{\text{eff}})^2}$): H$\alpha$/deep-red transmission rolls off smoothly toward the mid-field (`R/G = -0.84%` at $r=0.60$), while blue transmission near the short-wave edge rises (`B/G = +0.97%` at $r=0.65$ vs `-0.58%` at $r=0.15$).
   - Crucially, a smooth optical/CRA radial slope is **multiplicative photon throughput**, so standard astrophotography Master Flat calibration divides it out cleanly, unlike firmware integer gain steps/rings (`hp6`).
2. **Opposite Radial Sign of Factory `CAL33 Group 0` (`CAL38.bin @ 0x47180`) on `R/G` vs `B/G`**:
   - Factory `CAL33 Group 0` applies a baked sensor color-shading table (`R/G` span `0.890%`, `B/G` span `1.102%`).
   - On `R/G`, `Group 0` reinforced the Viltrox 16mm curve; routing still capture to unity `Group 4` (`16384` across all `33x4` entries) cut `broad R/G` by `-28.50%` (`1.583% -> 1.132%`).
   - On `B/G`, `Group 0` happened to partially oppose (`~0.14 pp`, `~4.5 DN` on a `3200 DN` flat) the Viltrox 16mm's inner-to-mid-field `B/G` slope (`r=0.15`: `-0.420%` in `M12` vs `-0.582%` true uncompensated optical ratio in `M13`; compare `Modified11` at `1.5770%`). Removing `Group 0` therefore reveals the true uncompensated optical `B/G` curve while reducing high-pass `B/G hp6` rings (`0.1583% -> 0.1546%`).
3. **`1/8000s` Illumination Flicker Variance in `Modified12`'s 3-Frame Mean**:
   - At `1/8000s` (`125 us`), light-panel PWM/AC ripple creates frame-to-frame vertical/radial phase differences: `Modified12`'s three individual flats had `broad B/G = [1.4135%, 1.5516%, 1.9501%]` (**single-frame mean = `1.6384%` > `Modified13`'s `1.5546%`**), where `Z61_4978.NEF` had an opposite phase that partially cancelled in the 3-frame average (`1.4130%`). `Modified13`'s three frames are tightly repeatable (`[1.5516%, 1.5527%, 1.5594%]`).

> **Engineering Conclusion**: No additional firmware ISP color table remains active in `Modified13` on the verified still path; phrasing in release documentation is strictly scoped to *"concentric ring (`hp6`) residual reduced to baseline floor (`0.175%` R/G, `0.155%` B/G); smooth optical CRA/vignette slope remains for standard flat-field division."*

---

## 2. `Modified14` (`30–600s` Native ROM Extended Shutter) Architecture

Referencing Nikon Z-series (`Zf` / `Z6` C3.80) exposure-table, command-dial, UI, top-OLED, and PTP architectures, `Modified14` bakes 8 extended M-still shutter speeds directly into two verified zero-filled XIP alignment holes (`0x1002EF14..0x1002FE00` and `0x10D30840..0x10D32B60`) with **zero overlap** against `Modified13`'s 14 astro RAW patches (`0x1002D884..0x1002D8C8` and `0x100AE3A4..0x10197878`):

| Step Label | Internal `Tv` (`s24`, `-24 * EV`) | UI ID | Wall-Clock Exposure ($\mu\text{s}$) | 64-bit Timer ($\text{ns}$) | EXIF `ExposureTime` | PTP `0x500D` (`0.1 ms`) |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| `60"` | `-144` | `67` (`0x43`) | `60,000,000` | `60,000,000,000` | `600 / 10` | `600,000` |
| `90"` | `-156` | `68` (`0x44`) | `90,000,000` | `90,000,000,000` | `900 / 10` | `900,000` |
| `120"` | `-168` | `69` (`0x45`) | `120,000,000` | `120,000,000,000` | `1200 / 10` | `1,200,000` |
| `180"` | `-180` | `70` (`0x46`) | `180,000,000` | `180,000,000,000` | `1800 / 10` | `1,800,000` |
| `240"` | `-192` | `71` (`0x47`) | `240,000,000` | `240,000,000,000` | `2400 / 10` | `2,400,000` |
| `300"` | `-200` | `72` (`0x48`) | `300,000,000` | `300,000,000,000` | `3000 / 10` | `3,000,000` |
| `480"` | `-216` | `73` (`0x49`) | `480,000,000` | `480,000,000,000` | `4800 / 10` | `4,800,000` |
| `600"` | `-224` | `74` (`0x4A`) | `600,000,000` | `600,000,000,000` | `6000 / 10` | `6,000,000` |

### Key Safety & Isolation Guarantees
1. **Boot-Pool Dynamic M-Table with Reset Invalidation (`0x1002FC20`, `0x1002F700`, `0x1002F820`)**:
   - Extends the `0x101120DC` pool allocation from `0x754E0` to `0x75D80` (`+2.2 KB` inside the `45 MB` `0xC9700000` pool) while recording stock `0x754E0` in `0xC1F8879C`.
   - Places a tagged (`0x5549584C`) 120-entry M-mode table at `pool_base + 0x75540`; if the pool ever resets (`0x101E5BA8`), the ready flag is cleared first and `0x10090102` falls back cleanly to stock's 112-entry RAM table (`0xC1816920`).
2. **Strict M-Still Mode Isolation**:
   - Allowed-`Tv` list builder (`0x1015093E`), minimum `Tv*8` clamp (`0x100DAD66`), UI adapters (`0x1002F900`), and PTP `0x500D` setter (`0x10D32B00`) check `exp_mode == 3 (M)`, `movie_mode == 0`, and `sub_mode == 0`.
   - P/A/S, Auto, and Movie modes retain 100% stock `30"` limits, and out-of-mode PTP `0x500D` writes above `30s` return standard PTP error `0x201C`.
3. **Zero Overflow in Exposure Timers**:
   - `600s = 600,000,000 us` (`0x23C34600 < 2^31`, safe in both `u32` and `s32` microsecond paths) and `600,000,000,000 ns` (`0x8BB2C97000`, returned via full 64-bit `umull` in `R0:R1`). Stock speeds (`<= 30"`, where `-5 EV = 32,000,000 us`) fall through to stock code untouched.

---

## 3. Offline Verification Summary (Non-Physical-Camera Scope)

All offline gates passed (note: real physical Z6 body flashing and actual 60s–600s sensor exposure timing remain post-flash hardware tests):
- **Dual-Build & Rollback (`analysis/modified14-preflash-2026-11-14/lab-build/manifest.json`)**:
  - Rebuilt bit-identically from both `Stock C3.80` (`98` sites) and `Modified13` (`84` `m600_*` sites); exact byte-level rollback verified to `Modified13` and `Stock C3.80`.
- **Unicorn ARM/Thumb Native Probe (`analysis/modified14-preflash-2026-11-14/native-probe/native_report.json`)**:
  - `Modified13` digital gain unity (`20` cases -> `4096` + NULL safety) & `CAL33 Group 4` (`16384` in still, `13/13` non-still modes stock): **PASS**.
  - `m600` pool alloc, pool-reset fallback, sentinel clamp, all 8 $\mu\text{s}$/$\text{ns}$ timers & EXIF rationals, stock `30"` passthrough, command dial `30" <-> 600" <-> Bulb/Time` stepping, burst boundary stops, allowed-`Tv` filter, `Tv*8` clamp, all 4 UI adapters, all 4 UI range checks, top-OLED 3-digit BCD (`60"` / `600"`), and PTP `0x500D` mode gate: **PASS**.
- **Native Firmware Updater & Flash Scheduler (`analysis/modified14-preflash-2026-11-14/updater-audit/result.json`)**:
  - `9/9` file discovery/CRC16/precheck cases (`stock/m12/m13 <-> m14` + `bad_crc`, `wrong_model` [filename rejection `EG172080.BIN`], `oversize` rejections) and `6/6` flash scheduler + failure-recovery passes: **PASS**.
- **Standalone Kit Verifier (`outputs/Z6-C380-modified14-reviewed-2026-11-14/verify.py`)**:
  - Verified all 5 `EG162080.BIN` images + `recipe.json` SHA-256 + dual reconstruction: **PASS**.

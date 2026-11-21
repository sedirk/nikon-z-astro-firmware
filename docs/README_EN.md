# Nikon Z6 C3.80 Documentation Index

> 🌐 **Language / 语言**: **[简体中文](README.md)** | **English** · 🏠 [Back to Main README](../README_EN.md)

Documentation in this repository is organized into four sections: **Core Technical Monographs**, **Audit Evidence & Catalogs**, **Release Download & Build Guide**, and **Historical Research Archive**.

---

## 1. Core Technical Monographs

| Document | Topic | Key Coverage |
| :--- | :--- | :--- |
| **[01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md](01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md)** | Frontend ISP Spatial Bypass & Concentric Ring Elimination | 14 RAW & hardware bit-packer hooks, zeroes 54 2D polynomial terms, locks 4-channel Q12 multipliers to `4096` ($1.0\times$), suppressing the `0.2276 cyc/DN` FFT comb |
| **[02_STAR_EATER_AND_DARK_CURRENT_EN.md](02_STAR_EATER_AND_DARK_CURRENT_EN.md)** | Spatial Filtering Bypass & Physical Dark Current Preservation | Bypasses `0x100C2654/7C/90` neighborhood clamps (`max8 + 8k`), preserving true hot pixels and faint pinpoint stars across lossless and uncompressed modes |
| **[03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md](03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md)** | Repurposed Menu Takeover & Effective `sRGB` Lock | Orthogonal repurposed menu properties `PID 0x0526` (*Color space*) & `PID 0x1111` (*Information display*), locking `PID 0x130A = 0 (sRGB)` and `DISP` Light-on-dark |
| **[04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md](04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md)** | M-Mode 600s Extended Shutter & Post-Exposure Interval Timer | Adds `60"~600"` M-mode speeds, starts interval wait after exposure completion (`0x101FF392`), and dynamically predicts end day/time (`0x1002E000`) |
| **[NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md](NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md)** | In-Camera Night Vision Red Display & VGC Backend Isolation | Derived from Nikon Z8 `d11`, intercepts VGC Channel 1 (`0x20144000` LCD+EVF) CSC and framing grid for pure-red night vision with zero RAW/JPEG/HDMI contamination |

---

## 2. Audit Evidence & Verification Datasets

- **Night Vision Red & Full-Firmware Release Evidence (`Modified24`)**: Native ARM/Thumb verification suite **[evidence/probe_modified24_native_result.json](evidence/probe_modified24_native_result.json)** (26 VGC CSC channel-isolation cases, 12 hardware grid cases, 648 36-language UI string checks, and 437 categorized RAW pipeline cases), single-module updater audit **[evidence/modified24_updater_audit.json](evidence/modified24_updater_audit.json)** (7 file checks, 5 flash-scheduler passes), and full-machine QEMU framebuffer audit **[evidence/qemu_modified24_result.json](evidence/qemu_modified24_result.json)** (`MenuCSC=0x3000`, `GridOn=0x030000d8`, `RedGridDiffPx=5109`).
- **[MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md)**: Root-cause analysis, 437-case Unicorn matrix, and 9-NEF real-camera verification report for the `0x100A34D0 -> 0x1002DB5C` uncompressed hardware bit-packer fix, backed by **[evidence/m23_audit_metrics.json](evidence/m23_audit_metrics.json)**, **[evidence/probe_modified23_native_result.json](evidence/probe_modified23_native_result.json)**, and **[evidence/modified23_updater_audit.json](evidence/modified23_updater_audit.json)**.
- **[MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md](MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md)**: Pixel- and byte-level audit of 18 matched flat/dark/bias NEF frames from the initial release baseline, backed by **[evidence/m22_audit_metrics.json](evidence/m22_audit_metrics.json)** and **[evidence/baseline112.json](evidence/baseline112.json)**.
- **[images/modified22_real_camera_verification.png](images/modified22_real_camera_verification.png)**: Real-camera (`Astro RAW` vs `Standard`) flat-field histogram and FFT comb suppression figure.
- **[SAMPLE_EVIDENCE_CATALOG.json](SAMPLE_EVIDENCE_CATALOG.json)**: Full machine-readable catalog of SHA-256 digests, EXIF/MakerNote fields, and spectral metrics across 130 real-camera NEF samples.

---

## 3. Release Package & Reproducible Build Guide

- **Direct Release Download**: Visit **[GitHub Releases (`v3.80-modified24`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified24)** to download [`Nikon-Z6-C380-Modified24-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified24/Nikon-Z6-C380-Modified24-Astro-Firmware.zip) (contains `01_MODIFIED24/EG162080.BIN`, `02_STOCK_C380_ROLLBACK/EG162080.BIN`, and offline `verify.py`).
- **[TOOLS_EN.md](TOOLS_EN.md)**: Toolchain architecture, dependencies, and reproducible local build instructions (`python tools/build_modified24.py --stock <Z_6_0380.bin> --zip`).

---

## 4. Release Changelog & Priority Roadmap

- **[CHANGELOG_EN.md](CHANGELOG_EN.md)**: **Release Changelog & Iteration History** (documenting official production releases and earlier prototyping milestones).
- **[NEXT_STEPS.md](NEXT_STEPS.md)** *(Chinese)*: **Priority Roadmap** and engineering investigation notes:
  - Prior roadmap items **P1 (Long-Exposure Uncompressed Astro RAW Bit-Packing)** and **P2 (In-Camera Night Vision Red Display)** are resolved, camera-verified, and shipped in the current **`Modified24`** production firmware (see [MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md) and [NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md](NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md));
  - Active open priority: **P3 — Standby Focus Position Retention** (preventing focus-by-wire stepper lenses such as Viltrox AF 16mm F1.8 Z from resetting to mechanical fake infinity `∞` upon waking from camera standby sleep; prior investigation archived in [STANDBY_FOCUS_LOSS_INVESTIGATION.md](STANDBY_FOCUS_LOSS_INVESTIGATION.md)).
- **[PROJECT_GOALS.md](PROJECT_GOALS.md)** & **[SOURCES.md](SOURCES.md)** *(Chinese)*: Master engineering goals, verification criteria, and external literature index.
- Earlier Chinese research logs and pre-flash audit notes are archived under `MODIFIED*.md` and `RAW_*.md` in this directory.

> [!NOTE]
> Local laboratory directories mentioned in historical research logs (`outputs/`, `analysis/`, `references/`, `work/`) are excluded via `.gitignore` and are not distributed in the public Git repository. End users should either download the release zip from GitHub Releases or build locally with `tools/build_modified24.py`.

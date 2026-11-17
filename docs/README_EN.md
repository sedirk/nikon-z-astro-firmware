# Nikon Z6 C3.80 Documentation Index

> 🌐 **Language / 语言**: **[简体中文](README.md)** | **English** · 🏠 [Back to Main README](../README_EN.md)

Documentation in this repository is organized into four sections: **Core Technical Monographs**, **Audit Evidence & Catalogs**, **Release Download & Build Guide**, and **Historical Research Archive**.

---

## 1. Core Technical Monographs

| Document | Topic | Key Coverage |
| :--- | :--- | :--- |
| **[01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md](01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md)** | Frontend ISP Spatial Bypass & Concentric Ring Elimination | Bypasses 13 RAW pipeline hooks, zeroes 54 2D polynomial terms, locks 4-channel Q12 multipliers to `4096` ($1.0\times$), suppressing the `0.2276 cyc/DN` FFT comb |
| **[02_STAR_EATER_AND_DARK_CURRENT_EN.md](02_STAR_EATER_AND_DARK_CURRENT_EN.md)** | Spatial Filtering Bypass & Physical Dark Current Preservation | Bypasses `0x100C2654/7C/90` neighborhood clamps (`max8 + 8k`), preserving true hot pixels and faint single-pixel stars |
| **[03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md](03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md)** | Color Space Menu Takeover & Effective `sRGB` Lock | Uses genuine Color Space property `PID 0x0526` for the UI toggle while locking `PID 0x130A = 0 (sRGB)`, resolving `_Z61` naming and Auto ISO (`PID 0x0508`) conflicts |
| **[04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md](04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md)** | M-Mode 600s Extended Shutter & Post-Exposure Interval Timer | Adds `60"~600"` M-mode speeds, starts interval wait after exposure completion (`0x101FF392`), and dynamically predicts end day/time (`0x1002E000`) |

---

## 2. Audit Evidence & Verification Datasets

- **[MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md](MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md)**: Independent pixel- and byte-level audit of 18 real-camera NEF frames captured on `Modified22`, including the 16-bit LE uncompressed dark layout analysis.
- **[evidence/m22_audit_metrics.json](evidence/m22_audit_metrics.json)** & **[evidence/baseline112.json](evidence/baseline112.json)**: Pinned `Modified22` audit metrics and the frozen 112 hot-pixel coordinate benchmark.
- **[images/modified22_real_camera_verification.png](images/modified22_real_camera_verification.png)**: Real-camera `Modified22` (`Astro RAW` vs `Standard`) flat FFT comb, dark neighborhood clamp, and bias readout noise comparison figure.
- **[SAMPLE_EVIDENCE_CATALOG.json](SAMPLE_EVIDENCE_CATALOG.json)**: Full machine-readable catalog of SHA-256 digests, EXIF/MakerNote fields, and spectral metrics across 121 real-camera NEF samples.

---

## 3. Release Package & Reproducible Build Guide

- **Direct Release Download**: Visit **[GitHub Releases (`v3.80-modified22`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified22)** to download [`Nikon-Z6-C380-Modified22-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified22/Nikon-Z6-C380-Modified22-Astro-Firmware.zip) (contains `01_MODIFIED22/EG162080.BIN`, `02_STOCK_C380_ROLLBACK/EG162080.BIN`, and offline `verify.py`).
- **[TOOLS_EN.md](TOOLS_EN.md)**: Toolchain architecture, dependencies, and reproducible local build instructions (`python tools/build_modified22.py --stock <Z_6_0380.bin> --zip`).

---

## 4. Historical Iteration Archive

Intermediate technical notes and pre-flash audit logs from `Modified1` through `Modified21` are archived in Chinese under `MODIFIED*.md` and `RAW_*.md` in this directory ([see Chinese index](README.md)).

> [!NOTE]
> Local laboratory directories mentioned in historical research logs (`outputs/`, `analysis/`, `references/`, `work/`) are excluded via `.gitignore` and are not distributed in the public Git repository. End users should either download the release zip from GitHub Releases or build locally with `tools/build_modified22.py`.

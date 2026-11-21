# Nikon Z6 C3.80 Astro RAW & Extended Exposure Firmware

> 🌐 **Language / 语言**: **[简体中文](README.md)** | **English**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Base Firmware](https://img.shields.io/badge/Nikon%20Firmware-C3.80-orange.svg)](https://downloadcenter.nikonimglib.com/en/download/fw/557.html)
[![Release Version](https://img.shields.io/badge/Release-v3.80--modified24-brightgreen.svg)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified24)

An open-source reverse-engineering and firmware enhancement suite for the **Nikon Z6 (official firmware C3.80)**. By reconstructing key stages of the in-camera Image Signal Processor (ISP), Video Graphics Controller (VGC), RTOS property evaluators, hardware bit-packer, and menu/timer state machines, this firmware resolves the four major limitations affecting deep-sky astrophotography and night-sky time-lapse imaging on first-generation Nikon Z mirrorless bodies: **hardcoded RAW spatial vignette/gain comb artifacts (Concentric Colored Rings), aggressive dark-frame hot-pixel clamping ("Star Eater" & broken dark-frame subtraction), the 30-second M-mode shutter cap / start-to-start interval timer bottleneck, and the lack of a dark-adaptation pure-red display mode**.

---

## 1. Feature Matrix

| Problem / Capability | Stock Nikon C3.80 Behavior | Enhanced Firmware Behavior (`Modified24`) | Technical Mechanism & Evidence |
| :--- | :--- | :--- | :--- |
| **Concentric Colored Rings**<br>*(RAW Histogram Comb)* | Frontend ISP injects mandatory $4.39\text{ DN}$ periodic digital gain & 2D spatial shading modulation into full-size RAW, creating periodic missing codes ($0.2276\text{ cyc/DN}$ FFT spike) and severe colored rings under deep-sky stretching | **Decisively Suppressed**: Selecting `Astro RAW (sRGB)` yields smooth continuous RAW histograms, reducing comb spectral peaks by **$9.8\sim 13.5\times$** ($0.2276\text{ cyc/DN}$ bin drops from $27,242$ to $2,012$; `[0.22, 0.24]` band peak drops from $278,093$ to $28,451$) | Routes full-size frontend RAW directly past backend replacement buffers, zeroes 54 2D polynomial terms, locks 4-channel Q12 multipliers to unity $1.0\times$ (`4096`), and configures lossless hardware bit-packing (see [Tech Doc 01](docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md)) |
| **Star-Eater & Dark Clamping**<br>*(Hot Pixel Suppression)* | Backend ISP applies aggressive $3\times 3$ same-color neighborhood clamping (`max8 + 8k`), erasing faint single-pixel pinpoint stars and invalidating Master Dark calibration | **True Physical Preservation**: Completely bypasses neighborhood hot-pixel suppression; faint stellar photons and true dark-current hot pixels are recorded linearly for clean dark subtraction | Frozen 112 hot-pixel benchmark records `0/112` clamp hits across both lossless and uncompressed long-exposure darks (`5s` & `60s`), unclipped bias readout noise $\approx 4.11\text{ DN}$ ($3.54\text{ DN}$ central 68%), and zero `0 ADU` clipped pixels (see [Tech Doc 02](docs/02_STAR_EATER_AND_DARK_CURRENT_EN.md)) |
| **Seamless Menu Toggle & sRGB Lock**<br>*(UI-Switchable Astro Mode)* | Cannot disable internal RAW spatial scaling | **Borrowed Color Space Menu Switch**: Toggle freely under `Photo Shooting Menu -> Astro RAW mode` (repurposes stock *Color space*), decoupled from `NEF (RAW) recording` (12/14-bit and Lossless/Uncompressed/Lossy at all shutter speeds), with `i`-menu, `My Menu`, and `U1/U2/U3` support | Repurposes Color Space menu property `PID 0x0526` (`RAM 0xC24CDEA0`) while locking effective color space `PID 0x130A = 0` (`sRGB`) at `0x1014BB28` — filenames always remain `Z61_xxxx.NEF` (see [Tech Doc 03](docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md)) |
| **Resident `30"~600"` Shutter Speeds**<br>*(Extended M-Mode Exposures)* | M-mode timed exposures stop at `30"`, requiring external intervalometers or manual Bulb/Time actuation for longer subs | **8 Built-in Long Shutter Steps**: Directly dial **`60", 90", 120", 180", 240", 300", 480", 600"`** in M mode without an external release cable | Extends 1/3-EV shutter lookup tables, UI labels, and exposure timer dividers (see [Tech Doc 04](docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md)) |
| **Post-Exposure Pure Wait Intervalometer**<br>*(Interval Timer Shooting)* | Stock interval is measured *start-to-start*, shrinking sensor cooldown gaps or dropping frames whenever exposure + LENR exceeds interval | **Countdown Starts After Exposure**: Configured interval acts as pure post-exposure wait/cooldown gap, with dynamic **End day/time** calculation accounting for exposure + LENR + delay | Hooks exposure-completion callback `0x101FF392` and injects dynamic end-time predictor `0x1049C26C -> 0x1002E000` (see [Tech Doc 04](docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md)) |
| **Zeroed Gain Boost & Astro-Mod Restoration**<br>*(Unity Q12 Channel Gain)* | Applies hidden non-unity Q12 digital pre-scaling before NEF encoding ($k_R \approx 1.295\times$, $k_B \approx 1.263\times$), causing severe red casts in RAW viewers and premature red-channel clipping on UV/IR-cut modified ($\text{H}\alpha$) bodies | **Gain Pre-Scaling Zeroed ($1.0\times$ Unity)**: Eliminates artificial in-camera channel multipliers, restoring linear sensor photo-electron response and full red-channel headroom on astro-modified bodies without abnormal reddening | Locks all 4 Bayer channel Q12 multipliers at `0x10122CBC` to exact `4096` ($1.0000\times$); center flat `R/G1` median drops from pre-scaled `1.0103` to native QE ratio `0.8997` (see [Tech Doc 01](docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md)) |
| **In-Camera Night Vision Red Display**<br>*(Dark-Adaptation Red UI & LiveView)* | First-gen Z6 lacks a warm/red display mode; bright blue/green/white light from the rear LCD and OLED EVF ruins human scotopic dark adaptation | **Pure-Red Rear LCD + OLED EVF Toggle**: Switch under `Setup Menu -> Astro red display` (repurposes stock *Information display*, `G = 0, B = 0`), bindable to the top of `My Menu` for one-button blind toggling; recorded NEF RAW, JPEGs, metering/histograms, and external HDMI output remain **100% uncontaminated full color** | Repurposes `PID 0x1111` (`RAM 0xC24DD0EC`), intercepting only VGC Channel 1 (`0x20144000`) hardware CSC (`0x00003000`) and framing grid (`0x20145618`), while permanently locking the `DISP` info screen to `Light on dark` (see [Tech Doc 05](docs/NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md)) |

---

## 2. Real-Camera Verification

Matched flat, bias, and long-exposure dark frames captured on physical Nikon Z6 hardware confirm end-to-end signal integrity:

![Real-Camera Histogram & Comb Suppression Verification](docs/images/modified22_real_camera_verification.png)

- **Left Column (`Standard (sRGB)`)**: Around the ~3300 DN flat-field peak, the RAW histogram exhibits periodic missing-code spikes, producing an intense $278,093$ FFT comb peak in the $0.2276\text{ cyc/DN}$ band;
- **Right Column (`Astro RAW (sRGB)`)**: The histogram follows a smooth physical Poisson-Gaussian envelope with comb amplitude suppressed by **$9.8\sim 13.5\times$** ($0.2276$ bin reduced from $27,242$ to $2,012$; band peak reduced to $28,451$), while preserving standard `Z61_xxxx.NEF` naming and native `sRGB` EXIF/preview metadata;
- **Long-Exposure Lossless & Uncompressed Parity**: Across `5s` and extended M-mode `60s` 14-bit dark frames, both `Lossless compressed` and `Uncompressed` (`42,920,960` B `packed-14`) match `LibRaw 0.22.2` with zero pixel diffs, identical readout noise (`5s` central 68% $\approx 4.24\text{ DN}$), and `0/112` hot-pixel clamp hits.

---

## 3. Download, Flash & Reproducible Local Build

We provide both **ready-to-flash pre-packaged release archives** on GitHub Releases and a **zero-dependency reproducible Python builder** (the Git source tree tracks only clean-room source code, JSON recipes, and audit evidence).

### 3.1 Option A (Recommended): Direct Download from GitHub Releases
1. Download the pre-packaged flash kit from **[GitHub Releases (`v3.80-modified24`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified24)**:
   - 📦 **[`Nikon-Z6-C380-Modified24-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified24/Nikon-Z6-C380-Modified24-Astro-Firmware.zip)** (`29,325,238` bytes, SHA-256: `089d694c3fe5a2eb467467ad7d44cdd8ecd9ab7fc6d76d892f09f126fd3e46dd`)
   - 🔑 **[`SHA256SUMS.txt`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified24/SHA256SUMS.txt)** (standalone SHA-256 checksum manifest)
2. Extract the archive. Inside `Nikon-Z6-C380-Modified24-Astro-Firmware/` you will find:
   - `01_MODIFIED24/EG162080.BIN`: **`Modified24` Astro Firmware** main module (`33,502,842` B, SHA-256: `168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653`, CRC-16/XMODEM: `0x8799`);
   - `02_STOCK_C380_ROLLBACK/EG162080.BIN`: **Official Stock C3.80 rollback** module (`33,502,842` B, SHA-256: `1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c`);
   - `verify.py` & `FLASH_INSTRUCTIONS.txt`: Run `python verify.py` inside the extracted folder before flashing to verify SHA-256, CRC-16, and all 112 patch spans offline.

### 3.2 Option B: Reproducible Local Build from Official Firmware (Optional)
1. Download official Nikon Z6 firmware C3.80 from the [Nikon Download Center](https://downloadcenter.nikonimglib.com/en/download/fw/557.html) and extract `Z_6_0380.bin` (SHA-256: `ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54`);
2. Run the standalone builder (requires **Python 3.10+ standard library only**; reproduces the byte-identical folder and `.zip` archive in ~1 second):
   ```bash
   python tools/build_modified24.py --stock /path/to/Z_6_0380.bin --output-dir outputs/Nikon-Z6-C380-Modified24-Astro-Firmware --zip
   ```

### 3.3 Camera Flashing & Rollback Steps
1. Format an XQD / CFexpress memory card inside the camera;
2. Copy `01_MODIFIED24/EG162080.BIN` to the **root directory** of the memory card (ensure only **one** `.BIN` file is present at the card root);
3. Insert a **fully charged genuine Nikon battery**, power on, navigate to **`Setup Menu -> Firmware version`**, select **`Update`**, and follow on-screen prompts;
4. **Never** power off the camera or remove the battery/card during the update. Restart the camera when prompted.

> [!TIP]
> Whenever the camera boots normally into the menu system, you can place `02_STOCK_C380_ROLLBACK/EG162080.BIN` at the memory card root and run `Firmware version -> Update` to revert cleanly to 100% Stock C3.80.

### 3.4 Repurposed Stock Menu Reference & In-Camera Operation (All 36 Camera Languages)

To integrate natively with Nikon's UI state machine, `i`-menu, `My Menu`, and `U1/U2/U3` user-setting banks without invasive menu-tree reallocation, the two independent toggles repurpose two low-frequency stock menu slots:

| Enhanced Feature Toggle | Repurposed Stock Menu Slot & Property ID | Original Stock Options | Repurposed Options & Runtime Behavior |
| :--- | :--- | :--- | :--- |
| **Astro RAW mode**<br>*(天文直通RAW模式)* | **Photo Shooting Menu -> Color space**<br>(`PID 0x0526` @ `RAM 0xC24CDEA0`) | `0 = sRGB`<br>`1 = Adobe RGB` | **`0 = Standard (sRGB)`**: 100% stock C3.80 ISP pipeline<br>**`1 = Astro RAW (sRGB)`**: Enables Astro RAW bypass & $1.0\times$ unity Q12 channel gain<br>*Effective color space `PID 0x130A` is permanently locked to `0 (sRGB)`; filenames always stay `Z61_xxxx.NEF`* |
| **Astro red display**<br>*(天文红光显示)* | **Setup Menu (Wrench) -> Information display**<br>(`PID 0x1111` @ `RAM 0xC24DD0EC`, `rom_default = 0`) | `0 = Dark on light`<br>`1 = Light on dark` | **`0 = Off (Standard)`**: Rear LCD & OLED EVF render normal full color<br>**`1 = On (Astro Red)`**: Rear LCD & OLED EVF (including hardware framing grid) switch to pure-red night vision (`G = 0, B = 0`)<br>*The `DISP` shooting-info screen is permanently locked to eye-friendly **`Light on dark`**; recorded NEF/JPEG & external HDMI are unaffected* |

> [!IMPORTANT]
> **First-Boot Red Display Note (NVRAM Setting Inheritance)**: Nikon firmware updates preserve personal settings stored in camera NVRAM. If you previously set **`Setup Menu -> Information display`** to **`Light on dark` (`1`)** under stock firmware, the camera will inherit `PID 0x1111 == 1` and boot directly into **Astro Red** mode after flashing. Simply open **`Setup Menu -> Astro red display`** once and switch it back to **`Off (Standard)` (`0`)** to persist normal full-color display (*Reset all settings* defaults to `0 = Off` via `rom_default = 0`).

Menu navigation and display pipelines were also validated in a QEMU system-emulation harness (screenshots below show an earlier prototype UI for interaction reference):

| LiveView & Info Strip | Menu System & Mode Selection |
| :---: | :---: |
| ![QEMU LiveView Prototype Screenshot](docs/images/qemu_simulator_liveview.png) | ![QEMU Menu Prototype Screenshot](docs/images/qemu_simulator_menu.png) |

1. **Enable Astro RAW**: Open **`Photo Shooting Menu -> Astro RAW mode`** (repurposes *Color space*) and select **`Astro RAW (sRGB)`**, or toggle it via the `i` menu / `U1/U2/U3` banks;
2. **One-Button Blind Red Display Toggle**: Open **`Setup Menu -> Astro red display`** (repurposes *Information display*) to toggle night-vision red mode; register it as the top item in **`My Menu`** and assign `Fn1/Fn2` to *Access top item in My Menu* for instant blind toggling in the dark;
3. **Extended M-Mode Shutter & Pure-Wait Intervalometer**: Turn the mode dial to **M** and rotate the main command dial past `30"` to select **`60"`, `90"`, `120"`, `180"`, `240"`, `300"`, `480"`, `600"`**; in Interval Timer Shooting, each interval countdown begins strictly after the preceding exposure completes.

---

## 4. Technical Documentation & Quantitative Evidence

Architecture monographs, disassembly notes, real-camera pixel audits, and release history are organized below:

1. **[Tech Monograph 01 — Astro RAW Pipeline Reconstruction & Concentric Ring Elimination](docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md)**  
   *Disassembly of 14 dynamic ISP & hardware bit-packer hooks, 54-term 2D shading polynomial sanitization, and Q12 unity-gain locking.*
2. **[Tech Monograph 02 — Bypassing Star-Eater & Preserving Physical Dark Current](docs/02_STAR_EATER_AND_DARK_CURRENT_EN.md)**  
   *Analysis of the `0x100C2654` $3\times 3$ same-color neighborhood clamp bypass and frozen 112 hot-pixel benchmarks.*
3. **[Tech Monograph 03 — Seamless UI Switch & Dual-Layer Color Space Architecture](docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md)**  
   *Orthogonal repurposed-menu architecture (`PID 0x0526` & `PID 0x1111`) paired with effective `PID 0x130A = 0 (sRGB)` locking.*
4. **[Tech Monograph 04 — M-Mode 600s Extended Shutter & Post-Exposure Interval Timer](docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md)**  
   *Shutter table extension, exposure-complete callback hooking (`0x101FF392`), and dynamic end-time prediction (`0x1002E000`).*
5. **[Tech Monograph 05 — In-Camera Night Vision Red Display & VGC Backend Isolation](docs/NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md)**  
   *Nikon Z8 `d11` warm-display reverse engineering, Z6 VGC Channel 1 (`0x20144000`) CSC & framing-grid red transformation, HDMI clean-feed isolation, and QEMU/camera verification.*
6. **[Real-Camera Verification — Uncompressed Astro RAW Hardware Bit-Packer Fix & 9-NEF Audit](docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md)**  
   *Root-cause analysis of `0x100A34D0 -> 0x1002DB5C`, 437-case Unicorn matrix, and physical `5s`/`60s` NEF pixel verification.*
7. **[Tools & Reproducible Build Guide](docs/TOOLS_EN.md)** / **[Documentation Index](docs/README_EN.md)**  
   *Guide to `build_modified24.py`, clean-room container XOR mask recovery, and automated repository hygiene checks.*
8. **[Machine-Readable Sample Evidence Catalog](docs/SAMPLE_EVIDENCE_CATALOG.json)**  
   *SHA-256 digests, EXIF/MakerNote metadata, spectral/noise measurements across all 130 real-camera NEF test frames, and `docs/evidence/` native probe records.*
9. **[Release Changelog & Iteration History](docs/CHANGELOG_EN.md)**  
   *Standalone version history covering official releases and earlier research milestones.*

---

## 5. Acknowledgements & Credits

This project builds upon foundational research and tooling from the open-source camera reverse-engineering and astrophotography communities:

- **[Wonder-Lantern / z6-qemu / z7-qemu](https://github.com/WonderLantern)**: Created by **vic2349** and the WonderLantern contributors, enabling safe offline execution and peripheral emulation before physical camera testing.
- **[RealCaCl2 / z30-firmware-extensions](https://github.com/RealCaCl2/z30-firmware-extensions)**: Clean-room spanning-tree XOR mask recovery methodology, CRC conventions, and Nikon Z firmware container insights.
- **[Mark Shelley](https://www.markshelley.co.uk/Astronomy/concentric_ring_diagnosis.html)**: Pioneering diagnosis of Nikon's concentric colored rings and FFT histogram comb quantification methodology.
- **[Simeon Pilgrim / Nikon-Patch](https://simeonpilgrim.com/nikon-patch/nikon-patch.html)**: Early DSLR firmware patching and dark-current preservation research that inspired the community.

---

## 6. License

Original code, patch recipes, and documentation in this repository are licensed under the **[GNU General Public License v3.0 or later (`GPL-3.0-or-later`)](LICENSE)**. See **[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)** for third-party attributions and proprietary firmware notices.

```text
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

*Disclaimer: Flashing modified camera firmware carries inherent hardware risks. Read all flashing and recording instructions carefully before proceeding; you assume sole responsibility for any operational errors or hardware damage.*

# Release Changelog & Iteration History

> 🌐 **Language / 语言**: **[简体中文](CHANGELOG.md)** | **English** · 🏠 [Back to Main README](../README_EN.md) · 📚 [Docs Index](README_EN.md)

This document records the release changelog and reverse-engineering iteration history of the **Nikon Z6 C3.80 Astro Firmware** project. User guides and architecture monographs describe only the latest production release; historical version transitions are consolidated here.

---

## Official Releases

### [`v3.80-modified24`](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified24) — 2026-11-21 (Latest Production Release)

- **Release Artifacts & Checksums**:
  - Pre-packaged flash kit: `Nikon-Z6-C380-Modified24-Astro-Firmware.zip` (`29,325,238` B, SHA-256: `089d694c3fe5a2eb467467ad7d44cdd8ecd9ab7fc6d76d892f09f126fd3e46dd`)
  - Main firmware module `01_MODIFIED24/EG162080.BIN`: `33,502,842` B, SHA-256: `168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653`, CRC-16/XMODEM: `0x8799` (`112` patch spans: `18` Astro/UI + `7` night-vision red display + `3` post-exposure interval timer + `84` M-mode `60"~600"` extended shutter)
- **What Changed & Repurposed Menu Summary**:
  - **In-Camera Night Vision Red Display & VGC Channel 1 Hardware Isolation (`Free Hole B 0x1002E1B0` + 6 display/UI hooks)**: Reverse-engineered Nikon Z8's `d11: Warm display colors` mechanism and deployed `Mode 2A LumaRed` (Q14 matrix word 0 `0x00003000`, `G = 0, B = 0`), stateless single-frame live sync (`0x102435AE`), and hardware framing-grid pure-red masking (`0x10244154` -> `0x20145618 = 0x030000d8`) strictly on Z6 VGC Channel 1 (`0x20144000`, rear LCD + OLED EVF), leaving Channel 0 (`0x20140000` external HDMI clean feed) as well as recorded NEF RAW, JPEGs, metering, and histograms 100% uncontaminated;
  - **Orthogonal Dual Repurposed Stock Menu Architecture (All 36 Camera Languages)**:
    1. **Astro RAW mode toggle** repurposes **`Photo Shooting Menu -> Color space`** (`PID 0x0526` @ `RAM 0xC24CDEA0`: stock `0 = sRGB` / `1 = Adobe RGB` -> `0 = Standard (sRGB)` / `1 = Astro RAW (sRGB)`, while effective color space `PID 0x130A` remains locked to `0 (sRGB)`);
    2. **Astro red display toggle** repurposes **`Setup Menu -> Information display`** (`PID 0x1111` @ `RAM 0xC24DD0EC`, `rom_default = 0`: stock `0 = Dark on light` / `1 = Light on dark` -> `0 = Off (Standard)` / `1 = On (Astro Red)`), permanently locks the `DISP` shooting-info screen to eye-friendly `Light on dark` (`0x1040E7D8` / `0x1043A1E0`), and chains 36-language UTF-16LE label overrides at `GetLanguageString` epilogue `0x104C013C` alongside `0x104C0134` (because Nikon firmware updates preserve NVRAM user settings, bodies previously set to `Light on dark` (`1`) under stock firmware boot into `On (Astro Red)` once until switched back to `0 = Off (Standard)`).
- **Verification & Pinned Evidence**:
  - Verified via Unicorn native emulation (`26` VGC CSC matrix & Ch0 HDMI isolation cases, `12` hardware grid color cases, stateless single-frame transition tests, `648` 36-language dual-menu & neighbor string checks, plus full `Modified23` regression gates), `z6-qemu` full-system GUI menu & LiveView scanout verification (`0x201454F0 = 0x3000`, grid register `0x030000d8`, `5,109` pure-red zero-G/B changed pixels, Ch0 HDMI constant `0x0`), 7 single-module updater file checks + 5 offline flash-scheduler passes (`Modified23 <-> Modified24` and `Stock C3.80 <-> Modified24`), and on-camera flashing & LiveView/menu/playback testing on physical Nikon Z6 hardware (see [NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md](NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md), [evidence/probe_modified24_native_result.json](evidence/probe_modified24_native_result.json), [evidence/qemu_modified24_result.json](evidence/qemu_modified24_result.json), and [evidence/modified24_updater_audit.json](evidence/modified24_updater_audit.json)).

---

### [`v3.80-modified23`](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified23) — 2026-11-19

- **Release Artifacts & Checksums**:
  - Pre-packaged flash kit: `Nikon-Z6-C380-Modified23-Astro-Firmware.zip` (`29,320,565` B, SHA-256: `1aae77b798f2768ef873d256108758d0a097537632d8fb531c04ca26c29d818e`)
  - Main firmware module `01_MODIFIED23/EG162080.BIN`: `33,502,842` B, SHA-256: `47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029`, CRC-16/XMODEM: `0xc083` (`105` patch spans: `18` Astro/UI + `3` post-exposure interval timer + `84` M-mode `60"~600"` extended shutter)
- **What Changed**:
  - **Long-Exposure Uncompressed Astro RAW Hardware Bit-Packer Fix (`0x100A34D0 -> 0x1002DB5C`)**: Resolved the backend `0x100A3480` -> `0x100A34D0` uncompressed packer branch where long-exposure (`>= 1s`) frontend `format = 3` (`16-bit LE` unpacked) captures previously programmed output pack code `0`, writing `48,997,120` B and overlapping embedded preview JPEGs across rows `3633..4000`. Added the 14th `fn_is_astro_r0`-gated trampoline `tramp_a34d0` to configure EXPEED 6 hardware bit-packing to `14-bit` packed (FX `42,920,960` B, stride `10,624` B) or `12-bit` packed (FX `36,780,160` B, stride `9,104` B) with `lut_ptr = 0` lossless linear packing across all shutter speeds.
- **Verification & Pinned Evidence**:
  - Passed 437-case categorized Unicorn pipeline emulation (`113` uncompressed + `216` compressed queue descriptor + `108` `JPEG-only` skip, `216` non-Astro stock parity cases), 28-case `0x100A34D0` register/APSR conservation suite, and 7 single-module updater file checks + 5 offline flash-scheduler passes;
  - Verified on physical Nikon Z6 hardware across `9` real-camera dark NEFs (`Z61_5128.NEF` – `Z61_5136.NEF`: `5s` 14-bit lossless × 3, `5s` 14-bit uncompressed × 3, and M-mode extended `60s` 14-bit uncompressed × 3), confirming `146,991,360` hardware-packed pixels with `0` pixel diffs against `LibRaw 0.22.2`, `0` preview collisions, Pearson `r = 0.999550` hot-pixel correlation in rows `3633..4000`, and `0 / 112` spatial clamp hits (see [MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md) and [evidence/m23_audit_metrics.json](evidence/m23_audit_metrics.json)).

---

### [`v3.80-modified22`](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified22) — 2026-11-17 (Initial Open-Source Release)

- **Release Artifacts & Checksums**:
  - Pre-packaged flash kit: `Nikon-Z6-C380-Modified22-Astro-Firmware.zip` (`29,318,898` B, SHA-256: `066ae056b5a84207ca7d99f31fedfc17f09c70283fbb466688137e5eed342e24`)
  - Main firmware module `01_MODIFIED22/EG162080.BIN`: `33,502,842` B, SHA-256: `c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771`, CRC-16/XMODEM: `0x48f3` (`104` patch spans)
- **Key Capabilities Delivered**:
  - **Dual-Layer Color Space UI Toggle (`PID 0x0526` + `PID 0x130A = 0`)**: Bound the menu switch to genuine Photo Shooting Menu Color Space property `PID 0x0526` (`RAM 0xC24CDEA0`) while NOP-locking effective color space `PID 0x130A = 0 (sRGB)` at `0x1014BB28`, keeping `Z61_xxxx.NEF` / `DSC_xxxx.NEF` naming, native `sRGB` EXIF/JPEGs, 36-language UI labels, `i`-menu access, and `U1/U2/U3` bank persistence;
  - **Concentric Ring Elimination & Zeroed Channel Gain Boost**: 13 ISP hooks bypass backend replacement buffers, sanitize 54 frontend 2D shading polynomial coefficients in place, and lock 4-channel Q12 digital multipliers at `0x1011E2DC` / `0x10122CBC` to exact `4096` ($1.0000\times$ unity gain), suppressing the `0.2276 cyc/DN` FFT comb by $9.8\sim 13.5\times$ and restoring native sensor QE ratio (`R/G1 = 0.8997`);
  - **Star-Eater Bypass & Physical Dark Current Preservation**: Bypasses `0x100C2654 / 0x100C267C / 0x100C2690` $3\times 3$ same-color neighborhood clamping;
  - **Resident M-Mode `60"~600"` Shutter Speeds & Post-Exposure Intervalometer**: Adds 8 timed M-mode speeds (`60"` – `600"`), starts interval countdowns upon exposure completion (`0x101FF392`), and dynamically predicts end day/time (`0x1002E000`);
  - **GPL-3.0 Clean-Room Open-Source Release**: Dynamic runtime recovery of three 256-byte XOR container mask tables (`z6_c380_container.py`) and automated repository hygiene gate (`verify_repo_hygiene.py`) (see [MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md](MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md)).

---

## Earlier Research & Prototyping Milestones (`Modified1` – `Modified21`, 2026-11-08 – 2026-11-16)

Summary of experimental milestones prior to the public open-source releases (detailed Chinese lab logs are archived under `docs/MODIFIED*.md` and `docs/RAW_*.md`):

| Milestone | Date | Reverse-Engineering Breakthrough & Hardware Outcome | Archived Report |
| :--- | :---: | :--- | :--- |
| **`Modified1`** | 2026-11-09 | Bypassed backend `0x100C2654 / 0x100C267C / 0x100C2690` dark neighborhood clamp sites; verified `0/112` `max8 + 8k` clamp hits across 7 real-camera NEFs | [MODIFIED1_REAL_NEF_2026-11-09.md](MODIFIED1_REAL_NEF_2026-11-09.md) |
| **`Modified2` – `Modified4`** | 2026-11-09 | Isolated backend 257-entry vignette curve, dual 17-entry spatial tables (`0x100C28B2/C8/964`), and frontend scalar control bits; neutralized `NEFInfo 0x0006/0x0007` and narrowed remaining rings to frontend ISP stages | [MODIFIED3_REAL_NEF_2026-11-09.md](MODIFIED3_REAL_NEF_2026-11-09.md), [MODIFIED4_REAL_NEF_2026-11-09.md](MODIFIED4_REAL_NEF_2026-11-09.md) |
| **`Modified5` – `Modified8`** | 2026-11-09 – 11-12 | Mapped `ID35` completion IRQ synchronization, `CAL33` `+0x18`/`+0x1A` controls, and the 54-term frontend 2D shading polynomial (`MMIO 0x20068718..0x200687D4`) plus the 50 ms `Event 8` shutter timing budget | [MODIFIED7_REAL_NEF_2026-11-12.md](MODIFIED7_REAL_NEF_2026-11-12.md) |
| **`Modified9` – `Modified10`** | 2026-11-13 | Built in-place 2D polynomial sanitizer `0x1017D834 -> 0x1002D884` (zero `Event 8` timeouts) and full-size frontend direct RAW route `0x100AE3A4` bypassing backend buffer `0x20380000` | [MODIFIED10_PREFLASH_REVIEW_2026-11-13.md](MODIFIED10_PREFLASH_REVIEW_2026-11-13.md) |
| **`Modified12` – `Modified13`** | 2026-11-14 | Locked 4-channel Q12 digital multipliers at `0x1011E2DC` and `0x10122CBC` to unity `4096` ($1.0\times$) while preserving `cbz r1` null-pointer guards, eliminating the `0.2276 cyc/DN` histogram comb and converging the 13 core ISP hooks | [MODIFIED12_REAL_NEF_2026-11-14.md](MODIFIED12_REAL_NEF_2026-11-14.md) |
| **`Modified15` – `Modified16`** | 2026-11-15 | Completed resident M-mode `60"~600"` 8-step shutter table extension v2 and 36-language UTF-16LE menu string override table | [MODIFIED15_600S_FIX_PREFLASH_2026-11-15.md](MODIFIED15_600S_FIX_PREFLASH_2026-11-15.md), [MODIFIED16_ASTRO_UI_600S_PREFLASH_2026-11-15.md](MODIFIED16_ASTRO_UI_600S_PREFLASH_2026-11-15.md) |
| **`Modified17`** | 2026-11-15 | Explored third-party stepper lens standby focus retention; experimental hooks were stripped from production builds pending full mount-handshake re-architecture (tracked as P3) | [STANDBY_FOCUS_LOSS_INVESTIGATION.md](STANDBY_FOCUS_LOSS_INVESTIGATION.md) |
| **`Modified19` – `Modified21`** | 2026-11-16 | Implemented `0x101FF392` post-exposure interval timer and `0x1049C26C -> 0x1002E000` dynamic end-time predictor; diagnosed `PID 0x0440` / `PID 0x0508` ROM property table slots leading to `PID 0x0526` | [MODIFIED20_ASTRO_RAW_UI_AND_ENDTIME_2026-11-16.md](MODIFIED20_ASTRO_RAW_UI_AND_ENDTIME_2026-11-16.md), [MODIFIED22_COLOR_SPACE_PID0526_ROOT_CAUSE_FIX_2026-11-17.md](MODIFIED22_COLOR_SPACE_PID0526_ROOT_CAUSE_FIX_2026-11-17.md) |

# Nikon Z6 C3.80 Modified21 — Astro RAW Switch Fix, True sRGB Lock & UI Update (2026-11-16)

## 1. Background & Root-Cause Diagnosis (`11.16_modified20` Real-Camera Samples)
- **Sample Verification (`samples/11.16_modified20/`)**:
  - Group 1 (selected `天文直通RAW`): `_Z615073.NEF`, `_Z615077.NEF`, `_Z615079.NEF`
  - Group 2 (selected `标准 (sRGB)`): `Z61_5080.NEF`, `Z61_5081.NEF`, `Z61_5082.NEF`
  - **Audit Findings**:
    1. All 6 NEFs shared identical factory ISP pixel signatures: the 4.39-DN R-channel gain/spatial comb at `0.2276 cyc/DN` remained at `6066..7250` (vs `401..546` in genuine `Modified13` Astro RAW samples `Z61_4994..5006.NEF`), and radial shading residuals cross-correlated at `0.984` across groups.
    2. Only Nikon MakerNote `ColorSpace (0x001E)` (`2` vs `1`) and DCF filename prefix (`_Z61` vs `Z61_`) changed between the two groups.
- **Exact Firmware Root Causes**:
  1. **Misidentified PID `0x0508` RAM Slot (`0xC24CDDC4` -> `0xC24CDE28`)**:
     - Native `GetProperty` (`0x100700A0`, via ROM tables `0x10070474` / `0x10070478`) maps PID `0x0508` (Photo Shooting Menu -> Color space, `idx=161, type=7, sz=4`) to **`0xC24CDE28`**, whereas `0xC24CDDC4` (`idx=136`) belongs to PID `0x0440` (Focus Shift shot count, default `100 != 1`).
     - Consequently, `fn_is_astro_r0` in `Modified18..Modified20` always evaluated `0` (Stock ISP) unless Focus Shift shot count happened to equal `1`.
  2. **Incomplete sRGB Lock (`0x1040AD00` vs `0x1014F638` / `0x1381`)**:
     - `0x1040AD00` is UI gray-out condition `0x18` in `0x1090D180`, whereas ISP JPEG encoding (`0x1013EDA6`, `0x10144ED2`, `0x1016CD30`, `0x1016D042`), MakerNote `0x001E`, and DCF `_Z61` / `Z61_` naming (`0x1042871C`, `0x104737D6`) read **Effective Color Space PID `0x1381` (`0xC24CC948`)**, evaluated from `0x0508` in Photo mode by `0x1014F638`.
     - Meanwhile, the external LiveView / Info screen Color Space icon (`0x1049B07E`, `0x1049B294`) reads PID `0x0508` (`0xC24CDE28`) directly (`0 -> 0xD1 sRGB`, `1 -> 0xD2 AdobeRGB`).

---

## 2. Modified21 Engineering Changes (`z6_astro_ui_color_space_v2.py`)
1. **Corrected `fn_is_astro_r0` Predicate (`0x1002D900`)**:
   - Reads `uint32([0xC24CDE28]) == 1` (`PID 0x0508 == 1`) AND `uint32([0xC24CC798]) <= 1` (`PID 0x131B <= 1`, RAW or RAW+JPEG), driving all 13 Modified13 Astro RAW dual-path trampolines.
   - All `RAM_PROP_*` constants are now automatically cross-checked against the Stock ROM property descriptor tables (`0x10070474` / `0x10070478`) during build (`prepare_modified21_lab.py`) and via native `0x100700A0` execution in Unicorn (`probe_modified21_native.py`).
2. **Genuine Photo-Mode Effective Color Space sRGB Lock (`0x1014F678`)**:
   - Replaces `0x1014F678: bne #0x1014f67c` (`00d1`) with `nop` (`00bf`) inside `0x1014F638`, executing Stock's own `str r7(=0), [sp, #4]` path so `PID 0x1381` (`0xC24CC948`) is always `0 (sRGB)` in Photo mode, while `PID 0x0508` (`0xC24CDE28`) remains `0` or `1`:
     - External LiveView / Info screen retains the `AdobeRGB` icon as a visual indicator when `直通RAW (sRGB)` is active;
     - Embedded NEF preview JPEGs, companion `RAW+JPEG` `.JPG` files, MakerNote `ColorSpace`, and DCF filenames (`Z61_xxxx.NEF` / `DSC_xxxx.NEF`) are designed to remain `sRGB` via `PID 0x1381 = 0` (verified in offline `0x1014F638` emulation; pending on-camera capture confirmation);
     - PTP/USB sync (`0x1012D464`), NVRAM persistence, `i` Quick Menu, and `U1/U2/U3` banks preserve `0x0508 = 0/1` in the property model.
3. **Updated 36-Language UI Labels (`0x104C0134` -> `UI_OVERRIDES_M21`)**:
   - `0x03B3` (Title): `天文直通RAW模式` (ZH_CN) / `天文直通 RAW 模式` (ZH_TW) / `Astro RAW mode` (EN & others)
   - `0x03B4` (Option 0): **`标准 (sRGB)`** (ZH_CN) / **`標準 (sRGB)`** (ZH_TW) / **`Standard (sRGB)`** (EN & others)
   - `0x03B5` (Option 1): **`直通RAW (sRGB)`** (ZH_CN) / **`直通RAW (sRGB)`** (ZH_TW) / **`Astro RAW (sRGB)`** (EN & others)
   - `0x082B` / `0x082C` (Colon labels): **`标准 (sRGB)：` / `直通RAW (sRGB)：`** (ZH_CN), **`標準 (sRGB)：` / `直通RAW (sRGB)：`** (ZH_TW), **`Standard (sRGB):` / `Astro RAW (sRGB):`** (EN & others)

---

## 3. Verification Summary
- **Candidate Binary (`modified21-astro-raw-fix-srgb-ui-interval-endtime-600s-v1`)**:
  - `SHA-256`: `e632a9113b4a32944d6f9582dd9e44ad43eeeef1846778143e46626023908609`
  - `CRC16-HQX`: `0xb3b1` (`crc_hqx(full_file, 0) == 0`)
  - Total spans: `105` (`18` Astro/UI/sRGB + `3` Interval Timer + `84` `m600_v2`), `0` overlaps, `0` interior branch collisions, `548` bytes free before `0x1002E000`, `3,420` bytes free before `0x1002EF04`, 100% reversible to Stock `C3.80`, and 100% bit-reproducible preservation of `Modified19` & `Modified20`.
- **Unicorn Native Emulation (`probe_modified21_native.py`)**:
  - Native `0x100700A0` RAM discovery + `0x1033F75E` menu mapping + `25/25` predicate cases + `Modified20` regression reproduction & fix: **PASS**;
  - `0x1040AD00` + `0x1014F638` Photo-mode `0x1381 = 0` sRGB lock (`13/13` cases across `P/A/S/M/AUTO`): **PASS**;
  - All `13` patched Astro RAW firmware call-sites (`28/28` dual-branch paths + NZCV/register preservation): **PASS**;
  - `36`-language × `10` string IDs (`360/360` checks) + `0` missing glyphs across all 36 pools: **PASS**;
  - Post-exposure Interval Timer (`3` stock + `8` patched sequences) + `37/37` native `End day/time` cases: **PASS**.
- **Offline Updater & 5-Slot Kit Verification (`probe_modified21_updater.py`, `verify_modified21_kit.py`)**:
  - `6` offline updater prechecks (including `modified20 <-> modified21` and `stock <-> modified21`) + `4` offline RAM flash-scheduler passes (`physical_flash=False`; physical NOR/NAND erase/write and power-loss fault injection are not emulated) + standalone `5`-slot kit SHA-256/CRC16 verification (`python verify.py`): **ALL PASS**.

## 4. Verification Boundaries & On-Camera Acceptance Checklist
- **Boundaries**: All checks above are offline binary/Unicorn emulations (`physical_flash=False`). Flash only with a fully charged battery and formatted card containing a single target `EG162080.BIN`; rollback slots (`02..05`) apply when the camera boots normally into `Setup Menu -> Firmware version`.
- **On-Camera Checklist**: (1) Verify `标准 (sRGB)` / `直通RAW (sRGB)` menu labels and external `Adobe` indicator icon; (2) shoot paired RAW+JPEG frames in both slots to confirm `Z61_`/`DSC_` naming, `sRGB` MakerNote/JPEG tags, and elimination of the `0.2276 cyc/DN` R-channel comb in `直通RAW (sRGB)`; (3) check `U1-U3` recall, playback zoom, USB/PTP, and Movie mode.

# Nikon Z6 C3.80 Modified22 — Color Space `PID 0x0526` Root-Cause Fix, True `PID 0x130A` sRGB Lock & Auto ISO Restoration (2026-11-17)

## 1. Real-Camera Sample Audit (`samples/11.16_modified21/`)
- **Captured NEFs (`Ver.03.80`, Manual `M` mode, `RAW`, Lossless Compressed)**:
  - `标准 (sRGB)` group (`Z61_5093.NEF`, `Z61_5094.NEF`, `Z61_5095.NEF`):
    - DCF prefix: `Z61_`, MakerNote `ColorSpace (0x001E) = [1]` (`sRGB`), `BlackLevel = [1008, 1008, 1008, 1008]`
    - Center R-channel median: `1464..1503 DN`
    - R-channel histogram DFT at `0.2276 cyc/DN` (`4.39 DN` ISP gain/vignette comb): **`707,282 .. 718,621`** (peak **`1,240,102 .. 1,245,030`** at `0.2280 cyc/DN`)
  - `直通RAW (sRGB)` group (`_Z615096.NEF`, `_Z615097.NEF`, `_Z615098.NEF`):
    - DCF prefix: **`_Z61`** (Adobe RGB naming), MakerNote `ColorSpace (0x001E) = [2]` (**Adobe RGB**), `BlackLevel = [1008, 1008, 1008, 1008]`
    - Center R-channel median: `1472..1495 DN`
    - R-channel histogram DFT at `0.2276 cyc/DN`: **`707,965 .. 721,390`** (peak **`1,242,086 .. 1,246,224`** at `0.2280 cyc/DN`)
  - **Reference Hardware Astro Baseline (`samples/11.14_modified13/`)**:
    - `Z61_4994..4996.NEF` (R median `1666..1688 DN`): `comb@0.2276 = 26,003 .. 28,293` (~26× lower — pure Poisson/read noise floor).
- **Conclusion from Real Hardware**:
  - In `Modified21`, selecting `直通RAW (sRGB)` neither activated the 13 `Modified13` Astro RAW hooks nor locked the camera's actual Color Space to `sRGB` (`_Z61` filename prefix and MakerNote `0x001E = 2` persisted).

---

## 2. Full-Chain Firmware Root Cause (Why `Modified18 .. Modified21` All Failed)

> [!IMPORTANT]
> Every build since moving the UI switch from `NEF (RAW) compression` (`Modified16`) to `Photo Shooting Menu -> Color space` (`Modified18`..`Modified21`) misidentified the property ID of `Color space` as `PID 0x0508`.

1. **What `PID 0x0508` (`RAM 0xC24CDE28`) and `PID 0x1381` (`RAM 0xC24CC948`) Actually Are**:
   - Photo Shooting Menu row `0x113F0F58` (`String ID 0x01C0` `"ISO sensitivity settings"` -> submenu `wid=0x1396` -> `0x1049B06E`) and PTP property `0xD054` (`0x1053384A`) prove that **`PID 0x0508` is `Auto ISO sensitivity control` (`0 = Off`, `1 = On`)**!
   - `0x1040AD00` greys out Auto ISO sub-options (`Maximum sensitivity`, `Minimum shutter speed`) when `0x0508 == 0`.
   - `0x1014F638` evaluates **`PID 0x1381` = Effective Auto ISO control** in Photo modes.
   - Consequently:
     - `Modified18..Modified20` read `0xC24CDDC4` (`PID 0x0440`, Focus Shift shot count, default `100 != 1`) -> Astro RAW never activated;
     - `Modified21` read `0xC24CDE28` (`PID 0x0508`, Auto ISO) and NOP-locked `0x1014F678` (`PID 0x1381 = 0`) -> when shooting Manual (`M`) mode with Auto ISO `Off` (`0x0508 = 0`), `fn_is_astro_r0` returned `0` on every frame, `Color space` remained untouched (`_Z61` + Adobe RGB), and Photo-mode Auto ISO was inadvertently disabled!

2. **Genuine `Photo Shooting Menu -> Color space` Architecture in C3.80 ROM**:
   - **Menu Property `PID 0x0526`** (`idx = 191`, `type = 7` `uint32`, `size = 4`, **`RAM = 0xC24CDEA0`**, `default = 0`):
     - Photo Shooting Menu row `0x113F0720` binds `String ID 0x03B3` (`色空间`) to `wid = 0x1343` (`0x10497CD0: movw r0, #0x0526`);
     - Submenu rows `0x113F3B68` (`SID 0x03B4` `sRGB`) and `0x113F3B84` (`SID 0x03B5` `Adobe RGB`) invoke `0x104A149C` (`r1 = 0`) and `0x104A14A6` (`r1 = 1`) -> `0x10409240(0x0526, val)` -> `SetProperty(0x0526)`;
     - `i` Quick Menu (`0x104A8C8C`), `i`-Menu/Info strip cell (`0x113A3EEC`, icon table `0x2A4`: `0 -> sRGB`, `1 -> Adobe`), U1/U2/U3 6-bank storage (`0x11F549A4`, `bank[0] = 0xC24CDEA0`), NVRAM save list (`0x11F4B70C`), and PTP `0xD032` (`0x1053133A`) all read/write `PID 0x0526`.
   - **Effective Color Space `PID 0x130A`** (`idx = 996`, `type = 7` `uint32`, `size = 4`, **`RAM = 0xC24CC74C`**, `default = 0`):
     - Sole evaluator in the entire ROM (`Rule @ 0x114D32D0`): **`0x1014BAEA`**, which copies `PID 0x0526` (`sp+4`) into `PID 0x130A` and coerces `0x130A = 0` when Movie/HLG condition `0x130F == 2` holds (`0x1014BB28: bne #0x1014bb2e; movs r0, #0; str r0, [sp, #4]`);
     - Still-capture bulk table `0xC18B6390` (`0x101703DC`) reads `PID 0x130A` into `capture_owner + 0x25D`, which directly drives DCF filename prefix builder `0x10255850` (`0 -> "Z61_"/"DSC_"`, `1 -> "_Z61"/"_DSC"`), MakerNote `ColorSpace (0x001E)`, companion/embedded JPEG ISP (`0x100C2710`), and LiveView color pipeline (`0x10144C44`).

---

## 3. Modified22 Engineering Changes (`z6_astro_ui_color_space_v2.py`)

1. **Corrected `fn_is_astro_r0` Gate (`0x1002D900`)**:
   - Gates all 13 `Modified13` Astro RAW hooks on **`uint32([0xC24CDEA0]) == 1` (`PID 0x0526 == 1`) AND `uint32([0xC24CC798]) <= 1` (`PID 0x131B` in `{RAW+JPEG, RAW}`)**;
   - `0 = 标准 (sRGB)` executes 100% Stock C3.80 RAW processing; `1 = 直通RAW (sRGB)` executes all 13 `Modified13` Astro RAW bypass sites (independent of Uncompressed vs Lossless Compressed NEF).
2. **True Effective Color Space sRGB Lock (`0x1014BB28`)**:
   - Replaces `0x1014BB28: bne #0x1014bb2e` (`01d1`) with `nop` (`00bf`) inside `0x1014BAEA`, unconditionally running Stock's own `movs r0, #0; str r0, [sp, #4]` path so **`PID 0x130A` (`0xC24CC74C`) is locked to `0 (sRGB)`** across all camera modes;
   - Preserves `PID 0x0526` (`0xC24CDEA0`) as `0/1` across the Photo Shooting Menu, `i` Quick Menu / Info cell (`0x113A3EEC`), NVRAM power cycles, and `U1/U2/U3` user settings banks, while guaranteeing `Z61_` / `DSC_` filenames and genuine `sRGB` MakerNote & JPEG output.
3. **100% Restoration of Stock Auto ISO (`0x1040AD00` & `0x1014F678`)**:
   - Drops `Modified18..21`'s edits at `0x1040AD00` and `0x1014F678`, restoring `PID 0x0508` / `PID 0x1381` Auto ISO sensitivity control and submenu grey-out behavior byte-for-byte to factory Stock `C3.80`.
4. **Preserved Features & Reproducibility**:
   - Preserves 36-language zero-missing-glyph UI (`天文直通RAW模式` -> `标准 (sRGB)` / `直通RAW (sRGB)`), Post-Exposure Interval Timer (`0x101FF392`) + Dynamic Exposure-Aware End Day/Time (`0x1049C26C -> 0x1002E000`), and permanent 30"–600" shutter speeds (`z6_m600_v2.py`);
   - Legacy builders `M19`, `M20`, and `M21` remain 100% bit-for-bit reproducible.

---

## 4. Offline Verification Summary & On-Camera Checklist
- **Candidate Binary (`outputs/Z6-C380-modified22-reviewed-2026-11-17/01_TEST_MODIFIED22/EG162080.BIN`)**:
  - `SHA-256`: `c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771` (`33,502,842` bytes, `CRC16-HQX = 0x48f3`)
  - Total patch spans: `104` (`17` Astro/UI/sRGB + `3` Interval Timer + `84` `m600_v2`), `0` overlaps, `0` interior branch collisions, `548` B cave gap before `0x1002E000`, `3,420` B free cave headroom before `0x1002EF04`.
- **Unicorn Native Emulation (`probe_modified22_native.py`)**:
  - End-to-end UI submenu callbacks (`0x104A149C` / `0x104A14A6`) -> scalar `SetProperty` (`0x10070366`) / banked `U1..U3` (`0x10070428` / `0x10070178`) -> `GetProperty` (`0x100700A0` -> `0xC24CDEA0`) -> `fn_is_astro_r0` (`30/30` cases): **PASS**;
  - Exact reproduction of `samples/11.16_modified21` failure (`M20`/`M21` `astro=0`, `M21` `dcf="_Z61"`) vs `Modified22` fix (`astro=1`, `0x130A=0`, `dcf="Z61_"/"DSC_"` via native `0x1014BAEA -> 0x101703DC -> 0x10255850`, `30/30` cases): **PASS**;
  - Stock parity of Auto ISO `0x1040AD00` + `0x1014F638` (`14/14` cases), all `13` Astro RAW hooks (`28/28` dual-branch paths), `360/360` 36-language UI string checks, and `8` Interval sequences + `37/37` End Day/Time cases: **PASS**.
- **Updater & Kit Verification (`probe_modified22_updater.py`, `verify_modified22_kit.py`)**:
  - `7` updater prechecks (including `modified21 <-> modified22`, `modified16 <-> modified22`, `stock <-> modified22`) + `4` offline RAM flash-scheduler passes (`physical_flash=False`) + 5-slot kit verification (`M22`, `M16`, `M15`, `M13`, `Stock`; superseded `M18..21` excluded): **ALL PASS**.
- **On-Camera Acceptance**:
  1. Shoot paired `标准 (sRGB)` and `直通RAW (sRGB)` RAW frames (midtone/flat ~1400–4000 DN): verify both use `Z61_xxxx.NEF` naming, `sRGB` MakerNote (`0x001E=1`), and that `直通RAW (sRGB)` eliminates the `0.2276 cyc/DN` R-channel histogram comb;
  2. Confirm `ISO sensitivity settings -> Auto ISO sensitivity control` toggles and greys out sub-items normally in `P/A/S/M`;
  3. Confirm `i` Quick Menu, `U1/U2/U3` bank recall, 600s shutter speeds, and Interval Timer End Day/Time.

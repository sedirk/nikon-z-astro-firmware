# Nikon Z6 C3.80 `Modified16` (UI-Switchable "Astro Lossless" + Permanent `30–600s` Extended Shutter) Preflash Report

- **Date**: 2026-11-15
- **Target Model**: Nikon Z6 (1st Gen), Official Firmware Base `C3.80` (`EG162080.BIN`, `33,502,842` bytes)
- **Candidate**: `modified16-astro-ui-600s-v1` (supersedes `modified15-production-600s-v2`)
  - **SHA-256**: `4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf`
  - **CRC16-HQX**: `0x1dd2` (`crc_hqx(full_file, 0) == 0`)
  - **Recipe JSON**: `patches/z6-c380-modified16-astro-ui-600s.json` (SHA-256 `813af1df75fd8749a6c21d0a007339fc76e308d904480bdf4fed8ecf3f57a0d7`)
  - **Total Patch Sites**: `105` (`21` UI-switchable Astro Lossless & Lossless coercion sites + `84` permanent `30–600s` v2 extended shutter sites)
  - **Byte Deltas**: `5,799` bytes vs Stock `C3.80`; `1,165` bytes vs `Modified15`
- **Delivery Kit**: `outputs/Z6-C380-modified16-reviewed-2026-11-15/` and `outputs/Z6-C380-modified16-reviewed-2026-11-15.zip`
- **Verification Scope**: Offline deterministic dual-build/rollback verification + native ARM/Thumb Unicorn execution (`ROM` mapped strictly `READ | EXEC`, native ROM scalar getters `0x1015BEBE` / `0x104014DE` -> `0x100700A0` with coherent 32-bit `0xC24C*` RAM storage, plus modeled RTOS/IPC boundaries) + native Nikon firmware updater/scheduler audit. **Pending real-camera hardware test.**

---

## 1. Design A3 Architecture: In-Camera Menu Toggle for Astro RAW

### 1.1 Repurposed Menu Option (`0x0506 == 2`)
In Stock `C3.80`, `照片拍摄菜单 → NEF（RAW）记录 → NEF（RAW）压缩` (`Photo Shooting Menu -> NEF (RAW) recording -> NEF (RAW) compression`, property `0x0506`) contains three options:
1. `val = 1` (`无损压缩` / `Lossless compressed`): Factory default.
2. `val = 2` (`压缩` / `Compressed`): Nikon's lossy quantization NEF format.
3. `val = 0` (`未压缩` / `Uncompressed`): Uncompressed 12-bit / 14-bit NEF.

`Modified16` repurposes Option 2 (`val = 2`) as **`天文无损`** (Simplified Chinese `lang=8`), **`天文無損`** (Traditional Chinese `lang=9`), or **`Astro Lossless`** (English and all other 34 camera languages):

| Menu Selection (`0x0506`) | In-Camera Label | RAW Processing Path | NEF Bitstream Encoding | Remaining-Shots Capacity | EXIF MakerNote `0x0093` |
| --- | --- | --- | --- | --- | --- |
| **`1`** | **`无损压缩`** / `Lossless compressed` | **100% Stock C3.80 RAW path** (dark clipping, CAL33 vignetting & spatial corrections active) | Factory Lossless NEF | Factory Lossless | `3` (`Lossless`) |
| **`2`** | **`天文无损`** / `Astro Lossless` | **100% `Modified13` 14-site Astro RAW path** (dark clipping bypassed, CAL33 unity Group 4, digital gain unity, 2D polynomials zeroed, spatial17 neutral, fullsize front RAW preserved) | **Forced Genuine Lossless NEF** (lossless buffer size, codec flag `[0xC23234C8]=1`) | **Lossless** (`0x40000318=1`) | **`3`** (`Lossless`) |
| **`0`** | **`未压缩`** / `Uncompressed` | **100% Stock C3.80 RAW path** | Factory Uncompressed NEF | Factory Uncompressed | `10` / `6` (`Uncompressed`) |

### 1.2 Permanent Extended Shutter (`30–600s`)
`Modified15`'s 84-site `m600_v2` M-mode still extended shutter is **permanently active** regardless of whether `Astro Lossless`, `Lossless compressed`, or `Uncompressed` is selected. Full dial stepping across `Time <-> Bulb <-> 600"..60" <-> 30"..1/8000s` remains immediately available at all times.

---

## 2. Dynamic Gating & Lossless Coercion Engineering

### 2.1 Dynamic Predicate: `fn_is_astro_r0`
In `Modified16`, the Astro processing path is activated **if and only if**:
$$\text{uint32}([0xC24CC77C]) == 2 \quad \text{AND} \quad \text{uint32}([0xC24CC798]) \le 1$$
- `0xC24CC77C` stores effective NEF compression `0x1315`, built dynamically by native ROM function `0x1014a852` as `(0x0505 == 0) ? 0x0506 : 1`. If the user selects Medium or Small RAW (`0x0505 != 0`), `0x1315` is automatically forced to `1`, cleanly bypassing Astro mode.
- `0xC24CC798` (`== 0xC24CC77C + 0x1C`) stores effective recording format `0x131b` (`0` = NEF only, `1` = NEF + JPEG, `>= 2` = JPEG only). When the user selects a JPEG-only quality mode (`0x0501` in `{1, 2, 3, 4}`) or enters HDR/special modes that force JPEG-only (`0x131b = 3`), Astro RAW hooks are automatically suppressed even if `0x0506 == 2` remains stored in NVRAM.
- Both loads use a single base pointer `0xC24CC77C`:
  ```armasm
  set_u32  r1, 0xc24cc77c
  ldr      r0, [r1, #0]       ; 0x1315
  cmp      r0, #2
  bne      astro_inactive
  ldr      r0, [r1, #0x1c]    ; 0x131b
  cmp      r0, #1
  bls      astro_active
  astro_inactive:
  movs     r0, #0
  bx       lr
  astro_active:
  movs     r0, #1
  bx       lr
  ```

### 2.2 Transparent Trampoline Pattern (Zero Flag / Register Clobber)
Every multi-instruction non-BL hook uses a standardized trampoline template that guarantees bit-for-bit caller state preservation:
```armasm
tramp_site:
  push         {r0, r1, r2, lr}   ; 16 bytes: 8-byte AAPCS stack alignment preserved
  mrs          r2, apsr           ; save APSR_nzcvq flags in r2
  bl           fn_is_astro_r0
  cmp          r0, #1
  beq          tramp_astro
  msr          apsr_nzcvq, r2     ; restore exact incoming flags
  pop          {r0, r1, r2, lr}   ; restore exact incoming registers r0..r12, sp, lr
  <stock instructions>
  b.w          return_address
tramp_astro:
  msr          apsr_nzcvq, r2     ; restore exact incoming flags
  pop          {r0, r1, r2, lr}   ; restore exact incoming registers r0..r12, sp, lr
  <astro instructions>
  b.w          return_address
```

### 2.3 Lossless NEF Bitstream Coercion
To prevent the camera from applying lossy compression or undersizing the output bitstream buffer when `0x0506 == 2`, 5 dedicated coercion points intercept and coerce `mode 2 -> 1`:
1. **`0x10125782` (in `0x101254bc`)**: Coerces `r0: 2 -> 1` and writes `1` to `[owner + 0x194]`. This ensures `0x101257c4` reads `1`, calculating the full Lossless buffer capacity, and sets `[ENCODED + 0x50] = 1`, driving the hardware codec in Lossless mode (`[0xC23234C8] = 1`).
2. **`0x10142396` (in `0x101422f8`)**: Coerces property getter `0x10164bfa(0x0506)` return `2 -> 1` when initializing secondary capture owner structs.
3. **`0x10144c30` (in `0x10144bf0`)**: Coerces property getter `0x10164bfa(0x1315)` return `2 -> 1` so remaining-shots capacity calculation and `0x40000318` IPC report Lossless NEF.
4. **`0x1028d2c8`**: Coerces `r0: 2 -> 1` in EXIF MakerNote builder, writing tag `0x0093 NEFCompression = 3` (`Lossless`) instead of `4` (`Lossy`).
5. **`0x10312c24` (in `0x10312be8`)**: Coerces `[r0 + 0x4c]: 2 -> 1` before storing into `[owner + 0x194]`.

### 2.4 Unbroken Card Playback & Settings Preservation
- **SD/CFexpress Card Playback & Retouch (`0x102dd088..0x102dd184`)**: 100% factory Stock code is preserved untouched. Existing Lossy Compressed NEFs taken on other cameras or older firmwares continue to decode, display, and retouch in-camera without error.
- **User Settings (U1/U2/U3) & Save/Load Settings (`0x103c68ce -> 0x10409234`)**: 100% factory Stock code is preserved untouched. Reading raw `0x0506` directly allows `'Astro Lossless'` (`val = 2`) to be stored in and restored from user setting banks and settings files.

---

## 3. Localized UI Strings & Font Glyph Verification

At `0x104c0134` (inside string table resolver `0x104c0104`), `Modified16` intercepts string requests for ID `0x0364` (menu option label) and ID `0x057e` (`?` help text):
- **Option Label (`0x0364`)**:
  - `lang == 8` (Simplified Chinese): `"天文无损"` (`8` bytes UTF-16LE)
  - `lang == 9` (Traditional Chinese): `"天文無損"` (`8` bytes UTF-16LE)
  - All other 34 languages (`0..7, 10..35`): `"Astro Lossless"` (`28` bytes UTF-16LE)
- **`?` Help Text (`0x057e`)**:
  - `lang == 8` (Simplified Chinese): `"天文无损：关闭机内RAW暗电流裁切\n与空间彩圈校正，并以可逆无损压\n缩记录NEF(RAW)图像。"`
  - `lang == 9` (Traditional Chinese): `"天文無損：關閉機內RAW暗場裁切與\n空間彩圈校正，並以可復原的無損\n壓縮記錄NEF(RAW)影像。"`
  - All other 34 languages (`0..7, 10..35`): `"Astro Lossless: NEF (RAW) images\nare recorded using lossless\ncompression. Dark and spatial\nRAW calibration are bypassed."`
- **36-Language Font Glyph Audit**: Every character in all strings was cross-checked against the character sets of all 36 camera language string pools (`0x112C2A98`). Result: **`0/36` missing glyphs** (zero missing character warnings or tofu boxes).
- Neighbor string IDs (`0x0363` Lossless, `0x0365` 12-bit, `0x057d` Lossless help, `0x057f` Uncompressed help) are 100% untouched.

---

## 4. Comprehensive Offline Verification Summary

### 4.1 Native Unicorn ARM/Thumb Probe (`tools/fw/probe_modified16_native.py`)
1. **0x1315 Derived Property & Predicate Matrix**:
   - `20/20` cases passed across `0x1315` in `{0, 1, 2, 3}` and `0x131b` in `{0, 1, 2, 3, 0xFF}`.
   - `9/9` native `0x1014a852` builder cases passed across all (size, comp) combinations; JPEG-only suppression confirmed.
2. **Dual-Path Frontend 2D Polynomial Sanitizer (`0x1017d834`)**:
   - `168/168` total trace executions across 24 sensor configs x 7 operating modes.
   - `Stock 1` (Lossless), `Stock 0` (Uncompressed), and `JPEG-only bypass` (`2, 3`) produce **identical 507 MMIO writes and packet descriptors to Stock C3.80**.
   - `Astro RAW-only` (`2, 0`) and `Astro RAW+JPEG` (`2, 1`) produce **identical 507 MMIO writes to Modified13** (6 non-zero polynomial registers zeroed, unity DC gains).
   - `32/32` ABI/NZCV flag and `8/8` error propagation test cases passed.
3. **Dual-Path Digital Gain (`0x10122cbc`) & CAL33 Group 4 (`0x1011e2dc`)**:
   - Digital gain packet builder matches Stock C3.80 when Astro is OFF/JPEG-only, and sets unity `4096x4` when Astro is ON.
   - CAL33 static still capture routes to factory unity Group 4 (all 132 entries = `16384`) in Astro mode, routes to factory Group 0 in Stock mode, and leaves movie modes 0..13 untouched.
4. **Dual-Path Backend Dark Preserve, Vignette, Spatial17 & Front RAW**:
   - `160/160` full chain executions passed.
   - Stock mode matches Stock C3.80 identically (curves loaded, replacement buffer assigned, tag7 active).
   - Astro mode matches Modified13 identically (dark clipping bypassed, neutral vignette, spatial curves zeroed, fullsize front RAW preserved).
5. **Lossless Coercion & 36-Language UI Strings**:
   - `18/18` encoder/codec cases confirmed full Lossless buffer allocation and hardware codec `[0xC23234C8] = 1`.
   - EXIF NEFCompression tag `0x0093` verified as `3` (`Lossless`).
   - All 36 camera languages verified for localized labels and help texts; all neighbor string IDs matched Stock.
6. **Permanent 30–600s Extended Shutter**:
   - All `m600_v2` dial, burst, PTP, top-OLED, and Modified14 negative-control test suites passed.

### 4.2 Native Updater & Flash Scheduler Audit (`tools/fw/probe_modified16_updater.py`)
- `11/11` file discovery/integrity/component prechecks passed:
  - Upgrade paths: `modified15 -> modified16`, `modified13 -> modified16`, `modified12 -> modified16`, `stock -> modified16`.
  - Rollback paths: `modified16 -> modified15`, `modified16 -> modified13`, `modified16 -> modified12`, `modified16 -> stock`.
  - Rejection checks: `bad_crc` (`integrity_return = 3`), `wrong_filename` (`EG172080.BIN`), `oversize`.
- `7/7` flash scheduler state-machine passes completed cleanly.

### 4.3 Kit Packaging & Offline Verification (`verify_modified16_kit.py`)
- `5/5` binaries verified:
  - `01_TEST_MODIFIED16/EG162080.BIN` (`4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf`)
  - `02_BACK_TO_MODIFIED15/EG162080.BIN` (`0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c`) [Camera-Verified Fallback 1]
  - `03_BACK_TO_MODIFIED13/EG162080.BIN` (`3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749`) [Camera-Verified Fallback 2]
  - `04_BACK_TO_MODIFIED12/EG162080.BIN` (`9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c`)
  - `05_STOCK_C380/EG162080.BIN` (`1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c`)
- Dual-build from Stock C3.80 and exact inverse rollbacks to `Modified15` and Stock verified bit-for-bit.

---

## 5. Real-Camera Testing Checklist

1. **Direct Firmware Upgrade**:
   - Copy `01_TEST_MODIFIED16/EG162080.BIN` to memory card root directory.
   - Camera -> Setup menu (wrench) -> Firmware version -> Update.
2. **Menu Toggle & UI Help Check**:
   - Go to `Photo Shooting Menu -> NEF (RAW) recording -> NEF (RAW) compression`.
   - Confirm options display as:
     - `Lossless compressed` (无损压缩)
     - `Astro Lossless` (天文无损 / 繁体中文系统显示为“天文無損”)
     - `Uncompressed` (未压缩)
   - Press `?` on `Astro Lossless` and verify clear help text without missing glyphs.
3. **Astro vs Stock RAW Dark Frame Comparison**:
   - Set to `Astro Lossless`: shoot dark frame (cap on, 1/8000s, ISO 6400, Large RAW). Open in RawDigger: verify black level histogram is centered around ~600 ADU with normal bell curve (zero dark clipping), Lossless compression.
   - Switch to `Lossless compressed`: shoot dark frame with identical settings. Verify standard Nikon clipping at 0 ADU.
4. **Extended Shutter Check**:
   - In M mode, rotate rear command dial right/left across `60"..600" -> Bulb -> Time`.

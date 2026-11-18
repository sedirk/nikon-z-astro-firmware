# Monograph 03: Seamless UI Switch & Dual-Layer Color Space Architecture

> 🌐 **Language / 语言**: **[简体中文](03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

## 1. UI Host Selection & Property Table Disassembly

To allow astrophotographers to enable Astro RAW while freely combining every option under `NEF (RAW) recording`—including **12-bit / 14-bit** depth and **Lossless compressed / Uncompressed / Compressed** encoding—the Astro RAW switch must be decoupled from RAW compression slots and hosted on **`Photo Shooting Menu -> Color space`** (`0 = Standard (sRGB)`, `1 = Astro RAW (sRGB)`).

### 1.1 Exact Property Descriptor Mapping in Stock C3.80
Disassembly of the C3.80 ROM property descriptor tables (`0x10070474 / 0x10070478`) and menu handlers establishes the exact boundaries between adjacent camera properties:

1. **`PID 0x0526` (`RAM 0xC24CDEA0`) — True `Color space` Menu Property**:
   - Photo Shooting Menu row descriptor `0x113F0720` (`String ID 0x03B3`) invokes `0x10497CD0: movw r0, #0x0526`;
   - All six `U1 / U2 / U3` user-setting storage banks (`0x11F549A4`) and power-off NVRAM persistence read and write `PID 0x0526`.
2. **`PID 0x0508` (`RAM 0xC24CDE28`) — `Auto ISO sensitivity control` (Left Untouched)**:
   - Menu handler `0x1049B06E` (`String ID 0x01C0`) belongs to the `ISO sensitivity settings` submenu, while `0x1040AD00` and `0x1014F638` (`PID 0x1381`) govern photo-mode Auto ISO. Leaving these bytes 100% stock preserves factory Auto ISO behavior.
3. **`PID 0x131B` (`RAM 0xC24CC798`) — Effective RAW Recording State**:
   - Evaluates to `<= 1` whenever image quality includes RAW (`0 = RAW + JPEG`, `1 = RAW only`), automatically bypassing RAW hooks during pure JPEG shooting.

---

## 2. Dual-Layer Color Space Architecture in Stock C3.80

Nikon Z6 C3.80 separates Color Space into a **user menu property** and a **downstream effective property**:

```text
User Menu Selection (PID 0x0526)
        │
        ▼  (0x104A149C=0 / 0x104A14A6=1)
[ Menu Property PID 0x0526 (RAM 0xC24CDEA0) ] ─── Drives UI menus, i-menu strip, NVRAM, U1~U3
        │
        ▼
[ Single Firmware Evaluator (0x1014BAEA) ]
        │  Stock code forces 0 (sRGB) for movie mode at 0x1014BB28
        ▼
[ Effective Color Space PID 0x130A (RAM 0xC24CC74C) ]
        │
        ├─► DCF Filename Builder (0x10255850): 0 -> "Z61_xxxx.NEF", 1 -> "_Z61xxxx.NEF"
        ├─► MakerNote EXIF Tag 0x001E: 1 -> sRGB, 2 -> Adobe RGB
        └─► Embedded Preview & Companion JPEG Color Pipeline
```

- **Menu Property `PID 0x0526` (`RAM 0xC24CDEA0`)**: Drives menu selection highlights, `i`-menu cells, power-off NVRAM retention, and `U1/U2/U3` bank recall.
- **Effective Color Space `PID 0x130A` (`RAM 0xC24CC74C`)**: Computed exclusively by `0x1014BAEA`. Capture initialization (`0x101703DC`) copies this value into `capture_owner + 0x25D`, governing DCF filename prefixes (`Z61_` vs `_Z61`), EXIF `MakerNote:ColorSpace (0x001E)`, and embedded/companion JPEG color rendering.

---

## 3. Seamless Toggle & Native `sRGB` Lock (`z6_astro_ui_color_space_v2.py`)

Implemented in [z6_astro_ui_color_space_v2.py](../tools/fw/z6_astro_ui_color_space_v2.py), the firmware leverages this dual-layer split to provide a zero-side-effect Astro RAW switch:

### 3.1 Unified Gate Predicate `fn_is_astro_r0` (`0x1002D900`)
```arm
// fn_is_astro_r0:
movw  r1, #0xDEA0
movt  r1, #0xC24C
ldr   r0, [r1]           // Load PID 0x0526 (Astro RAW menu state)
cmp   r0, #1             // 1 == Astro RAW (sRGB)
bne   .not_astro
movw  r1, #0xC798
movt  r1, #0xC24C
ldr   r0, [r1]           // Load PID 0x131B (Effective RAW recording mode)
cmp   r0, #1             // Must be <= 1 (0=RAW+JPEG, 1=RAW only)
bls   .is_astro
```

### 3.2 Lock Effective Color Space `PID 0x130A` to Standard `sRGB` (`0x1014BB28`)
Inside `0x1014BAEA`, stock firmware contains a branch that skips zeroing `r0` when not in movie mode:
```arm
0x1014BB28: 01 d1        bne  #0x1014bb2e    ; Skip zeroing if non-movie
0x1014BB2A: 00 20        movs r0, #0         ; Force 0 (sRGB)
0x1014BB2C: 01 90        str  r0, [sp, #4]
```
Replacing `0x1014BB28` with a single 2-byte `nop`:
```arm
0x1014BB28: 00 bf        nop                 ; Always execute movs r0, #0 (sRGB)
```

### 3.3 Operational Benefits & 36-Language UI Support
- **Native `sRGB` Output & Standard DCF Naming**: Regardless of whether `Standard (sRGB)` or `Astro RAW (sRGB)` is selected, `PID 0x130A` remains `0 (sRGB)`, filenames remain **`Z61_xxxx.NEF` / `DSC_xxxx.NEF`** (never `_Z61xxxx.NEF`), and MakerNote `0x001E = 1 (sRGB)`, embedded previews, and RAW+JPEG out-of-camera JPEGs stay native `sRGB`;
- **Full `i`-Menu, `U1/U2/U3` & Multi-Language Integration**: Localized across all 36 firmware UI language tables (`Astro RAW Mode` / 「天文直通RAW模式」), assignable to the `i`-menu strip and saved per `U1/U2/U3` bank (e.g., `U1` for daytime standard photography and `U3` for deep-sky Astro RAW + 600s shutter) with zero interference with factory Auto ISO.

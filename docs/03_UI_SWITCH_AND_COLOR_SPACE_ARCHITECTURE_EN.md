# Monograph 03: Seamless UI Switch & Dual-Layer Color Space Architecture

> 🌐 **Language / 语言**: **[简体中文](03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

## 1. Why Earlier Color-Space Migrations (`Modified18`–`Modified21`) Failed

Prior to `Modified18`, the Astro RAW switch was hosted inside `NEF (RAW) recording -> NEF (RAW) compression` by repurposing the lossy compression slot. However, coupling Astro RAW to the compression menu prevented users from independently selecting **Lossless compressed** vs **Uncompressed** RAW.

Starting in `Modified18`, we migrated the toggle to `Photo Shooting Menu -> Color space` (`0 = Standard (sRGB)`, `1 = Astro RAW (sRGB)`). Yet real-camera testing of `Modified18` through `Modified21` revealed that Astro RAW hooks never activated in manual M-mode astrophotography.

### 1.1 Root Cause: Property ID Misidentification (`PID 0x0508` vs `PID 0x0526`)
Full disassembly of the C3.80 ROM property descriptor tables (`0x10070474 / 0x10070478`) and menu item handlers uncovered the exact cause:

1. **`PID 0x0508` (`RAM 0xC24CDE28`) is NOT Color Space — it is `Auto ISO sensitivity control`**:
   - Menu handler `0x1049B06E` (`String ID 0x01C0`) proves `PID 0x0508` belongs to the `ISO sensitivity settings` submenu;
   - `0x1040AD00` controls submenu graying when Auto ISO is turned OFF (`0x0508 == 0`);
   - `0x1014F638` computes effective photo Auto ISO state (`PID 0x1381`).
2. **Cascade in `Modified18`–`Modified20`**:
   - `fn_is_astro_r0` read `0xC24CDDC4` (`PID 0x0440`, *Focus shift shooting — Number of shots*, default `100 != 1`), causing the gate to return `0` unconditionally.
3. **Cascade in `Modified21`**:
   - `fn_is_astro_r0` read `0xC24CDE28` (`PID 0x0508`) and forced `0x1014F678` (`PID 0x1381 = 0`);
   - When shooting in M mode with Auto ISO OFF (`0x0508 == 0`), the Astro gate stayed `0`, leaving the `0.2276 cyc/DN` comb untouched while simultaneously leaving Adobe RGB `_Z61` filenames active and disabling photo-mode Auto ISO!

---

## 2. True Dual-Layer Color Space Architecture in Stock C3.80

Nikon Z6 C3.80 separates Color Space into a **user menu property** and a **downstream effective property**:

```text
User Menu Selection (PID 0x0526)
        │
        ▼  (0x104A149C=0 / 0x104A14A6=1)
[ Menu Property PID 0x0526 (RAM 0xC24CDEA0) ] ─── Drives UI menus, i-menu strip, NVRAM, U1~U3
        │
        ▼
[ Single Firmware Evaluator (0x1014BAEA) ]
        │  Stock code already forces 0 in movie mode at 0x1014BB28
        ▼
[ Effective Color Space PID 0x130A (RAM 0xC24CC74C) ]
        │
        ├─► DCF Filename Builder (0x10255850): 0 -> "Z61_xxxx.NEF", 1 -> "_Z61xxxx.NEF"
        ├─► MakerNote EXIF Tag 0x001E: 1 -> sRGB, 2 -> Adobe RGB
        └─► Companion/Embedded JPEG Color Pipeline
```

- **Menu Property `PID 0x0526` (`RAM 0xC24CDEA0`)**:
  Bound directly to Photo Shooting Menu row `0x113F0720` (`String ID 0x03B3`, calling `0x10497CD0: movw r0, #0x0526`) and saved across all six `U1/U2/U3` user-setting banks (`0x11F549A4`).
- **Effective Color Space `PID 0x130A` (`RAM 0xC24CC74C`)**:
  Computed exclusively by `0x1014BAEA`. Capture initialization (`0x101703DC`) copies this value into `capture_owner + 0x25D`, governing DCF filename prefixes (`Z61_` vs `_Z61`), EXIF `MakerNote:ColorSpace (0x001E)`, and embedded/companion JPEG color rendering.

---

## 3. The Three-Part Fix in `Modified22`

Implemented in [z6_astro_ui_color_space_v2.py](../tools/fw/z6_astro_ui_color_space_v2.py), `Modified22` cleanly decouples the UI switch from downstream color space side effects:

### 3.1 Gate Predicate Bound to `PID 0x0526` (`0x1002D900`)
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
**Resulting Behavior**:
- Regardless of whether `Standard (sRGB)` or `Astro RAW (sRGB)` is selected, `PID 0x130A` is always `0 (sRGB)`;
- Filenames always remain **`Z61_xxxx.NEF` / `DSC_xxxx.NEF`** (never `_Z61xxxx.NEF`);
- MakerNote `0x001E`, embedded previews, and RAW+JPEG out-of-camera JPEGs remain native `sRGB`;
- Photo Shooting Menu, `i`-menu cells, `U1/U2/U3` banks, and power-off NVRAM persistence faithfully track `PID 0x0526`.

### 3.3 Full Restoration of Factory Auto ISO (`0x1040AD00` & `0x1014F678`)
Both `0x1040AD00` (4 bytes) and `0x1014F678` (2 bytes) are restored byte-for-byte to Stock C3.80, guaranteeing 100% factory Auto ISO behavior.

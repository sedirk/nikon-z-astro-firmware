# Monograph 03: Seamless UI Switch & Dual-Layer Color Space Architecture

> 🌐 **Language / 语言**: **[简体中文](03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

## 1. UI Host Selection & Property Table Disassembly

To deliver native in-camera controls without sacrificing any factory photography capability, the firmware exploits Nikon Z6 C3.80's decoupled property architecture and hosts its two user-facing switches on **two mutually orthogonal factory menu entries** (disjoint RAM addresses and state machines):

| Firmware Toggle | Repurposed Factory Menu Location | Property ID & RAM Address | Original Stock Options & Role | Repurposed Menu Labels & Behavior | Downstream State Lock & Persistence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Astro RAW mode**<br>(`天文直通RAW模式`) | **Photo Shooting Menu** -> **Color space** | `PID 0x0526`<br>`RAM 0xC24CDEA0`<br>(`SID 0x03B3`) | `0 = sRGB` (`0x03B4`)<br>`1 = Adobe RGB` (`0x03B5`)<br>Controls JPEG/EXIF color space & `_Z61` filename prefix | `0 = Standard (sRGB)`<br>`1 = Astro RAW (sRGB)`<br>Freely combinable with 12/14-bit and Lossless / Uncompressed / Compressed RAW | Evaluator `0x1014BB28` **permanently locks** effective color space `PID 0x130A` (`0xC24CC74C`) to **`0 (sRGB)`** (`Z61_`/`DSC_` naming); supports `i`-menu strip, independent `U1–U3` bank recall, and NVRAM retention |
| **Astro red display**<br>(`天文红光显示`) | **Setup Menu (wrench icon)** -> **Information display** | `PID 0x1111`<br>`RAM 0xC24DD0EC`<br>(`rom_default = 0` @ `0x114E3DF0`, `SID 0x023F`) | `0 = Dark on light` (`0x0240`, white background)<br>`1 = Light on dark` (`0x0241`, dark background)<br>Selects rear-screen `DISP` shooting info theme | `0 = Off (Standard)`<br>`1 = On (Astro Red)`<br>Switches rear LCD & OLED EVF to pure-red night vision while keeping RAW/JPEG & HDMI normal | `0x1040E7D8` & `0x1043A1E0` **permanently lock** the `DISP` info screen to eye-friendly **`Light on dark`**; *Reset all settings* defaults to `0` (`Off`). Assignable to **MY MENU** top item + `Fn1/Fn2` for blind one-button toggling |

> [!NOTE]
> **First-Boot State Note (In-Camera NVRAM Retention)**: Updating Nikon firmware preserves existing user settings stored in camera NVRAM. If **`Setup Menu -> Information display`** was previously set to **`Light on dark` (`1`)** under stock firmware, the camera will read `PID 0x1111 == 1` on the first boot after flashing and start directly in **`On (Astro Red)`** mode. Simply open `Setup Menu -> Astro red display` and switch it once to **`Off (Standard)` (`0`)** to restore normal full-color display across subsequent power cycles.

Sections 1–3 below detail the `PID 0x0526` dual-layer Color Space split and `fn_is_astro_r0` gate; Section 4 summarizes how `PID 0x1111` chains orthogonally at the `GetLanguageString` epilogue (for the VGC Channel 1 pure-red display backend, see **[NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md](NIGHT_VISION_RED_DISPLAY_ARCHITECTURE_EN.md)**).

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

---

## 4. Second Orthogonal Switch (`PID 0x1111` Information Display) & Chained 36-Language Epilogue

Implemented in [z6_night_vision_red.py](../tools/fw/z6_night_vision_red.py), the Night Vision Red Display switch coexists with the Color Space architecture with zero address or state overlap:

1. **Disjoint Property & State-Machine Coordinates**:
   - The red-display switch reads `PID 0x1111` (descriptor `0x114D7E58`, `RAM 0xC24DD0EC`, menu callbacks `0x104CE0A4 = 0` / `0x104CE0AE = 1`), completely separate from `PID 0x0526` (`RAM 0xC24CDEA0`), effective color space `PID 0x130A` (`RAM 0xC24CC74C`), and Auto ISO `PID 0x0508` (`RAM 0xC24CDE28`). All four (`2 × 2`) combinations of Astro RAW and Astro Red Display operate independently;
2. **Permanent `DISP` Dark-Theme Lock**:
   - Stock firmware consumes `PID 0x1111` exclusively in two `DISP` info-screen theme selectors: `0x1040E7D6` (`0x1040E7D8: movs r4, #1 -> movs r4, #0`) and `0x1043A1D6` (`0x1043A1E0: beq -> b #0x1043A214`). Locking both branches keeps the `DISP` parameter screen permanently on **`Light on dark`** whether `PID 0x1111` is `0` (`Off`) or `1` (`On`);
3. **Chained 36-Language `GetLanguageString` Epilogue (`0x104C0134 -> 0x104C013C`)**:
   - While the Astro RAW string override hooks `0x104C0134` (`SID 0x03B3 / 0x03B4 / 0x03B5 / 0x082B / 0x0935`), the Astro Red string override chains cleanly at the immediately following epilogue instruction `0x104C013C` (`tramp_astro_red_lang_str` @ `0x1002E2A8`, overriding `SID 0x023F / 0x0240 / 0x0241 / 0x054C`), verified for `0` missing font glyphs across all 36 factory language pools before executing stock `pop.w {r0..r8, pc}`.

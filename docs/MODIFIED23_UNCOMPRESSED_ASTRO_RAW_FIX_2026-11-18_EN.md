# Nikon Z6 C3.80 `Modified23` Uncompressed Astro RAW Hardware Bit-Packer Fix & Real-Camera Verification Report

> 🌐 **Language / 语言**: **[简体中文](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

> [!IMPORTANT]
> **Validation Status (Verified on Real Camera Hardware)**: `Modified23` (`modified23-uncompressed-astro-raw-pid0526-srgb-600s-v1`, SHA-256: `47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029`, CRC-16/XMODEM: `0xc083`) has passed both full offline emulation and **physical EXPEED 6 camera flashing & 9-NEF real-capture verification (`samples/11.19_modified23`, `hardware_pixels_verified = true`)**. Alongside 105-site binary verification (with negative `Modified22` rejection gates), 437-case Unicorn pipeline emulation, software `packed-14`/`packed-12` round-trip plus real-NEF (`Z61_5105.NEF`) software repack, and `7` updater file checks + `5` offline flash-scheduler passes, all `6` on-camera long-exposure uncompressed `14-bit` NEFs (`5s` × 3 + `60s` extended shutter × 3, totaling `146,991,360` hardware-packed pixels) emit exact `42,920,960` B `packed-14` strips with zero preview overlap and zero pixel difference against `LibRaw 0.22.2`. This milestone shipped as `v3.80-modified23` and is carried forward unchanged in the latest production release (`v3.80-modified24`).

---

## 1. Observed Symptom & Real-NEF Forensics (`samples/11.17_modified22/Z61_5105..5107.NEF`)

During the [18-NEF pixel-level audit of `Modified22`](MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md), every `1/8000s` frame (both Astro and Standard), every `Lossless compressed` frame, and every Standard-mode `5s` dark frame produced a standard `42,920,960` B (`packed-14`, row stride `10,624` B) strip with zero pixel overlap and exact `LibRaw 0.22.2` parity. Exclusively when combining **`Astro RAW (sRGB)` + long exposure (`5s`) + `Uncompressed`**, frames `Z61_5105.NEF` – `Z61_5107.NEF` exhibited three coupled anomalies:

1. **Strip Size Overflow & Bit-Packing Mismatch**:
   - TIFF `SubIFD2` still declared `Compression = 34713` and `BitsPerSample = 14`, yet `StripByteCounts (0x0117)` jumped to **`48,997,120` B** (`6064 × 4040 × 2`, i.e., unpacked `16-bit LE` at `12,128` B/row), exceeding the `42,920,960` B `packed-14` slot ceiling (`raw_cap`) by **`6,076,160` B**.
2. **Bottom-Row Overwrite by Embedded Preview JPEGs**:
   - The in-camera NEF container writer continued placing three embedded preview JPEG copies (`SubIFD1`, `MakerNote PreviewIFD`, and `SubIFD3`) at fixed offsets relative to `StripOffset` computed for a `42,920,960` B slot (`+44,072,448` / `0x02A07E00`, `+48,027,648` / `0x02DCC000`, and `+48,204,288` / `0x02DF8000`), overwriting rows **`3633..4000`** near the bottom of the `48,997,120` B `16-bit LE` strip.
3. **Third-Party Decoder Misinterpretation**:
   - Guided by `Compression = 34713` + `BitsPerSample = 14`, `LibRaw 0.22.2 / rawpy` unpacked the `16-bit LE` bytes as `packed-14` (4 pixels per 7 bytes), shifting medians to `3840~3856 DN` and synthesizing tens of thousands of false `0 ADU` pixels.

---

## 2. Full-Pipeline Firmware Root Cause (`0x10124196 -> 0x100AE3A4 -> 0x100A3480`)

Tracing the still-capture RAW acquisition, buffer routing, and NEF encoding state machines in C3.80 ROM explained why this bug occurs **if and only if** `Astro RAW + >= 1s exposure + Uncompressed` coincide:

```text
[ 0x10124196 -> 0x10123E70 Frontend Capture Descriptor Planner: INPUT (frame+0x1f8) ]
  ├── 12-bit RAW (depth==0) or 14-bit short exposures (< 1s, wide==0 && slow_1af0==0):
  │     INPUT format = 2 (12-bit packed) or 4 (14-bit packed)
  └── 14-bit long exposures (>= 1s, depth==1 with owner+0x252==1 or owner+0x1af0!=0):
        INPUT format = 3 (16-bit LE unpacked, 2B/px)
           │
           ▼
[ 0x10142D8E / 0x10142E7A Clear wide/slow_1af0 Post-Capture -> 0x10124224 Backend OUTPUT (frame+0x1fc) ]
  └── OUTPUT format is always initialized to 4 (14-bit packed) or 2 (12-bit packed)
           │
           ▼
[ 0x100AE33E (hook site 0x100AE3A4) -> 0x100AE41E Release Buffer Router ]
  ├── Standard (sRGB) / M/S RAW: 0x100AE3A4 calls 0x101BA474 (has_raw==1) -> req+0x1a8 = OUTPUT -> selects format 4 / 2
  └── Full-Size Astro RAW (sRGB): tramp_ae3a4 calls 0x101BA4B6 (r0=0) -> req+0x1a8 = 0 -> retains frontend INPUT (format == 3 on >= 1s!)
           │
           ▼
[ 0x100AF648 NEF Codec Dispatcher (0x100AF65A: returns 0 immediately when JPEG-only) ]
  ├── Lossless / Lossy compressed (0x100A323E -> 0x101CAAD8): natively submits format == 3 descriptor to hardware codec queue
  └── Uncompressed -> invokes 0x100A3480 Uncompressed Hardware Bit-Packer:
        ├── chosen format != 3 (0x100A349E): passes through pre-packed buffer -> 42,920,960 B (OK)
        └── chosen format == 3 (0x100A349A: cmp r3, #3; beq #0x100A34D0):
              Stock 0x100A34D0: strb r2, [r4, #2]; strb r2, [r4, #3] (with r2 == 0!)
              -> sets input [r4+2]=0 (16-bit LE) AND output [r4+3]=0 (16-bit LE)!
              -> 0x100A359C emits 12,128 × 4,040 = 48,997,120 B, overflowing raw_cap into preview slots!
```

1. **Frontend `format = 3` Acquisition on Long Exposures (`0x10124196 -> 0x10123E70`)**:
   Whenever `14-bit` long-exposure / wide readout timing is active (`owner+0x252 == 1` for `>= 1s` exposures, or `owner+0x1AF0 != 0`), the frontend sensor DMA descriptor `INPUT` (`frame+0x1f8`) uses `format = 3` (`16-bit LE` unpacked, 2 bytes per pixel, holding linear 14-bit `0..16383` ADC values).
2. **Why Standard Mode and Lossless Compressed Were Unaffected**:
   - In **`Standard (sRGB)`** (and Medium/Small RAW), post-capture routines `0x10142D8E` / `0x10142E7A` clear `owner+0x252` and `owner+0x1AF0` before `0x10124224` initializes the backend replacement descriptor `OUTPUT` (`frame+0x1fc`) to `format = 4` (`14-bit` packed) or `format = 2` (`12-bit` packed); `0x100AE3A4` calls `0x101BA474` (`has_raw == 1`), storing `OUTPUT` into `req+0x1a8` so `0x100AE41E` swaps `frame+0x1f8` to `OUTPUT` (`r3 != 3` in `0x100A3480`);
   - In **`Lossless compressed`**, compressed encoder setup `0x100A323E` natively accepts `format = 3` (`16-bit LE`) input descriptors and submits them to hardware queue `0x101CAAD8`, producing a standard Nikon lossless bitstream well inside `raw_cap`.
3. **The `0x100A34D0` Hardware Packer Configuration Flaw**:
   When full-size `Astro RAW` redirects `0x100AE3A4 -> 0x101BA4B6` (`req+0x1a8 = 0`) and routes the `format = 3` frontend `INPUT` handle straight into `0x100A3480`, `0x100A349A` (`cmp r3, #3; beq #0x100A34D0`) branches to `0x100A34D0` with `r2 == 0`. Stock executes `strb r2, [r4, #2]; strb r2, [r4, #3]`, programming both input format `[r4+2]` and output format `[r4+3]` of `CODEC_MMIO 0x20204000` to `0` (`16-bit LE`), emitting `48,997,120` B and overflowing the `42,920,960` B RAW slot.
---

## 3. `Modified23` Engineering Fix (`0x100A34D0 -> 0x1002DB5C`)

`Modified23` **leaves the frontend sensor/DMA `format = 3` capture contract completely untouched** and installs a **14th** `fn_is_astro_r0`-gated trampoline at `0x100A34D0` inside the backend uncompressed encoder:

### 3.1 Patch Site & Full-ROM Cross-Reference Safety Audit
- **Hook Site**: `0x100A34D0` (exact 4-byte replacement):
  - Stock bytes: `a270 e270` (`strb r2, [r4, #2]; strb r2, [r4, #3]`)
  - `Modified23` bytes: `8af7 44bb` (`b.w #0x1002db5c` -> `tramp_a34d0`)
  - Adjacent instruction preserved byte-for-byte: `0x100A34D4: e9e7` (`b #0x100a34aa`).
- **Global Xref Scan across 33.5 MB EG Module**:
  - `u32` function/jump-table pointer hits to `0x100A34D0..0x100A34D3`: `0`;
  - Wide branch (`b.w` / `bl`) hits: `0`;
  - Local conditional branch hits: single entry `0x100A349C: beq #0x100a34d0` targeting the start of the 4-byte hook (`0` interior `+2` branch collisions).

### 3.2 `tramp_a34d0` (`0x1002DB5C..0x1002DB93`, 56 B) Assembly Logic
Added inside `astro_ui_cave` in [`tools/fw/z6_astro_ui_color_space_v2.py`](../tools/fw/z6_astro_ui_color_space_v2.py) (`07b5eff30082fff7cdfe012807d082f3008cbde80740a270e27075f098bc0020a0706978022900d00121e17082f3008cbde8074075f08bbc`):

1. **Full Register & APSR Flag Preservation**: Saves `{r0, r1, r2, lr}` and `mrs r2, apsr_nzcvq`, then calls `fn_is_astro_r0` (`0x1002D900`, true iff `PID 0x0526 == 1 && PID 0x131B <= 1`);
2. **Standard Mode (`r0 != 1`)**: Restores `APSR` and `{r0, r1, r2, lr}`, executes stock `strb r2, [r4, #2]; strb r2, [r4, #3]`, and jumps to `0x100A34AA` (100% stock parity);
3. **Astro RAW Mode (`r0 == 1`)**:
   - Writes `[r4+2] = 0` (`16-bit LE` unpacked input);
   - Reads target NEF bit-depth code `ldrb r1, [r5, #1]` (`4` = 14-bit NEF, `2` = 12-bit NEF):
     - If `r1 == 2` (12-bit RAW selected), sets `[r4+3] = 2` (hardware `12-bit` packed output);
     - Otherwise sets `[r4+3] = 1` (hardware `14-bit` LSB-first packed output: 4 pixels -> 7 bytes, 32-byte row-aligned);
   - Restores `APSR` and `{r0, r1, r2, lr}` (zero side effects on `r0..r12, sp, lr, APSR`) and jumps to `0x100A34AA`.
4. **Bit-Exact Linear Hardware Packing (`lut_ptr = 0`) & Fallback Safety**:
   - With `[r4+2] = 0, [r4+3] = 1`, `0x100A3480` programs `CODEC_MMIO 0x20204000 + 0x40 = 0x00010008` with `lut_ptr = 0` (pure bit-packing, zero tone-curve LUT, 100% lossless over `0..16383` ADC codes);
   - High-entropy `Lossless compressed` captures that trigger the encoder's automatic fallback into `0x100A3480` are likewise protected from overflowing `raw_cap`.

### 3.3 XIP Hole 1 Budget & Historical Builder Reproducibility
- `astro_ui_cave` (`0x1002D900..0x1002DE13`) grows from `1,244` B (`Modified22`) to `1,300` B (240 instructions / `740` B code + UTF-16LE override table), leaving **`492` B free gap** before `0x1002E000` (`ADDR_M20_IV_CAVE`) and **`3,420` B free cave headroom** before `0x1002EF04` (`m600_v2`).
- `include_uncomp_raw_pack_fix` defaults to `False`, preserving 100% bit-for-bit SHA-256 reproducibility for `Modified19`, `Modified20`, `Modified21`, and `Modified22`.

---

## 4. Pre-Flash Offline Verification Matrix

Machine-readable verification artifacts are committed at [`docs/evidence/probe_modified23_native_result.json`](evidence/probe_modified23_native_result.json) and [`docs/evidence/modified23_updater_audit.json`](evidence/modified23_updater_audit.json), alongside the pinned patch recipe [`patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json`](../patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json).

### 4.1 Exact Uncompressed Output Geometry Across Crop & Shutter Modes (`wide = 1` Astro RAW)

Measured via Unicorn emulation of the full native descriptor chain (`0x10124196 -> 0x10123E70 -> 0x10124224 -> 0x101254BC -> 0x100AE33E -> 0x100AF648 -> 0x100A359C`):

| Readout & Area Mode | Dimensions (`W × H`) | Bit Depth | Input Format / Stride | `Modified23` Out Pack / Stride | `StripByteCounts` (B) | Slot Ceiling `raw_cap` (B) | Slot Fit Check |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FX Mechanical / EFCS** (`ro=0, area=0`) | `6064 × 4040` | **14-bit** | `fmt=3` (`12,128` B) | `out_pack=1` (`10,624` B) | **`42,920,960`** | `42,920,960` | **PASS** (`1,151,488` B headroom before preview 1) |
| **FX Mechanical / EFCS** (`ro=0, area=0`) | `6064 × 4040` | **12-bit** | `fmt=3` (`12,128` B) | `out_pack=2` (`9,104` B) | **`36,780,160`** | `36,780,544` | **PASS** |
| **DX Crop Mode** (`ro=0, area=1`) | `3952 × 2640` | **14-bit** | `fmt=3` (`7,904` B) | `out_pack=1` (`6,928` B) | **`18,289,920`** | `18,290,176` | **PASS** |
| **DX Crop Mode** (`ro=0, area=1`) | `3952 × 2640` | **12-bit** | `fmt=3` (`7,904` B) | `out_pack=2` (`5,936` B) | **`15,671,040`** | `15,671,296` | **PASS** |
| **FX Electronic / Silent** (`ro=1, area=0`) | `6104 × 4222` | **14-bit** | `fmt=3` (`12,208` B) | `out_pack=1` (`10,688` B) | **`45,124,736`** | `45,125,120` | **PASS** |
| **FX Electronic / Silent** (`ro=1, area=0`) | `6104 × 4222` | **12-bit** | `fmt=3` (`12,208` B) | `out_pack=2` (`9,168` B) | **`38,707,296`** | `45,125,120` | **PASS** |

*(Comparison: On row 1, `Modified22` emitted `out_pack=0`, `dst_s=12,128` B, `StripByteCounts = 48,997,120` B > `raw_cap = 42,920,960` B, reproducing the real-camera preview collision.)*

### 4.2 Native Emulation, Three-Tier Bit-Packing Round-Trip & Updater Audit Summary
1. **`tools/fw/probe_modified23_native.py` (`status: PASS`, explicitly rejects `python -O/-OO`)**:
   - **Measured Binary Identity & Negative `Modified22` Rejection Gates**: Measures SHA-256 (`47a5caa9...`), CRC-16/XMODEM (`0xc083`), and size (`33,502,842` B) directly from the tested image, and verifies that passing `Modified22` fails both binary validation (`negative_m22_binary_gate_rejected = true`) and Hook #14 Unicorn execution (`negative_m22_hook14_unicorn_rejected = true`);
   - **437-Case Categorized RAW Pipeline Matrix (`432` orthogonal grid + `5` boundary cases)**:
     - **`113` Uncompressed End-to-End Cases** (`108` grid + `4` FX electronic shutter `readout=1` + `1` `Lossless -> Uncompressed` overflow fallback `0x100AF6D8..0x100AF6E6`): executes `0x100A3480 -> 0x100A359C -> 0x101CA666 -> 0x10108F8A`, verifying `StripByteCounts <= raw_cap`, exact `CODEC_MMIO + 0x40` format bits (`0x00010008` on FX 14-bit `format=3`), and `lut_ptr = 0`;
     - **`216` Compressed Queue Descriptor Cases** (`Lossless` / `Lossy`): verifies native descriptor setup and codec queue submission (`0x100A323E -> 0x101CAAD8`; final variable-length compressed bitstream bytes are produced at runtime by EXPEED hardware);
     - **`108` `JPEG-only` (`raw_131b == 2`) Encoder-Skip Cases**: verifies `0x101BA474` returns `0`, `req+0x1a8 = 0`, and `0x100AF648` cleanly skips RAW encoding (`r0 = 0`);
     - **`216` Non-Astro Stock Parity Cases**: verifies 100% field-for-field parity against both `Stock C3.80` and `Modified22`.
   - **Site-14 (`0x100A34D0`) Dual-Branch & APSR Suite (28/28 PASS)**: Sweeps all `NZCV` flag states and caller registers, confirming exact `r0..r12, sp, lr, NZCV` preservation and intact `0x100A34D4: e9e7`;
   - **All `Modified22` Invariants Preserved**: 30 UI/`U1..U3` gate cases, 30 `PID 0x130A = 0 (sRGB)` + `Z61_`/`DSC_` naming cases, 14 Auto ISO stock-parity cases, 28 dual-branch cases across the original 13 hooks, 360 UI string checks across 36 languages, 8 post-exposure interval sequences, and 37 dynamic end-time cases all **PASS**.
2. **Three-Tier Bit-Packing & `LibRaw` Round-Trip Scope**:
   - **`synthetic_pack` (Software Full-Frame Bit-Packing Round-Trip, `PASS`)**: Verifies LSB-first `14-bit` (`10,624` B/row, `42,920,960` B) and `12-bit` (`9,104` B/row, `36,780,160` B) software pack/unpack across all `24,498,560` (`6064 × 4040`) pixels with `max_abs_adu_diff = 0`;
   - **`real_nef_libraw` (Software Repack + `LibRaw` Decode on Real `Z61_5105.NEF`; `PASS` with local sample, `SKIPPED` on clean public checkouts without `samples/`)**: Reads all **`3,672` clean unmodified `16-bit LE` sensor rows** (`0..3632` and `4001..4039`, **`22,267,008` pixels**, verified `< 16384`) from `samples/11.17_modified22/Z61_5105.NEF` (SHA-256 `65e9af0d...`), substitutes clean rows `0..367` into the **`368` rows (`3633..4000`, `2,231,552` pixels)** that were overwritten on card in `Modified22` by embedded preview JPEGs to construct a valid `4040 × 6064` pre-pack reference frame, software-repacks it into a `42,920,960` B `packed-14` strip (`1,151,488` B headroom before preview slot 1 at `+44,072,448`, with all `3` embedded preview JPEG SHA-256 digests 100% preserved), and decodes it end-to-end via `LibRaw 0.22.2 / rawpy 0.28.0` with `max_abs_adu_diff_vs_prepack_reference = 0` across all `24,498,560` pixels;
   - **`hardware_camera_nef` & `hardware_pixels_verified = true` (Physical EXPEED 6 Hardware Verification; `SKIPPED` / `false` on clean checkouts without `samples/`)**: Audits all `9` real-camera NEFs in `samples/11.19_modified23` (`3` `5s` lossless + `6` `5s / 60s` uncompressed `packed-14`), confirming `146,991,360` hardware-packed pixels match both the independent LSB-first unpacker and `LibRaw 0.22.2` bit-for-bit (`libraw_vs_independent_pixel_diff_count = 0`, `preview_overlap_count = 0`).
3. **`tools/fw/probe_modified23_updater.py` (`ok: true`, `negative_m22_binary_rejected = true`)**:
   - Passed **`7` single-module updater file checks**: **`5` valid cross-version upgrades/rollbacks** (`Modified22 -> Modified23`, `Stock C3.80 -> Modified23`, `Modified21 -> Modified23`, `Modified23 -> Modified22`, and `Modified23 -> Stock C3.80`; all `host_crc = 0`, `discovery_return = 0`, `integrity_return = 0`, `component_precheck_return = 0`, halting preflash buffer prep cleanly before physical flash primitive `0x1014A674` with `end_canary_preserved = true`) plus **`2` negative rejection checks** (`bad_crc` bit-flip rejected with `integrity_return = 3`; wrong filename `EG172080.BIN` rejected with `discovery_return != 0`);
   - Passed **`5` offline flash-scheduler passes**: **`4` normal cross-version passes** (`Modified22 <-> Modified23` and `Stock C3.80 <-> Modified23`, each executing `330` sector erase + `330` sector program adapter calls with `prefix_preserved = true`, `tail_canary_preserved = true`, `physical_flash = false`) plus **`1` injected erase-failure pass** (`Modified22 -> Modified23`, aborting cleanly with `program_service_calls = 0`).
---

## 5. Real-Camera Flash & Capture Verification (`samples/11.19_modified23`, 9 NEFs)

After flashing `Modified23` (`EG162080.BIN` SHA-256 `47a5caa9...`) onto physical Nikon Z6 hardware, `9` consecutive dark frames (`Z61_5128.NEF` – `Z61_5136.NEF`, shutter counts `480745` – `480753`) were captured at `ISO 1600` in `Astro RAW (sRGB)` (`MakerNote 0x001E = 1`, DCF prefix `Z61_`). Full machine-readable metrics are committed at [`docs/evidence/m23_audit_metrics.json`](evidence/m23_audit_metrics.json):

| Sample Group (`11.19_modified23`) | Exposure / Compression | Verified Layout | `StripByteCounts` (B) | Preview Collisions / Trailing Bytes | Independent Unpacker vs `LibRaw 0.22.2` | Frozen-112 Clamp Hits (`0,8..56`) | Former Overlay Zone (`y+2>=3633`) Hits |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`Z61_5128` – `5130`** (`3` frames) | `5s` · 14-bit Lossless | `lossless_14bit` | `24,057,606` – `24,064,594` | `0` / `0` B | Clean native lossless decode | **`0 / 112` (0%)** | **`0 / 17` (0%)** |
| **`Z61_5131` – `5133`** (`3` frames) | `5s` · 14-bit **Uncompressed** | `packed_14bit_stride10624` | **`42,920,960`** | **`0` / `0` B** | **`0` diff pixels** (`73,495,680` px) | **`0 / 112` (0%)** | **`0 / 17` (0%)** |
| **`Z61_5134` – `5136`** (`3` frames) | **`60s`** · 14-bit **Uncompressed** | `packed_14bit_stride10624` | **`42,920,960`** | **`0` / `0` B** | **`0` diff pixels** (`73,495,680` px) | **`0 / 112` (0%)** | **`0 / 17` (0%)** |

1. **Zero-Error EXPEED 6 Hardware Bit-Packing & Container Integrity**:
   - Across all `6` uncompressed long exposures (`5s` and M-mode extended `60s`), `StripByteCounts` shrinks from `48,997,120` B (`Modified22`) to exact **`42,920,960` B** (`10,612` B payload + `12` zero-pad bytes = `10,624` B/row; `6,076,160` B reduction per frame), with `StripOffset + StripByteCounts == filesize` and all three declared preview JPEGs cleanly preceding `StripOffset` with zero overlap;
   - Across all `6 × 24,498,560 = 146,991,360` pixels, the independent LSB-first `packed-14` unpacker and `LibRaw 0.22.2` achieve **`pixel_diff_count = 0`**.
2. **Recovery of Genuine Sensor Pixels in Former Overlay Rows (`3633..4000`)**:
   - All `9` frames exhibit uniform `1009.0 DN` medians across `rows 8..3632`, `rows 3633..4000`, and `rows 4001..4031`, with `zero_adu_count = 0` frame-wide;
   - Cross-correlating real dark-current hot pixels (`> 2000 ADU`) inside `rows 3633..4000` between `5s` Lossless `Z61_5130.NEF` and consecutive `5s` Uncompressed `Z61_5131.NEF` yields Pearson **`r = 0.999550`** (`63` shared hot pixels out of `67`), proving on silicon that rows `3633..4000` carry genuine bottom-of-sensor photo-charge data.
3. **Pairwise Readout Noise & Baseline Invariants**:
   - Sensor-area frame-difference noise matches between `5s` Lossless (`5128 vs 5129`) and `5s` Uncompressed (`5131 vs 5132`): `central_68pct_sigma = 4.2426 DN` and `IQR_sigma = 4.1934 DN`; `60s` Uncompressed frames (`5134..5136`) fire at `60.71s` / `60.62s` cadence (no LENR dark-frame lockout) with `central_68pct_sigma = 7.4246 DN`;
   - All `9` dark frames show R-channel `[0.22, 0.24] cyc/DN` band peaks of `92,620` – `97,087` (well below the `204,608` threshold) and **`0 / 112`** spatial clamp hits across all 112 frozen hot-pixel coordinates (including **`0 / 17`** in `y + 2 >= 3633`).

---

## 6. Standalone Reproducible Build & Offline Verification

Requires only Python 3.10+ standard library and your official `Z_6_0380.bin`:

```powershell
# Build official Modified23 release folder and deterministic .zip package
python tools/build_modified23.py --stock path\to\Z_6_0380.bin --output-dir outputs\Nikon-Z6-C380-Modified23-Astro-Firmware --zip

# Run read-only binary & opcode invariant verification
python tools/build_modified23.py --verify outputs\Nikon-Z6-C380-Modified23-Astro-Firmware
```

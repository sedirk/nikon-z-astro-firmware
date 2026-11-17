# Monograph 02: Bypassing Star-Eater & Preserving Physical Dark Current

> 🌐 **Language / 语言**: **[简体中文](02_STAR_EATER_AND_DARK_CURRENT.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

## 1. Problem Overview: Star Eating & Broken Dark Calibration

Consumer mirrorless ISP pipelines typically apply spatial hot-pixel suppression directly to RAW buffers to produce cleaner high-ISO JPEGs and previews. For astrophotography, this causes three severe defects:
1. **Clamped Dark Current & Hot Pixels**:
   Isolated photosites with elevated thermal dark current are forcefully clamped toward the maximum or median of same-color neighboring pixels;
2. **Eaten Faint Pinpoint Stars ("Star Eater")**:
   Under sharp optics and good seeing, faint single- or two-pixel stellar Airy cores share the spatial signature of isolated hot pixels and are attenuated or erased;
3. **Mismatched Master Dark Subtraction**:
   Because hot pixels are nonlinearly clamped frame-by-frame depending on surrounding noise, subtracting a Master Dark leaves behind dark "pockmarks" (negative holes) rather than cleanly canceling thermal fixed-pattern signal.

---

## 2. Disassembly & Bypass Mechanism

At `0x100C2654` in Stock C3.80, the backend RAW routine evaluates each center pixel $P_0$ against its 8 same-color neighbors in a $3\times 3$ Bayer-strided kernel (stride 2):

### 2.1 Stock Neighborhood Clamp Model
Given the local same-color 8-neighbor maximum:
$$M_8 = \max(\{P_1, P_2, \dots, P_8\})$$
whenever $P_0$ exceeds the local neighborhood threshold:
$$P_0 > M_8 + \Delta$$
stock firmware clamps or replaces $P_0$ with quantized steps $M_8 + 8 \times k$ ($k \in [0, 7]$, i.e., within $+0\dots+56\text{ DN}$ above $M_8$).

### 2.2 Firmware Patch (`0x100C2654` / `0x100C267C` / `0x100C2690`)
In `Modified13` and `Modified22`, conditional Thumb trampolines gate these three neighborhood clamp sites via `fn_is_astro_r0`:
- When `Astro RAW (sRGB)` is active, neighborhood clamping is completely bypassed, passing true sensor ADU values straight to the encoder;
- The native 14-bit black-level pedestal (`BlackLevel = 1008`) retains symmetric negative readout noise excursions below $1008\text{ DN}$ with zero black-clipping (`0 ADU` count = `0`).

---

## 3. Quantitative Verification (Frozen 112 Hot-Pixel Benchmark)

We froze **112 high-energy hot-pixel coordinates** discovered on Stock C3.80 dark frames (archived in [docs/evidence/baseline112.json](evidence/baseline112.json)) and evaluated 5-second dark frames across firmware generations:

| Firmware Build | Frozen-112 `max8 + 8k` Clamp Hits | True Hot-Pixel Retention (`> max8 + 56 DN`) | Frame-Diff Readout Noise (Central 68% / Unclipped) | `0 ADU` Clipped Pixels |
| :--- | :--- | :--- | :--- | :--- |
| **Stock Nikon C3.80** | **112 / 112 (100% clamped)** | Severely truncated ($0 / 112$ above $+56\text{ DN}$) | $3.54\text{ DN} / 4.61\text{ DN}$ | `0` |
| **Modified1 ~ Modified4** | $0 / 112$ (0% clamped) | $111\sim 112 / 112$ above $+56\text{ DN}$ | $3.54\text{ DN} / 4.59\text{ DN}$ | `0` |
| **Modified12 / Modified13** | $0 / 112$ (0% clamped) | $111\sim 112 / 112$ above $+56\text{ DN}$ (M13: $112/112$) | $3.54\text{ DN} / 4.10\sim 4.11\text{ DN}$ | `0` |
| **Modified22 (Latest, Astro RAW)** | **0 / 95 (0% clamped, clean rows)\*** | **95 / 95 (100%) above $+56\text{ DN}$** | **$3.54\text{ DN} / 4.11\text{ DN}$** | **`0`** |

*\*Note: `Modified22` executes the exact same 13 ISP hooks as `Modified13`. Because the M22 5s dark test frames (`Z61_5105..5107`) were intentionally captured in **Uncompressed** mode—which triggers an embedded preview overlay across bottom rows `3633..4000`—evaluation on the 95 frozen coordinates in the clean upper region (`y+2 < 3633`) yields `0 / 95` clamp hits and `95 / 95 (100%)` retention. For all `>= 1s` exposures in practice, always select **Lossless compressed** (see [MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md](MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md)).*

### 3.1 Summary
- Invasive $3\times 3$ same-color neighborhood clamping is completely bypassed in `Astro RAW (sRGB)`, protecting faint pinpoint stellar cores;
- Readout noise preserves unclipped Gaussian/Poisson symmetry around `1008 DN` (`0 ADU` count = `0`);
- Master Dark frames shot in 14-bit **Lossless compressed** mode align deterministically with light frames for artifact-free calibration.

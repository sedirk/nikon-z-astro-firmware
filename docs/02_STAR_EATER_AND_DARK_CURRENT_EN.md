# Monograph 02: Bypassing Star-Eater & Preserving Physical Dark Current

> 🌐 **Language / 语言**: **[简体中文](02_STAR_EATER_AND_DARK_CURRENT.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

## 1. Problem Overview: Star Eating & Broken Dark Calibration

Consumer mirrorless ISP pipelines typically apply spatial hot-pixel suppression directly to RAW buffers to produce cleaner high-ISO JPEGs and previews. For astrophotography, this causes three severe defects:
1. **Clamped Dark Current & Hot Pixels**:
   Isolated photosites with elevated thermal dark current are forcefully clamped toward the maximum of same-color neighboring pixels;
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

### 2.2 Firmware Gated Bypass (`0x100C2654` / `0x100C267C` / `0x100C2690`)
Conditional Thumb trampolines gate these three neighborhood clamp sites via `fn_is_astro_r0`:
- When `Astro RAW (sRGB)` is active, neighborhood clamping is completely bypassed, passing true sensor ADU values straight to downstream encoders (for both Lossless compressed and Uncompressed modes);
- The native 14-bit black-level pedestal (`BlackLevel = 1008`) retains symmetric negative readout noise excursions below $1008\text{ DN}$ with zero black-clipping (`0 ADU` count = `0`).

---

## 3. Real-Camera Quantitative Verification (Frozen 112 Hot-Pixel Benchmark)

We froze **112 high-energy hot-pixel coordinates** across the full sensor (including bottom rows `3633..4031`, archived in [docs/evidence/baseline112.json](evidence/baseline112.json) with full measurements in [docs/evidence/m23_audit_metrics.json](evidence/m23_audit_metrics.json)) and evaluated real-camera captures across Stock C3.80 and `Astro RAW (sRGB)`:

| Capture Mode & Frame Batch (ISO 1600, 14-bit) | Frozen-112 `max8 + 8k` Clamp Hits | Retention Above `max8 + 56 DN` | Frame-Diff Noise (Central 68% $\sigma$ / IQR $\sigma$) | Full-Frame `0 ADU` Pixels |
| :--- | :--- | :--- | :--- | :--- |
| **Stock Nikon C3.80 (5s Dark)** | **112 / 112 (100% clamped)** | $0 / 112$ (all truncated) | $3.54\text{ DN}$ (bias) | `0` |
| **Astro RAW · Bias (`1/8000s`, `Z61_5113..5115`)** | — | — | $3.54\text{ DN}$ (unclipped $4.11\text{ DN}$) | `0` |
| **Astro RAW · 5s Lossless Compressed (`Z61_5128..5130`)** | **0 / 112 (0% clamped)** | **112 / 112 (100%)** (median $\Delta \approx +10,247\text{ DN}$) | $4.24\text{ DN} / 4.19\text{ DN}$ | `0` |
| **Astro RAW · 5s Uncompressed `packed-14` (`Z61_5131..5133`)** | **0 / 112 (0% clamped)** | **111~112 / 112\*** (median $\Delta \approx +10,128\text{ DN}$) | $4.24\text{ DN} / 4.19\text{ DN}$ | `0` |
| **Astro RAW · 60s Extended-Shutter Uncompressed (`Z61_5134..5136`)** | **0 / 112 (0% clamped)** | **112 / 112 (100%)** (median $\Delta \approx +15,361\text{ DN}$) | $7.42\text{ DN} / 7.34\text{ DN}$ | `0` |

*\*Note: In `Z61_5133`, coordinate `(x=121, y=3740, G1)` exhibits physical sensor Random Telegraph Signal (RTS) blinking, dropping to baseline `1007 ADU` (`max8 + 8k` hit = `False`) before returning to `16383 ADU` full-well saturation across the subsequent `60s` frames.*

### 3.1 Summary
- Invasive $3\times 3$ same-color neighborhood clamping is 100% bypassed (`0 / 112` clamp hits) across both Lossless compressed and Uncompressed modes as well as M-mode `60"~600"` extended shutter speeds, protecting faint pinpoint stellar cores;
- Pairwise 5-second dark noise is identical between Lossless compressed and Uncompressed captures (central 68% $\sigma = 4.2426\text{ DN}$, IQR $\sigma = 4.1934\text{ DN}$), with zero black-clipped pixels (`0 ADU` count = `0`);
- Master Dark frames captured in either **Lossless compressed** or **Uncompressed** RAW align deterministically with light frames for artifact-free deep-sky calibration.

# Monograph 01: Astro RAW Pipeline Reconstruction & Concentric Ring Elimination

> 🌐 **Language / 语言**: **[简体中文](01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

## 1. Background & Observed Phenomenon (The Concentric Rings Problem)

On stock firmware of first-generation Nikon Z6 / Z7 cameras, astrophotographers stacking calibrated light and flat frames regularly encounter severe **Concentric Colored Rings** from the center toward the corners after nonlinear deep-sky stretching (e.g., STF / MaskedStretch)—regardless of whether *Vignette control*, *Auto distortion control*, and *Diffraction compensation* are turned off in camera menus.

### 1.1 Physical & Spectral Signatures on Stock Flats
Histogram and discrete Fourier transform (FFT) analysis of real-camera stock flat frames reveals:
1. **Periodic Missing Codes (Comb Signature)**:
   In the R and B Bayer channel histograms, pixel counts deviate from a smooth Poisson-Gaussian curve and exhibit periodic missing or depleted code bins alongside spiked neighbors.
2. **Fixed Spectral Comb Peak**:
   A 16384-bin `rfft` over the RAW histogram exhibits an intense periodic spike at $f = 0.2276\text{ cyc/DN}$ (corresponding to a discrete rounding period of $T = 1 / 0.2276 \approx 4.39\text{ DN}$).
3. **Root Cause**:
   Even with menu-level vignette control disabled, a frontend ISP 2D spatial shading polynomial and fixed digital gain stage inject radially varying fractional multipliers prior to RAW encoding, introducing quantization gaps that corrupt linear flat-field division.

---

## 2. Firmware Disassembly & the 13 Dynamic Control Points

Disassembly of Nikon Z6 firmware C3.80 traced the full-size RAW dataflow from sensor DMA buffers into the NEF bitstream encoder:

```text
[ Sensor ADC 14-bit RAW ]
           │
           ▼
[ Frontend ISP (0x1017D834) ] ─── Stock injects 2D polynomial shading & missing-code comb
           │
           ▼ (frame+0x1f8)
[ Backend Buffering (0x100AE3A4) ] ─── Substitutes backend filtered/rescaled buffer
           │
           ▼
[ Hot Pixel Suppression (0x100C2654) ] ─── 3x3 same-color neighborhood clamp (Star Eater)
           │
           ▼
[ Lossless Bitstream Codec (0x100AF648) ]
           │
           ▼
[ File Writer (.NEF) ]
```

### 2.1 The 13 Dynamic Trampoline Hooks (`Modified13` / `Modified22` Baseline)
To isolate and bypass every nonlinear spatial operator while preserving small/medium RAW compatibility, 13 conditional Thumb trampolines (`fn_is_astro_r0`) are installed:

1. **`0x100AE3A4` (Full-Size Frontend Direct Route)**:
   Routes full-size RAW (`size == 0`) directly from frontend `frame+0x1f8` into the NEF encoder, bypassing the backend `0x20380000` replacement buffer while leaving Medium/Small RAW downsampling intact.
2. **`0x100C2654 / 0x100C267C / 0x100C2690` (Dark Neighborhood Clamp Bypass)**:
   Skips backend $3\times 3$ same-color neighborhood clamping (`max8 + 8k`) and forced hot-pixel suppression.
3. **`0x100C28B2 / 0x100C28C8 / 0x100C2964` (Stage-2 Calibration Matrix Bypass)**:
   Skips secondary spatial vignette matrix multiplication.
4. **`0x1011E2DC` (Frontend Q12 Digital Multiplier Unity Lock)**:
   Locks all four Bayer channel Q12 digital multipliers (R, Gr, Gb, B) to exact unity $4096$ ($1.0\times$).
5. **`0x10122CBC` (Non-Null Descriptor Gain Conservation)**:
   Eliminates spatial modulation gain while preserving null-pointer safety guards.
6. **`0x1017D834 -> 0x1002D884` (In-Place 2D Shading Polynomial Sanitizer)**:
   Zeroes all 54 radial/2D shading polynomial coefficients in place and normalizes the four DC gains to unity (`16384`) before native DMA descriptor commit.
7. **`0x10197418 / 0x10197866 / 0x10197874` (Metadata & Black-Level Clamp Bypass)**:
   Prevents internal calibration flags from re-contaminating downstream NEF descriptors.

---

## 3. Real-Camera Verification (`Modified22` Matched Flats & Biases)

Under `Modified22`, matched real-camera flat frames (`Z61_5110.NEF` in Astro RAW vs `Z61_5119.NEF` in Standard sRGB, both 1/8000s, ISO 1600, 14-bit packed layout) confirm decisive comb suppression:

| Metric | Standard Mode (`Z61_5119`) | Astro RAW Mode (`Z61_5110`) | Improvement / Effect |
| :--- | :--- | :--- | :--- |
| **Histogram Envelope** | Pronounced periodic missing-code sawtooth | Smooth continuous physical curve | Periodic comb gaps eliminated |
| **`0.2276 cyc/DN` Nearest FFT Bin (`bin 3729`)** | **$27,242$** | **$2,012$** | **Reduced by ~13.5x** |
| **`0.22~0.24 cyc/DN` Band Peak** | **$278,093$** (peak at $0.2280$) | **$28,451$** | **Reduced by ~9.8x** |
| **Bias Frame Comb (`Z61_5113` vs `5102`)** | **$421,262$** | **$31,508$** | **Reduced by ~13.4x** |
| **Center Flat `R/G1` Median Ratio** | $1.0101$ (in-camera pre-scaled) | $0.8997$ (native QE response) | Nonlinear per-channel digital scaling removed |

Real-camera verification confirms that enabling `Astro RAW (sRGB)` suppresses nonlinear histogram comb modulation by an order of magnitude, eliminating false concentric colored rings during flat-field calibration.

# Monograph 04: M-Mode 600s Extended Shutter & Post-Exposure Interval Timer

> 🌐 **Language / 语言**: **[简体中文](04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md)** | **English** · 🏠 [Back to Docs Index](README_EN.md)

## 1. Resident M-Mode `30"~600"` Extended Shutter Speeds (`z6_m600_v2.py`)

### 1.1 Stock Limitation
Stock Nikon Z6 firmware caps timed manual (M-mode) shutter speeds at $30\text{ seconds}$. Deep-sky narrowband imaging, dark-site broadband subs, and long-exposure nightscapes routinely require $60\text{s}, 120\text{s}, 300\text{s}$, or $600\text{s}$ exposures—forcing photographers to rely on external wired intervalometers or manual Bulb/Time actuation.

### 1.2 Firmware Reconstruction (`z6_m600_v2.py`)
`Modified22` patches 84 spans across the C3.80 shutter speed tables, UI string formatters, and exposure timer dividers:
1. **1/3-EV Shutter Lookup Table Extension**:
   Appends 8 extended shutter steps seamlessly beyond `30"` in M mode:
   $$\text{30"} \longrightarrow \mathbf{60"} \to \mathbf{90"} \to \mathbf{120"} \to \mathbf{180"} \to \mathbf{240"} \to \mathbf{300"} \to \mathbf{480"} \to \mathbf{600"}$$
2. **Internal Exposure Timer Scaling**:
   Extends internal shutter duration timer registers to maintain stable timing up to 600 seconds;
3. **Native Top-OLED, Rear-LCD & EVF Readouts**:
   Rotating the main command dial past `30"` smoothly displays the exact second label (`60"` through `600"`) across all camera displays.

---

## 2. Post-Exposure Pure Wait Interval Timer (`z6_interval_post_exposure.py`)

### 2.1 Stock Start-to-Start Interval Flaw
In stock Nikon firmware, the built-in *Interval timer shooting* menu defines *Interval* as the **start-to-start time between consecutive exposures**.
For example, if exposure time is $25\text{s}$ and the interval is set to $30\text{s}$, only $5\text{s}$ of cooldown gap remains after readout. If Long Exposure NR (LENR) is enabled or shutter speed is raised to $60\text{s}$, single-frame duration exceeds the configured interval—causing skipped frames, shortened sequences, or immediate abort.

### 2.2 Starting Interval Countdown Upon Exposure Completion (`0x101FF392`)
Implemented in [z6_interval_post_exposure.py](../tools/fw/z6_interval_post_exposure.py), we intercept the shutter-close and sensor-readout completion callback at `0x101FF392`:
- **Pure Cooldown / Settle Gap**: The configured menu *Interval* becomes the **pure post-exposure waiting gap** after exposure and readout complete (ideal for sensor thermal cooldown, mount dithering, or tethered transfer);
- When *Shots per interval* is `1`, the wait gap runs after every frame; when *Shots per interval* is `> 1`, the burst completes first and the pure wait gap runs between bursts, preventing frame drops regardless of shutter duration.

---

## 3. Dynamic Exposure-Aware End-Time Predictor (`0x1049C26C -> 0x1002E000`)

### 3.1 Real-Time Completion Time Formula
Because intervals now represent post-exposure wait time, the *End day/time* preview shown inside the Interval Timer menu was reconstructed via a 424-byte native ARM/Thumb routine injected at `0x1002E000`:

$$T_{\text{total}} = N \times K \times (T_{\text{exp}} + T_{\text{lenr}} + T_{\text{delay}}) + (N - 1) \times T_{\text{interval}}$$

where:
- $N$: Number of intervals;
- $K$: Shots per interval;
- $T_{\text{exp}}$: Active shutter duration queried dynamically (supports M-mode `60"~600"` extended speeds, caps S-mode at `30"`, and reads metered exposure property `0x1308` in P/A/Auto);
- $T_{\text{lenr}}$: Automatically adds an equal dark-subtraction duration when $T_{\text{exp}} > 1\text{s}$ and Long Exposure NR is enabled;
- $T_{\text{delay}}$: Automatically includes Custom Setting `d4` Exposure Delay Mode (`1s / 2s / 3s`).

Photographers configuring multi-hour deep-sky or night-sky time-lapse sequences see an accurate completion timestamp directly on the rear LCD before pressing *Start*.

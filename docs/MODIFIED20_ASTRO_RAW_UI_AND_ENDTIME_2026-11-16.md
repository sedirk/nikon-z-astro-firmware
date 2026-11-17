# Nikon Z6 C3.80 `Modified20` Pre-Flash Technical Review (2026-11-16)

## 1. Scope & Summary
`Modified20` builds directly on `Modified19` (`c4629a3700c947846b6c535567beb57055613db1b4120d024b7473cd1e27667a`) and delivers two user-requested enhancements while preserving 100% backward compatibility with `Modified19`'s post-exposure interval scheduler, 13-site Astro RAW pipeline, sRGB EXIF/filename lock, and M-mode `60"~600"` extended shutter speeds:

1. **Idiomatic Chinese UI Localization (`天文直通RAW模式` / `天文直通RAW`)**:
   - Updates `UI_OVERRIDES_M20` in `tools/fw/z6_astro_ui_color_space_v2.py` across all 5 localized `0x0508` String IDs (`0x03B3`, `0x03B4`, `0x03B5`, `0x082B`, `0x082C`), verified for **0 missing glyphs across all 36 camera languages** and generous pixel margins (`<= 212 px` inside the `350 px` `0x015E` colon-label box at `0x11347E24` / `0x113F5B34`, and `370 px+` menu title box).
2. **Dynamic Exposure-Aware Interval Timer `End day/time` (`结束日期/时间`, `0x1049C19A`)**:
   - Replaces Stock's hardcoded `32s × 1 interval` assumption in `0x1049C19A` with a Thumb-2 cave routine at `0x1002E000` (hooked at `0x1049C26C`, 4 bytes) that dynamically queries the active shutter duration across **all camera exposure modes** (including `30" = 32.0s` and extended `60"~600"`), Long Exposure NR (`0x0528` when `> 1s`), and Exposure Delay Mode (`0x1025`) across all `N × K` frames plus `(N - 1)` post-exposure intervals.

---

## 2. Enhancement 1: `天文直通RAW模式` 36-Language UI Table (`0x1002D900..0x1002DD9C`)

| String ID | Stock Text | `Modified20` ZH_CN | `Modified20` ZH_TW | `Modified20` EN & Other 33 Langs |
| --- | --- | --- | --- | --- |
| `0x03B3` | `色空间` / `Color space` | `天文直通RAW模式` | `天文直通 RAW 模式` | `Astro RAW mode` |
| `0x03B4` | `sRGB` | `标准 (sRGB)` | `標準 (sRGB)` | `Standard (sRGB)` |
| `0x03B5` | `Adobe RGB` | `天文直通RAW` | `天文直通 RAW` | `Astro RAW` |
| `0x082B` | `sRGB：` / `sRGB:` | `标准 (sRGB)：` | `標準 (sRGB)：` | `Standard (sRGB):` |
| `0x082C` | `Adobe RGB：` / `Adobe RGB:` | `天文直通RAW：` | `天文直通 RAW：` | `Astro RAW:` |

---

## 3. Enhancement 2: Dynamic Interval Timer `End day/time` (`0x1049C26C -> 0x1002E000`)

### 3.1 Root Cause of Stock Inaccuracy
In Stock `0x1049C19A` (sole caller of calendar helper `0x1049BFF4`, invoked by `0x1049C676` on Interval Timer menu open and `0x104A8A5C` when refreshing widgets `0x047E` End day and `0x047F` End time):
- `0x1049C1FC..0x1049C204` hardcoded `r0 = 0x20` (`32` seconds) into `sl` and `[sp, #0x20]`, ignoring actual shutter speed.
- `0x1049C276..0x1049C30E` computed `(N - 1) * interval_tenths + K * (320 + lenr_tenths + delay_tenths)`, counting only a single interval's exposure overhead under Stock's start-to-start grid.

### 3.2 `Modified20` Exact Post-Exposure Formula & Cave Design
Both the menu spinner loop (`0x1049C24A..0x1049C26A`, `r8 = 4`, `sb = N`) and the active/pause remaining-shots branch (`0x1049C2CC..0x1049C2D6`, `r8 = 0`, `[sp, #0x24] = rem_total_shots`, `sb = rem_intervals` via `0x10205530`) converge at `0x1049C26C` (`5fea0900`: `movs.w r0, sb`).

`Modified20` hooks `0x1049C26C -> 0x1002E000` (`424` bytes, `139` Thumb-2 instructions):
1. **Zero-interval guard**: If `N == 0` (or `rem_total_shots == 0`), jumps to `0x1049C31A` with `(r0, r1) = (0, 0)` so `End == Start`.
2. **Total frames & gaps**:
   - Menu path (`r8 != 0`): `total_shots = N * K` (`K = *(uint32_t *)0xC1832A5C`), `num_gaps = N - 1`.
   - Pause/active path (`r8 == 0`): `total_shots = [sp, #0x24]`, `num_gaps = rem_intervals - 1`.
3. **Active Shutter Duration (`exp_ms`) via `0x101C486E`**:
   - **M mode (`[0xC24CC8FC] == 3`)**:
     - `sub_1319 == 0` (Timed): reads `tv_s24` (`[0xC24CD9C0]`, `-255..+384`) and calls `0x101C486E`, resolving exact microseconds for both Stock speeds (`30"` -> `32,000 ms`, `1/2s` -> `500 ms`, `1/1000s` -> `1 ms`) and all 8 extended speeds (`60"` -> `60,000 ms` up to `600"` `tv_s24 = -224` -> `600,000 ms`).
     - `sub_1319 == 3` (`x200`): calls `GetProperty(0x1034)` -> `0x101C486E`.
     - `sub_1319 in {1, 2}` (`Bulb` / `Time`): `exp_ms = 0`.
   - **S mode (`[0xC24CC8FC] == 1`)**: reads `tv_s24` (`[0xC24CD9C0]`), clamps `tv_s24 >= -120` (`30"` max in S mode), and calls `0x101C486E`.
   - **P / A / Auto (`[0xC24CC8FC] not in {1, 3}`)**: reads 8-byte metered rational `{denom, pad, num}` at `0xC24CC73C` (`PID 0x1308`), rejects unmetered/Lo/Hi sentinels (`denom <= 0`, `denom > 1024`, `num < -10*denom`, `num > 16*denom`), clamps `[-10*denom, -5*denom)` to `-5*denom` (`30"`), and calls `0x101C486E`.
4. **Per-Shot Overhead & 64-bit Total Milliseconds**:
   - Long Exposure NR (`0x0528`): if `exp_ms > 1000` (slower than `1"`) and `GetProperty(0x0528) != 0`, adds `+exp_ms`.
   - Exposure Delay (`0x1025`): if `GetProperty(0x1025) < 10000` unsigned, adds `+delay_ms` (`0..3000 ms`).
   - Computes 64-bit `total_ms = (N - 1) * interval_tenths * 100 + total_shots * shot_ms`, sets `(r1=500, r2=1000, r3=0)`, restores `sp`, and resumes `0x1049C310` (`blx 0x1023AE48` ARM `__aeabi_uldivmod` -> `total_sec` -> `+59s` minute rounding & `0x1049BFF4` calendar rollover).

---

## 4. Verification Summary
- **Candidate Binary**:
  - `SHA-256`: `8003fac8111e059d8b64d7800e471524247eab451dc1f84da2b163ed2e255ac1`
  - `CRC16-HQX`: `0x9fcf` (full-image remainder `0`)
  - Total spans: `104` (`17` Astro/UI + `3` Interval Timer + `84` `m600_v2`), `0` overlaps, `0` interior branch collisions, `3,420` bytes free cave headroom before `0x1002EF04`, 100% reversible to Stock `C3.80`.
- **Unicorn Native Emulation (`probe_modified20_native.py`)**:
  - Astro predicate matrix: `15/15 PASS`; sRGB lock: `3/3 PASS`; dual-path RAW trampolines: `6/6 PASS`;
  - 36-language `UI_OVERRIDES_M20` + neighbor string verification: `360/360 PASS`;
  - Post-exposure interval sequences (driving native `0x10200D9C..0x10200DBC` shutter-start count decrement into `0x101FED02` entry, multi-stage `0x10206950` RTOS timer delivery, and genuine low-word `0xFFFFFF00 + 1000` 64-bit carry): `3/3` stock reproductions + `8/8` `Modified20` sequences `PASS`;
  - Full native `0x1049C19A` `End day/time` matrix (covering stock & all 8 extended `60"~600"` speeds, multi-shot bursts, LENR `1s` vs `>1s`, Exposure Delay, M `Bulb`/`Time`/`x200`, S clamp, P/A metered & Lo/Hi sentinels, Pause screen `0x9E`, `N=0`, and year-end rollover): `37/37 PASS`.
- **Native Updater & Kit Verification (`probe_modified20_updater.py`, `verify_modified20_kit.py`)**:
  - `6` updater prechecks + `4` flash-scheduler passes + `5`-slot kit SHA-256/CRC16 verification: **ALL PASS**.

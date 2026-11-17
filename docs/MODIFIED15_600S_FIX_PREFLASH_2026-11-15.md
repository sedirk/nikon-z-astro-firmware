# Nikon Z6 C3.80 `Modified15` (`30–600s` v2 T-Mode Lock Fix + Astro RAW Convergence) Preflash Report

- **Date**: 2026-11-15
- **Target Model**: Nikon Z6 (1st Gen), Official Firmware Base `C3.80` (`EG162080.BIN`, `33,502,842` bytes)
- **Candidate**: `modified15-production-600s-v2` (supersedes `modified14-production-600s`)
  - **SHA-256**: `0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c`
  - **CRC16-HQX**: `0xa0c5` (`crc_hqx(full_file, 0) == 0`)
  - **Recipe JSON**: `patches/z6-c380-modified15-production-600s.json` (SHA-256 `2274a21596e99e71578bfc4a3c664862f1322891243e68d868d00398c3bc4eb6`)
  - **Total Patch Sites**: `98` (`14` inherited unchanged from camera-verified `Modified13` + `84` native ROM `30–600s` v2 sites)
  - **Byte Deltas**: `4,687` bytes vs Stock `C3.80`; `4,579` bytes vs `Modified13`
- **Delivery Kit**: `outputs/Z6-C380-modified15-reviewed-2026-11-15/` and `outputs/Z6-C380-modified15-reviewed-2026-11-15.zip`
- **Verification Scope**: Offline deterministic dual-build/rollback verification + native ARM/Thumb Unicorn execution (`ROM` mapped strictly `READ | EXEC`, native ROM scalar getters `0x1015BEBE` / `0x104014DE` -> `0x100700A0` with coherent 32-bit `0xC24C*` RAM storage, plus modeled RTOS/IPC commit/dial-permission boundaries documented in §3.1) + native Nikon firmware updater/scheduler audit. **Pending real-camera hardware test.**

---

## 1. Exact Root Cause of `Modified14` Real-Camera `Time` (`T` 门) Lockup

On physical Nikon Z6 hardware flashed with `Modified14` (`6d970609...`), rotating the command dial in M-still mode left the camera frozen in its pre-flash NVRAM `Time` (`T` 门) state. Full instruction-level disassembly and Unicorn reproduction (`reproduce_modified14_tmode_lock` in `tools/fw/z6_m600_v2_emu_e2e.py`) identified **two architectural defects** in `Modified14`'s `0x204` (`ExposureTime`) property list hook:

### 1.1 Primary Hardware Trigger: `+4`-Byte Dependency Context Shift in `0x10150602` (`pub_err = 1` -> All 120 `mtbl` Entries Disabled)
- In Stock `C3.80`, `0x114D3510` defines the 24-byte builder entry for property `0x204`:
  `{prop_id=0x204, flags=0, dep_desc=0x114CBA14, tv_grid_desc=0x114CF290, check_fn=0x101505C7, build_fn=0x10150603}`.
- Stock `0x114CBA14` (`46` entries at `0x114CB95C`) **already contained `0x204` at index `1`** (`[0x180C, 0x204, 0x4000030C, ...]`, with `0x0002` `ExposureMode` at index `24` / `ctx+0x60`, `0x020D` `ShutterMode` at index `29` / `ctx+0x74`, and `0x138D` `MovieMode` at index `41` / `ctx+0xA4`).
- `Modified14` (`tools/fw/z6_m600_tables.py:110`: `words47 = [words46[0], 0x204] + words46[1:]`) inserted a **duplicate `0x204` at index `1`**, shifting all 45 subsequent properties `ctx[1..45]` forward by `+4` bytes (`ctx[2..46]`):
  1. At `0x10150686` (`ldrb.w r0, [r4, #0x38]` with `r4 = ctx + 0x28`), `0x10150602` read `ctx + 0x60`, which in `Modified14` held `deps[23] = 0x565` (`0`) instead of `deps[24] = 0x0002` (`0x20` = M mode).
  2. `0x1015B69A` returned `r5 = 0` instead of `0x20`; at `0x10150858` (`cmp r5, #0x20; bne #0x1015087c`), execution branched to `0x1015087C: movs r3, #1` and published `0x204` via `0x1020931C` with **`pub_err = 1` (`disabled_flag = 1`)**.
  3. On every command-dial turn (`0x1012A752 -> 0x1012A68C -> ADDR_DIAL_PREREF -> 0x1012EC70 -> 0x1012D464`), `0x1012D4AC` (`ldrb r5, [r2, #0x14]; cbnz r5, #0x1012d4d0`) checked `0x204`'s `err` byte **before** checking `[r3, #4] == 0x7FFFFFFF`, jumping straight to `0x1012D4FE` for **every single row `0..119`** (`x200`, `Time`, `Bulb`, `600"..60"`, and `30"..1/8000s`).
  4. With `mtbl[0..119].enabled == [0]*120`, `0x1012A06E` could not step to any index and `0x1012A6EC` aborted `0x1012A68C` with zero `0x1015BEB6` property commits, locking the camera in its pre-flash NVRAM `Time` (`T` 门) state.

### 1.2 Secondary Latent Ceiling: `0x204` Global & Stack Capacity Is Strictly `109` Entries (`0x1B4` Bytes)
Even without the shifted `ctx` bug, `0x204` must never exceed `109` (`0x6D`) entries:
1. **Central Property Registration Table (`0xC18BD7C4[0]`, scatter-loaded from `0x11F52598`)**: registers `0x204` with `backing_buf = 0xC24C8B68` (immediately followed at `0xC24C8D1C` by `0x20B`, exact `0x1B4 = 436` bytes) and **`max_count = 109` (`0x6D`)**. `0x1020920E` (`0x10209240: cmp r1, r0; bhs`) rejects any publish with `count > 109` (`rc = 0`).
2. **Staging Buffer (`0x10150930`)**: `0xC236BEBC` is `0x1B4` bytes immediately preceding `0xC236C070` (the staging descriptor struct itself).
3. **Fixed `0x1B4`-Byte Stack Allocations Across `0x204`/`0x20B` Callers**: callers such as `0x1007109A`, `0x1012ED30`, `0x10169AAC`, `0x102FE7A8`, `0x1036B47A`, `0x1037B1F8`, `0x1042872C`, `0x10428878`, `0x1042ABA4`, and `0x10473792` allocate `0x1B4`-byte (`movw r2/r7, #0x1b4`) stack buffers for `0x204` (and `0x1012ECE6` / `0x1012EDB4` for `0x20B`).

---

## 2. `Modified15` (`z6_m600_v2.py`) Architectural Fix & Adversarial Review Hardening

`Modified15` keeps the internal `0x204` property builder (`0x10150602`), 46-entry dependency list (`0x114CBA14`), 109-entry Tv step-grid (`0x114CF290`), and all `0x1B4`-byte buffers **100% factory Stock** (`0x101508FD`, `0x1015093E`, and `0x114D3518` are untouched). Historical `Modified14` builder files (`z6_m600_*.py`) are left untouched so `Modified14` (`6d970609...`) remains bit-for-bit reproducible for negative-control auditing.

| Hook / Table Site | Target in Hole 1 / Hole 2 | Size | Exact Mechanism |
| --- | --- | ---: | --- |
| `0x1012D4B0` (`4B`) | `ADDR_MTBL_TV_GATE` (`0x1002F7C0`) | `64B` | Inside `0x1012D464`, when `r1 == 120` and `3 <= r4 < 11` (`600"..60"`), checks destination M-still eligibility (`[0xC24CC8FC] == 3` and `[0xC24CC980] == 0`) without gating on current `0x1319` (`0xC24CC790`), and substitutes `ip = -120` (`30"`) so `mtbl[3..10]` stay enabled even while currently in `Time` (`2`), `Bulb` (`1`), or `x200` (`3`). |
| `0x10209636` (`6B`) | `ADDR_PROP_ALLOW` (`0x1002F5F4`) | `84B` | In `0x10209636(prop_id, val, out_ptr)`, when `prop_id == 0x204` and `val` matches `-144..-224`, checks `[0xC24CC8FC] == 3` and `[0xC24CC980] == 0` (preserving `R2 = out_ptr` for `0x1020963E`), then delegates to Stock `0x204` check for `-120` (`30"`). Outside M-still, writes `*out_ptr = 0` so `0x10401684` snaps `-144..-224` to `-120` (`30"`). |
| `0x1012A6CC` (`4B`) & `0x1012A874` (`4B`) | `ADDR_DIAL_STEP_V2` (`0x1002FEA0`) & `ADDR_DIAL_BURST` (`0x1002F9E0`) | `104B` & `108B` | Steps smoothly across `x200(0) <-> Time(1) <-> Bulb(2) <-> 600"(3)..60"(10) <-> 30"(11)` (skipping `Bulb` cleanly if `mtbl[2].enabled == 0`), and tracks `[0xC1815D9C]` across `0x1012A68C` so slower bursts from `30"` stop at `60"` (`IDX_60S`), faster bursts from `>=60"` stop cleanly at `30"` (`IDX_30S`, never overshooting into sub-30s speeds), and bursts at the slow end stop at `600"`, `Bulb`, and `Time`. |
| `0x10331640` (`4B`), `0x10331D2A` (`4B`), `0x10331DAA` (`4B`) | `ADDR_PTP_GATE` (`0x10D32B00`) & `ADDR_PTP_ENUM` (`0x1002FE00`) | `84B` & `128B` | Uses unsigned `COND_LS` / `COND_HI` (`300,000 < val <= 6,000,000`) so `0xFFFFFFFF` (`Bulb`) and `0xFFFFFFFD` (`Time`) pass through untouched in all directions while gating `60"..600"` PTP writes and `0x200`-byte `GetDevicePropDesc` enum appends strictly to M-still mode. |
| `ADDR_STR_PTR_TBL - 16` (`0x10D317F0`) & `0x1041E546` (`4B`) | Relocated UI string table prefix + `ADDR_RANGE_3` (`0x1002FD60`) | `320B` & `24B` | Copies Stock's 16-byte pre-table string pointers (`[ADDR_STR_PTR_TBL - 4] = 0x11BA8D58`) so LV/EVF `0x1041E51C(ui_id = -1)` never dereferences `NULL` inside `0x1023B50C`, and checks `adds r0, r4, #1; beq 0x1041E584` + unsigned `COND_HI` in `ADDR_RANGE_3`. Active display resolvers (`ADDR_ACTIVE_UI` @ `0x1002F900`) continue to require `0x1319 == 0` (`[0xC24CC790] == 0`) with 32-bit scalar loads so `Bulb`/`Time`/`x200` labels are never overwritten by a stale `0x204` value. |

---

## 3. Verification Summary (`analysis/modified15-preflash-2026-11-15/`)

### 3.1 Modeled vs Native Boundaries in Unicorn (`z6_m600_v2_emu.py`, `z6_m600_v2_emu_e2e.py`)
- **Executed Natively from Read/Exec-Only ROM**:
  - Scalar property getters (`0x1015BEBE` / `0x104014DE` -> `0x1017039E` -> `0x100700A0`) reading 32-bit RAM slots initialized from ROM's `0x114D4FF8` table (cross-verified against native setter `0x10070366` and native `0x1319` builder `0x1014CD5A`).
  - `0x204` property builder (`0x10150602`), list publisher (`0x1020931C`), list getter (`0x102090DA` / `0x1015BEDA` / `0x10401668`), allowlist validator (`0x10209636` / `0x10401670` / `0x1034037C`), snap-to-nearest (`0x10401684`), M-table refresh (`0x1012EC70` -> `0x1012D464`), top-level command dial (`0x1012A752` -> `0x1012A68C` -> `0x1012A06E`), PTP setters/enums (`0x1033175C`, `0x10331992`, `0x10331D12`, `0x10331D92`), LV/EVF formatter (`0x1041E714` -> `0x1041E51C` -> ARM `0x1023B50C` `strncpy`), top-OLED BCD formatter, exposure timers (`0x101C486E`, `0x1011C14A`), and EXIF rational (`0x101C4790`).
- **Explicitly Modeled / Stubbed OS & Hardware Boundaries**:
  - RTOS mutexes (`0x10170DF0`/`DEA`), task sleep (`0x10170CCA`), heap alloc/free (`0x10164A44`/`A56`), event notify (`0x10117CDA`/`CD2`), synchronous scalar commit (`0x1015BEB6` / `0x10401630` writing 32-bit RAM slots and synchronizing derived `0x1319`), dial permission (`0x101308C2` returning `1`), LV glyph rasterizer (`0x1041DF0C`), and PTP post-commit hardware readback pollers (`0x10331506` / `0x1033146C`). Full asynchronous RTOS mode-dial state-machine propagation is **not** modeled offline; non-M-still isolation is verified at the `0x1012EC70`, `0x10209636`, `0x10401684`, `0x100DAD66`, `ADDR_ACTIVE_UI`, and PTP setter/enum layers (note also that S-mode uses `0x208`/`0x206` and Movie uses `0x20B`, separate from M-mode's `0x204`).

### 3.2 Key Quantitative Results
1. **Deterministic Dual-Build & Rollback (`prepare_modified15_lab.py`)**:
   - Direct build from Stock `C3.80` and incremental build from `Modified13` produce identical `33,502,842`-byte images (`SHA-256 = 0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c`, `CRC16 = 0xa0c5`); exact inverse rollbacks restore `Modified13` and Stock `C3.80` bit-for-bit; `verify_modified14_kit.py` continues to pass on historical `Modified14`.
2. **Coherent Dial, Burst, Sentinel, & PTP Matrix (`native-probe/native_report.json`)**:
   - **Negative Control (`Modified14`)**: `dep_count = 47`, `pub_err = 1`, `enabled_mtbl_entries = 0/120`, `0` dial commits from `Time`; `117`-entry publish to `0x204` returns `0`.
   - **`Modified15` Coherent Dial & Burst Across `1/3 EV` (`55`), `1/2 EV` (`37`), `1 EV` (`19`)**: starting from `Time` (`0x20D = 2`, `0x1319 = 2`), steps cleanly through `Time(1) <-> Bulb(2) <-> 600"(3)..60"(10) <-> 30"(11) <-> above-30"` and down to `x200(0)` and back; slower (`r0 = 0`) multi-click Fn bursts stop at `30" -> 60"`, `600"`, `Bulb`, and `Time`, while faster (`r0 = 2`) bursts from `>=60"` stop at `30"` (`1/3` & `1/2 EV`, or `60"` for a 1-click `90" -> 60"` step in `1 EV`) without overshooting past `30"`.
   - **LV/EVF `ui_id = -1` Sentinel & `600"`**: `0x1041E714 -> 0x1041E51C(-1)` executes native ARM `0x1023B50C` (`[0x10D317FC] = 0x11BA8D58`) without `NULL` read and returns via `0x1041E584` with `0` draw calls; active `600"` (`ui_id = 74`) copies `'600"'` and draws cleanly.
   - **PTP Setters & Enums**: `1/3 EV` M-still enum counts are `[63, 66]` (`0x500D`, `0xD100`) vs `[55, 58]` in A-mode (`0` canary corruption beyond `0x200` bytes). Full source/destination state matrix (`Timed` / `Bulb` / `Time` / `x200` -> `Bulb` / `Time` / `30"` / `60"` / `600"`) succeeds (`0x2001`) on both `0x1033175C` and `0x10331992` in M-still and rejects `60"`/`600"` (`0x201C`) in A, S, and Movie modes.
   - **Inherited `Modified13` Astro RAW Controls**: `0x10122CA2` (four `0x1000` / `4096` unity coefficients across `20` packaged probe cases + `512` independent review cases, plus NULL-pointer safety) and `0x1011E2CE` (`CAL33` Group 4 across still ISOs, Group 0 in movie) match `Modified13` identically.
3. **Updater & Scheduler Audit (`updater-audit/result.json`)**:
   - `11/11` file discovery/integrity/component prechecks passed (including `modified14 -> modified15` direct upgrade, rollbacks, `bad_crc`, `wrong_filename` using `EG172080.BIN`, and `oversize` rejections) and `7/7` flash scheduler passes completed as expected.

---

## 4. Residual Risks & Real-Camera Validation Gate

Offline emulation does **not** prove physical NOR-flash power-loss recovery, live RTOS asynchronous mode-transition behavior, or physical shutter curtain / sensor dark-current behavior over 600s. Real-camera verification on the user's Z6 should confirm:
1. Direct firmware upgrade `Modified14 -> Modified15` completes normally via Setup -> Firmware version -> Update.
2. Starting from `Time` (`T` 门) in M-still mode, rotating the main command dial steps smoothly through `Time <-> Bulb <-> 600" .. 60" <-> 30" .. 1/8000s` (and Fn bursts stop cleanly at `30"`), with matching rear LCD, EVF, and top-OLED labels.
3. A `60"` M-still dark/cap exposure runs for ~60 seconds wall-clock and records `ExposureTime = 60 s` in NEF EXIF, while `A/S/P` and Movie modes expose and execute no shutter speed slower than `30"`.

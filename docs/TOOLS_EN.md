# Tools & Reproducible Build Guide

> 🌐 **Language / 语言**: **[简体中文](TOOLS.md)** | **English** · 🏠 [Back to Main README](../README_EN.md)

All core firmware building, container unpacking, and repository hygiene tools in this repository are written using the **Python 3.10+ standard library only**. They run directly from the repository root without connecting to a camera, never touch hardware directly, and bundle zero proprietary binaries or precomputed third-party XOR tables in the Git source tree.

> [!TIP]
> If you just want to flash your camera without running the builder, download the pre-packaged [`Nikon-Z6-C380-Modified24-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified24/Nikon-Z6-C380-Modified24-Astro-Firmware.zip) directly from **[GitHub Releases (`v3.80-modified24`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified24)** and run `python verify.py` inside the extracted folder to verify all checksums and patch invariants offline.

---

## 1. Reproducible Firmware Build & Integrity Verification (For All Users)

Pass your legally obtained official Nikon Z6 C3.80 firmware file `Z_6_0380.bin` (SHA-256: `ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54`) to the standalone builder to reproduce the exact same directory and deterministic `.zip` archive published on GitHub Releases:

```powershell
# Build and package deterministic .zip archive (Python 3.10+ standard library only)
python tools/build_modified24.py --stock path\to\Z_6_0380.bin --output-dir outputs\Nikon-Z6-C380-Modified24-Astro-Firmware --zip

# Run standalone read-only verification on a built or extracted kit (size, SHA-256, CRC-16/XMODEM, all 112 patch opcode invariants)
python tools/build_modified24.py --verify outputs\Nikon-Z6-C380-Modified24-Astro-Firmware
```

If you have the optional disassembly verifier installed (`pip install capstone`), pass `--rebuild-from-source` to re-emit every Thumb assembly patch from the source generators in `tools/fw/` and cross-check byte-for-byte against the pinned [`patches/z6-c380-modified24-astro-raw-red-srgb-600s.json`](../patches/z6-c380-modified24-astro-raw-red-srgb-600s.json):

```powershell
python tools/build_modified24.py --stock path\to\Z_6_0380.bin --rebuild-from-source --force
```

---

## 2. Core Public Modules

| Script Path | Dependencies | Purpose |
| :--- | :--- | :--- |
| [`tools/build_modified24.py`](../tools/build_modified24.py) | Python 3.10+ stdlib (optional `capstone` for `--rebuild-from-source`) | Unpacks official `Z_6_0380.bin`, verifies ROM property table slots (`PID 0x0526`, `PID 0x1111`, `PID 0x130A`), applies 112 patch spans (14 Astro RAW & hardware bit-packer hooks, `PID 0x0526` UI switch, 7 `PID 0x1111` VGC Channel 1 Night Vision Red hooks, post-exposure interval timer, and `60"~600"` M-mode shutter speeds), recomputes CRC-16/XMODEM (`0x8799`), proves exact byte-reversal back to Stock C3.80, and atomically stages `01_MODIFIED24/EG162080.BIN` + `02_STOCK_C380_ROLLBACK/EG162080.BIN` (plus deterministic `--zip`) |
| [`tools/fw/z6_night_vision_red.py`](../tools/fw/z6_night_vision_red.py) / [`prepare_modified24_lab.py`](../tools/fw/prepare_modified24_lab.py) | Python 3.10+ stdlib, `capstone` | Emits the Night Vision Red code cave (`0x1002E1B0`), 36-language UTF-16LE string pool, and all 112 firmware edits directly from Thumb assembly generators, running instruction-boundary, branch-target, and cave-capacity audits |
| [`tools/fw/package_modified24_kit.py`](../tools/fw/package_modified24_kit.py) / [`verify_modified24_kit.py`](../tools/fw/verify_modified24_kit.py) | Python 3.10+ stdlib | Multi-slot (2/3/4/7-slot) researcher kit staging and independent offline multi-invariant verification utilities |
| [`tools/fw/probe_modified24_native.py`](../tools/fw/probe_modified24_native.py) | `unicorn`, `capstone`, `numpy` (optional `rawpy` when `samples/` is present) | Runs offline native ARM/Thumb verification on a clean clone from `Z_6_0380.bin` alone (26 VGC CSC channel-isolation cases, 12 hardware grid cases, 648 36-language UI string checks, 437 categorized RAW pipeline cases, 28 `0x100A34D0` register/NZCV checks, and 24.5 MP software packing round-trip) |
| [`tools/fw/probe_modified24_updater.py`](../tools/fw/probe_modified24_updater.py) / [`qemu_modified24_probe.py`](../tools/fw/qemu_modified24_probe.py) | `unicorn` / WSL `z6-qemu` | Runs 7 single-module camera updater file checks + 5 offline flash-scheduler passes, plus full-machine QEMU LiveView/Menu/Playback & red-grid framebuffer verification |
| [`tools/fw/z6_c380_container.py`](../tools/fw/z6_c380_container.py) | Python 3.10+ stdlib | Dynamically recovers the **three 256-byte XOR mask tables (column, row, block)** at runtime from structural zero-padding offsets ([`tools/fw/z6_c380_zero_samples.json`](../tools/fw/z6_c380_zero_samples.json)) inside the user's `Z_6_0380.bin` via spanning-tree differential recovery, extracting `eg1620_038000.bi` |
| [`tools/verify_repo_hygiene.py`](../tools/verify_repo_hygiene.py) | Python 3.10+ stdlib + `git` | Automated public repository gate: checks `.gitignore` tracking compliance, forbidden directories/extensions, file size caps, host-path sanitization, UTF-8/JSON validity, Markdown relative links, LaTeX escaping, evidence-to-doc numerical consistency, and (`--check-history`) full Git commit tree history |
| [`tools/analyze_z6.py`](../tools/analyze_z6.py) | Python 3.10+ stdlib | Statically parses official `Z_6_0380.bin`, extracts decoded modules via `z6_c380_container.py`, and writes a local static analysis summary |
| [`tools/evidence/build_sample_catalog.py`](../tools/evidence/build_sample_catalog.py) | `numpy`, `rawpy` | Regenerates the 130-frame [`docs/SAMPLE_EVIDENCE_CATALOG.json`](../docs/SAMPLE_EVIDENCE_CATALOG.json) when local `samples/` NEF archives are present |
| [`tools/evidence/build_m23_audit_metrics.py`](../tools/evidence/build_m23_audit_metrics.py) | `numpy`, `rawpy` | Recomputes [`docs/evidence/m23_audit_metrics.json`](../docs/evidence/m23_audit_metrics.json) full-frame `packed-14` parity, row-band continuity, frozen-112 hot-pixel retention, and pairwise dark noise metrics from local `samples/` |

Run the repository hygiene & consistency gate locally:

```powershell
python tools/verify_repo_hygiene.py --check-history
```

---

## 3. Historical Release & Research Scripts (Reproducibility Archive)

`tools/`, `tools/fw/`, and `tools/evidence/` also retain reproducible builders for earlier public releases ([`tools/build_modified23.py`](../tools/build_modified23.py), [`tools/build_modified22.py`](../tools/build_modified22.py), [`tools/evidence/build_m22_audit_metrics.py`](../tools/evidence/build_m22_audit_metrics.py)) alongside Unicorn/QEMU exploratory scripts from earlier research stages (see [`CHANGELOG_EN.md`](CHANGELOG_EN.md)).

> [!NOTE]
> Directories referenced by historical exploratory scripts (`outputs/`, `analysis/`, `references/`, `manifests/`, `work/`) are local laboratory caches excluded by [`.gitignore`](../.gitignore) and [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md); building or verifying the current production firmware requires only `tools/build_modified24.py`.

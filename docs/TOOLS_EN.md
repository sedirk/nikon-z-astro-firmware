# Tools & Reproducible Build Guide

> 🌐 **Language / 语言**: **[简体中文](TOOLS.md)** | **English** · 🏠 [Back to Main README](../README_EN.md)

All core firmware building, container unpacking, and repository hygiene tools in this repository are written using the **Python 3.10+ standard library only**. They run directly from the repository root without connecting to a camera, never touch hardware directly, and bundle zero proprietary binaries or precomputed third-party XOR tables in the Git source tree.

> [!TIP]
> If you just want to flash your camera without running the builder, download the pre-packaged [`Nikon-Z6-C380-Modified22-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified22/Nikon-Z6-C380-Modified22-Astro-Firmware.zip) directly from **[GitHub Releases (`v3.80-modified22`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified22)** and run `python verify.py` inside the extracted folder to verify all checksums and patch invariants offline.

---

## 1. Reproducible Firmware Build & Integrity Verification (For All Users)

Pass your legally obtained official Nikon Z6 C3.80 firmware file `Z_6_0380.bin` (SHA-256: `ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54`) to the standalone builder to reproduce the exact same directory and deterministic `.zip` archive published on GitHub Releases:

```powershell
# Build and package deterministic .zip archive (Python 3.10+ standard library only)
python tools/build_modified22.py --stock path\to\Z_6_0380.bin --output-dir outputs\Nikon-Z6-C380-Modified22-Astro-Firmware --zip

# Run standalone read-only verification on a built or extracted kit (size, SHA-256, CRC-16/XMODEM, PID 0x0526 / 0x130A opcode invariants)
python tools/build_modified22.py --verify outputs\Nikon-Z6-C380-Modified22-Astro-Firmware
```

If you have the optional disassembly verifier installed (`pip install capstone`), pass `--rebuild-from-source` to re-emit every Thumb assembly patch from the source generators in `tools/fw/` and cross-check byte-for-byte against the pinned [`patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json`](../patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json):

```powershell
python tools/build_modified22.py --stock path\to\Z_6_0380.bin --rebuild-from-source --force
```

---

## 2. Core Public Modules

| Script Path | Dependencies | Purpose |
| :--- | :--- | :--- |
| [`tools/build_modified22.py`](../tools/build_modified22.py) | Python 3.10+ stdlib (optional `capstone` for `--rebuild-from-source`) | Unpacks official `Z_6_0380.bin`, verifies ROM property table slots, applies 104 patch spans, recomputes CRC-16/XMODEM, proves exact byte-reversal back to Stock C3.80, and atomically stages `01_MODIFIED22/EG162080.BIN` + `02_STOCK_C380_ROLLBACK/EG162080.BIN` (plus deterministic `--zip`) |
| [`tools/fw/z6_c380_container.py`](../tools/fw/z6_c380_container.py) | Python 3.10+ stdlib | Dynamically recovers the **three 256-byte XOR mask tables (column, row, block)** at runtime from structural zero-padding offsets ([`tools/fw/z6_c380_zero_samples.json`](../tools/fw/z6_c380_zero_samples.json)) inside the user's `Z_6_0380.bin` via spanning-tree differential recovery, extracting `eg1620_038000.bi` |
| [`tools/verify_repo_hygiene.py`](../tools/verify_repo_hygiene.py) | Python 3.10+ stdlib + `git` | Automated public repository gate: checks `.gitignore` tracking compliance, forbidden directories/extensions, file size caps, host-path sanitization, UTF-8/JSON validity, Markdown relative links, LaTeX escaping, evidence-to-doc numerical consistency, and (`--check-history`) full Git commit tree history |
| [`tools/analyze_z6.py`](../tools/analyze_z6.py) | Python 3.10+ stdlib | Statically parses official `Z_6_0380.bin`, extracts decoded modules via `z6_c380_container.py`, and writes a local static analysis summary |
| [`tools/evidence/build_sample_catalog.py`](../tools/evidence/build_sample_catalog.py) | `numpy`, `rawpy` | Regenerates [`docs/SAMPLE_EVIDENCE_CATALOG.json`](../docs/SAMPLE_EVIDENCE_CATALOG.json) when local `samples/` NEF archives are present |
| [`tools/evidence/build_m22_audit_metrics.py`](../tools/evidence/build_m22_audit_metrics.py) | `numpy`, `rawpy` | Recomputes [`docs/evidence/m22_audit_metrics.json`](../docs/evidence/m22_audit_metrics.json) flat-field FFT spectra, bias readout noise, and frozen-112 dark metrics from local `samples/` |

Run the repository hygiene & consistency gate locally:

```powershell
python tools/verify_repo_hygiene.py
```

---

## 3. Historical Research Scripts (Archive Context)

`tools/` and `tools/fw/` retain exploratory probing, Unicorn/QEMU replay, and archival scripts used during earlier `Modified1` – `Modified21` reverse-engineering phases (such as `tools/archive_sources.py`, `tools/archive_research_update.py`, `tools/build_evidence.py`, `tools/verify_project.py`, `tools/organize_files.ps1`, etc.).

> [!NOTE]
> Directories referenced by those historical scripts (`outputs/`, `analysis/`, `references/`, `manifests/`, `work/`) are local laboratory caches excluded by [`.gitignore`](../.gitignore) and [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md); they are never needed for building or verifying `Modified22`.

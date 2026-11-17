# Third-Party Notices & Licensing

> 🌐 **Language / 语言**: **[简体中文 (README)](README.md)** | **[English (README_EN)](README_EN.md)**

Original software, patch recipes, build/verification scripts, and technical documentation in this repository are licensed under the **GNU General Public License v3.0 or later (`SPDX-License-Identifier: GPL-3.0-or-later`)**.

Third-party reference projects, mathematical format specifications, and proprietary camera firmware remain under the copyrights and licenses of their respective owners and are **not** relicensed by the root [LICENSE](LICENSE) file.

---

## 1. Project Copyright & License Scope

**Nikon Z6 Astro Firmware Enhancement (`Modified22`)**  
Copyright (C) 2026 SEDIRK and contributors.  
SPDX-License-Identifier: `GPL-3.0-or-later`

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the verbatim [LICENSE](LICENSE) file for the full text of the GNU General Public License v3.0.

**Covered Original Material**:
- Standalone clean-room build & verification tools (`tools/build_modified22.py`, `tools/verify_repo_hygiene.py`, `tools/fw/*`, `tools/evidence/*`);
- Patch recipes (`patches/*.json`), quantitative audit datasets (`docs/evidence/*.json`, `docs/SAMPLE_EVIDENCE_CATALOG.json`), and project documentation (`README.md`, `docs/**`).

---

## 2. Included Adapted Open-Source Method (MIT License)

### 2.1 Z30 Firmware Extensions (`RealCaCl2/z30-firmware-extensions`)
- **Affected File**: `tools/fw/z6_c380_container.py` (spanning-tree known-zero offset XOR mask recovery algorithm, adapted to Nikon Z6 C3.80 structural padding offsets in `tools/fw/z6_c380_zero_samples.json`).
- **Upstream Repository**: https://github.com/RealCaCl2/z30-firmware-extensions (reference commit `59ec38699ba248419508be85ae60e2a61b0b26fc`).
- **Upstream License**: MIT License (permissive, compatible with `GPL-3.0-or-later`; excludes the four upstream sound files governed by WLCL, which are neither used nor distributed here).
- **Required MIT Copyright & Permission Notice**:

```text
MIT License

Copyright (c) 2026 Z30 Firmware Extensions contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 3. Research Citations & Non-Distributed Upstream Projects

The following external projects and literature informed historical reverse-engineering research. Their source repositories, web pages, and binaries are excluded from this public repository (`.gitignore` excludes `references/`):

### 3.1 Wonder-Lantern & Camera QEMU Simulators (`z6-qemu` / `z7-qemu` / `z9-qemu`)
- **References**: https://github.com/WonderLantern / https://github.com/vic2349/Wonder-Lantern
- **Upstream Licenses**:
  - Camera QEMU emulation repositories (`z6-qemu`, `z7-qemu`, `z9-qemu`): **GNU General Public License v2.0 (`GPL-2.0-only` / `GPL-2.0-or-later`)** and **LGPL-2.1-or-later**, Copyright (C) Fabrice Bellard, the QEMU Project contributors, and respective camera simulator contributors.
  - Wonder-Lantern custom shutter-sound repository: **Wonder-Lantern Community License (WLCL)**, Copyright (C) 2026 Wonder Lantern contributors (non-commercial restriction).
- **Boundary Statement**: No Wonder-Lantern WLCL code, audio assets, or QEMU source archives are linked into or distributed with this project. All `Modified22` ARM/Thumb ISP hooks, property-table gates, 600s shutter tables, and interval-timer routines were independently developed.

### 3.2 Nikon Hacker Community (`nikon-firmware-tools` / `Nikon-Patch`)
- **References**: https://simeonpilgrim.com/nikon-patch/nikon-patch.html / https://github.com/simeonpilgrim/nikon-firmware-tools
- **Boundary Statement**: Historical DSLR dark-current research and container documentation served as background literature. `tools/build_modified22.py` and `tools/analyze_z6.py` use the clean-room `z6_c380_container.py` mask-recovery module and do **not** read, import, or redistribute `FirmwareUtils.java` or `FirmwareDecoder.java`.

### 3.3 Mark Shelley Astrophotography Research
- **References**: https://www.markshelley.co.uk/Astronomy/concentric_ring_diagnosis.html and related articles listed in [docs/SOURCES.md](docs/SOURCES.md).
- **Boundary Statement**: Cited as scientific literature for histogram comb and flat-field concentric ring diagnostics. Full HTML articles remain copyright Mark Shelley and are not redistributed in the public tree.

---

## 4. Trademark & Proprietary Firmware Disclaimer

- **Trademarks**: "Nikon", "NIKKOR", "Z6", and "EXPEED" are registered trademarks of Nikon Corporation. This project is an independent open-source research initiative and is **neither affiliated with, sponsored by, nor endorsed by Nikon Corporation**.
- **Source Tree Hygiene & Firmware Releases**: Proprietary firmware binaries (`Z_6_0380.bin`, `eg1620_038000.bi`, `EG162080.BIN`), ROM images, and camera-extracted calibration dumps (`CAL38`, `ID35`) are excluded from the Git source tree via `.gitignore` and `tools/verify_repo_hygiene.py`. Pre-built `Modified22` flash kits attached to GitHub Releases are derived from official Nikon Z6 firmware C3.80 (`Z_6_0380.bin`); Nikon's underlying base firmware remains proprietary to Nikon Corporation, while this project's original patch recipes, clean-room builders, and verification tools are licensed under `GPL-3.0-or-later`.
- **Reproducible Local Build**: Users may either download the pre-packaged flash kit from [GitHub Releases](https://github.com/sedirk/nikon-z-astro-firmware/releases) or obtain official `Z_6_0380.bin` directly from [Nikon Download Center](https://downloadcenter.nikonimglib.com/en/download/fw/557.html) and reproduce the identical `EG162080.BIN` locally via `tools/build_modified22.py`.

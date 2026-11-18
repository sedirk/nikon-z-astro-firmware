#!/usr/bin/env python3
"""Automated repository hygiene, licensing, privacy, and documentation gate.

Verifies that the public Nikon Z6 C3.80 Astro Firmware (`Modified23`) repository tree:
  1. Contains zero `.gitignore`-violating tracked files, proprietary firmware binaries,
     camera dumps, raw NEF files, or non-redistributable `references/` snapshots;
  2. Respects clean-room mask recovery boundaries (`z6_c380_container.py` without
     third-party `FirmwareDecoder.java` / `FirmwareUtils.java` imports or static XOR tables);
  3. Leaks zero host-specific paths, session scratch paths, or private personal emails
     across all public text files and Git commit metadata;
  4. Has 100% valid UTF-8 text files, valid JSON recipes/catalogs, zero broken or
     ignored-target Markdown links, and zero double-escaped LaTeX sequences;
  5. Cross-verifies quantitative claims in Markdown audit/technical reports against
     committed JSON evidence (`SAMPLE_EVIDENCE_CATALOG.json`, `m22_audit_metrics.json`, `m23_audit_metrics.json`);
  6. (With `--check-history`) Enumerates every reachable commit tree's full path set
     (independent of blob deduplication) plus all historical blobs and commit emails.

SPDX-License-Identifier: GPL-3.0-or-later
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("verify_repo_hygiene.py must not be executed with Python -O/-OO.")

import argparse
import ast
import json
from pathlib import Path
import re
import subprocess
import sys
REPO_ROOT = Path(__file__).resolve().parents[1]

MAX_PUBLIC_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB ceiling per public file

FORBIDDEN_DIR_PREFIXES = (
    "firmware/original/",
    "firmware/decoded/",
    "references/",
    "analysis/",
    "outputs/",
    "logs/",
    "work/",
    "manifests/",
    ".venv/",
    "venv/",
)

FORBIDDEN_EXTENSIONS = {
    ".bin",
    ".bi",
    ".nef",
    ".dmp",
    ".raw",
    ".lab",
    ".recalled",
    ".npz",
    ".zip",
    ".7z",
    ".tar",
    ".gz",
    ".exe",
    ".dll",
    ".pyc",
    ".pyo",
    ".pyd",
}

BINARY_ASSET_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".svg",
    ".pdf",
}

SENSITIVE_PATH_RE = re.compile(
    r"(Project_SEDIRK|Users[/\\]+sedirk|\.pi-desktop|antigravity-acp|START_HERE_另一台电脑|sedirk@outlook\.com)",
    re.IGNORECASE,
)

MARKDOWN_LINK_RE = re.compile(r"!?\[([^\]]*)\]\(([^)]+)\)")
DOUBLE_ESCAPED_LATEX_RE = re.compile(
    r"\\\\(text|times|sim|approx|frac|mu|sigma|ge|le|cdot|pm|Delta|alpha|beta)\b"
)

REQUIRED_ROOT_FILES = (
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "README.md",
    "README_EN.md",
    ".gitignore",
    "tools/build_modified22.py",
    "tools/build_modified23.py",
    "tools/verify_repo_hygiene.py",
    "tools/fw/z6_c380_container.py",
    "tools/fw/z6_c380_zero_samples.json",
    "tools/fw/prepare_modified23_lab.py",
    "tools/fw/package_modified23_kit.py",
    "tools/fw/verify_modified23_kit.py",
    "tools/fw/probe_modified23_native.py",
    "tools/fw/probe_modified23_updater.py",
    "tools/evidence/nef_evidence_lib.py",
    "tools/evidence/build_m23_audit_metrics.py",
    "patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json",
    "patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json",
    "docs/README.md",
    "docs/README_EN.md",
    "docs/CHANGELOG.md",
    "docs/CHANGELOG_EN.md",
    "docs/TOOLS.md",
    "docs/TOOLS_EN.md",
    "docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md",
    "docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md",
    "docs/02_STAR_EATER_AND_DARK_CURRENT.md",
    "docs/02_STAR_EATER_AND_DARK_CURRENT_EN.md",
    "docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md",
    "docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md",
    "docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md",
    "docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md",
    "docs/SAMPLE_EVIDENCE_CATALOG.json",
    "docs/evidence/m22_audit_metrics.json",
    "docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md",
    "docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md",
    "docs/evidence/probe_modified23_native_result.json",
    "docs/evidence/modified23_updater_audit.json",
    "docs/evidence/m23_audit_metrics.json",
    "docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md",
    "docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md",
)

BILINGUAL_DOC_PAIRS = (
    ("README.md", "README_EN.md", "README_EN.md", "README.md"),
    ("docs/README.md", "docs/README_EN.md", "README_EN.md", "README.md"),
    ("docs/TOOLS.md", "docs/TOOLS_EN.md", "TOOLS_EN.md", "TOOLS.md"),
    (
        "docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md",
        "docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md",
        "01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md",
        "01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md",
    ),
    (
        "docs/02_STAR_EATER_AND_DARK_CURRENT.md",
        "docs/02_STAR_EATER_AND_DARK_CURRENT_EN.md",
        "02_STAR_EATER_AND_DARK_CURRENT_EN.md",
        "02_STAR_EATER_AND_DARK_CURRENT.md",
    ),
    (
        "docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md",
        "docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md",
        "03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md",
        "03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md",
    ),
    (
        "docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md",
        "docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md",
        "04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md",
        "04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md",
    ),
    (
        "docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md",
        "docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md",
        "MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md",
        "MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md",
    ),
    (
        "docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md",
        "docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md",
        "MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md",
        "MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md",
    ),
    (
        "docs/CHANGELOG.md",
        "docs/CHANGELOG_EN.md",
        "CHANGELOG_EN.md",
        "CHANGELOG.md",
    ),
)

EXPECTED_RELEASE_ZIP_SIZE_TOKEN = "29,320,565"
EXPECTED_RELEASE_ZIP_SHA256 = "1aae77b798f2768ef873d256108758d0a097537632d8fb531c04ca26c29d818e"


def _git_lines(*args: str, cwd: Path = REPO_ROOT) -> list[str]:
    out = subprocess.check_output(
        ["git", "-c", "core.quotePath=false", *args],
        cwd=cwd,
    )
    return [line for line in out.decode("utf-8", errors="replace").splitlines() if line]


def collect_public_files(repo: Path, tracked_only: bool = False) -> tuple[list[str], list[str]]:
    tracked = set(_git_lines("ls-files", cwd=repo))
    ignored_tracked = sorted(_git_lines("ls-files", "-i", "-c", "--exclude-standard", cwd=repo))
    if tracked_only:
        public = sorted(tracked)
    else:
        untracked_public = set(_git_lines("ls-files", "--others", "--exclude-standard", cwd=repo))
        public = sorted((tracked - set(ignored_tracked)) | untracked_public)
    return public, ignored_tracked


def check_clean_room_tools(repo: Path, errors: list[str]) -> None:
    m23_hardened_scripts = (
        "tools/build_modified23.py",
        "tools/fw/prepare_modified23_lab.py",
        "tools/fw/package_modified23_kit.py",
        "tools/fw/verify_modified23_kit.py",
        "tools/fw/probe_modified23_native.py",
        "tools/fw/probe_modified23_updater.py",
        "tools/evidence/build_m23_audit_metrics.py",
    )
    clean_room_targets = [
        "tools/build_modified22.py",
        *m23_hardened_scripts,
        "tools/fw/z6_c380_container.py",
        "tools/analyze_z6.py",
    ]
    forbidden_tokens = ("FirmwareDecoder", "FirmwareUtils", "references/")
    for rel in clean_room_targets:
        p = repo / rel
        if not p.is_file():
            errors.append(f"Missing required clean-room module: {rel}")
            continue
        text = p.read_text(encoding="utf-8")
        for tok in forbidden_tokens:
            if tok in text:
                errors.append(f"Clean-room boundary violation in {rel}: contains '{tok}'")

    for rel in (*m23_hardened_scripts, "tools/verify_repo_hygiene.py"):
        p = repo / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8")
        if "if not __debug__:" not in text:
            errors.append(f"Missing Python -O/__debug__ rejection guard in {rel}")
        tree = ast.parse(text, filename=rel)
        assert_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        if assert_nodes:
            errors.append(f"Optimization-strippable assert statement(s) found in {rel}: {len(assert_nodes)}")

def check_markdown_file(
    rel: str, text: str, repo: Path, public_set: set[str], errors: list[str]
) -> None:
    file_path = repo / rel
    in_fence = False
    fence_marker = ""
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            marker = stripped[:3]
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif stripped.startswith(fence_marker):
                in_fence = False
            continue
        if in_fence:
            continue

        if DOUBLE_ESCAPED_LATEX_RE.search(line):
            errors.append(f"Double-escaped LaTeX command in {rel}:{line_no}: {line.strip()[:120]}")

        # Mask inline code spans (`...`) before scanning Markdown links
        masked_line = re.sub(r"`[^`]*`", "", line)
        for m in MARKDOWN_LINK_RE.finditer(masked_line):
            raw_target = m.group(2).strip()
            if raw_target.startswith("<") and raw_target.endswith(">"):
                raw_target = raw_target[1:-1].strip()
            if not raw_target or raw_target.startswith(("http://", "https://", "mailto:", "#", "data:")):
                continue
            target = raw_target.split()[0] if (" " in raw_target and not raw_target.startswith("http")) else raw_target
            target_path_str = target.split("#", 1)[0]
            if not re.match(r"^[A-Za-z]:", target_path_str):
                target_path_str = target_path_str.split(":", 1)[0]
            if not target_path_str:
                continue

            if re.match(r"^(file|vscode)://", raw_target, re.IGNORECASE):
                errors.append(f"Non-portable URI scheme in {rel}:{line_no}: {raw_target}")
                continue

            resolved = (file_path.parent / target_path_str).resolve()
            try:
                rel_target = resolved.relative_to(repo.resolve()).as_posix()
            except ValueError:
                errors.append(f"Link escapes repository root in {rel}:{line_no}: {raw_target}")
                continue

            if rel_target not in public_set:
                dir_prefix = rel_target.rstrip("/") + "/"
                if not any(f.startswith(dir_prefix) for f in public_set):
                    errors.append(
                        f"Broken or non-public Markdown link in {rel}:{line_no}: "
                        f"'{raw_target}' -> '{rel_target}'"
                    )
    if in_fence:
        errors.append(f"Unclosed fenced code block in {rel}")


def _check_forbidden_path(rel: str, scope_label: str, errors: list[str]) -> None:
    if any(rel.startswith(pref) for pref in FORBIDDEN_DIR_PREFIXES):
        errors.append(f"{scope_label} in forbidden directory: {rel}")
    if rel.startswith("samples/") and rel != "samples/README.md":
        errors.append(f"{scope_label} under samples/: {rel}")
    ext = Path(rel).suffix.lower()
    if ext in FORBIDDEN_EXTENSIONS:
        errors.append(f"{scope_label} with forbidden extension ({ext}): {rel}")
    if Path(rel).name.startswith("START_HERE"):
        errors.append(f"{scope_label} local handoff note: {rel}")


def check_git_history(repo: Path, errors: list[str]) -> dict[str, int]:
    # 1. Check all reachable commit emails for private address leaks
    commit_meta = _git_lines("log", "--format=%H%x09%ae%x09%ce", "HEAD", cwd=repo)
    for entry in commit_meta:
        parts = entry.split("\t")
        sha = parts[0][:12]
        for email in parts[1:]:
            if SENSITIVE_PATH_RE.search(email):
                errors.append(f"Private email leak in commit {sha} metadata: {email}")

    # 2. Enumerate EVERY path in EVERY reachable commit's root tree (no blob deduplication)
    unique_trees = sorted(set(_git_lines("log", "--format=%T", "HEAD", cwd=repo)))
    seen_tree_paths: set[str] = set()
    for tree_sha in unique_trees:
        raw_paths = subprocess.check_output(
            ["git", "-c", "core.quotePath=false", "ls-tree", "-r", "--full-tree", "--name-only", "-z", tree_sha],
            cwd=repo,
        )
        for raw_p in raw_paths.split(b"\x00"):
            if raw_p:
                seen_tree_paths.add(raw_p.decode("utf-8", errors="replace"))

    for rel in sorted(seen_tree_paths):
        _check_forbidden_path(rel, "Historical tree entry", errors)

    # 3. Check all reachable blob sizes via rev-list --objects (deduplicated content size check)
    rev_objects = _git_lines("rev-list", "--objects", "HEAD", cwd=repo)
    proc = subprocess.run(
        ["git", "cat-file", "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)"],
        input=("\n".join(rev_objects) + "\n").encode("utf-8"),
        cwd=repo,
        capture_output=True,
        check=True,
    )
    blob_count = 0
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        parts = line.split(" ", 3)
        if len(parts) < 4 or parts[0] != "blob":
            continue
        blob_count += 1
        size = int(parts[2])
        rel = parts[3]
        if size > MAX_PUBLIC_FILE_BYTES:
            errors.append(f"Historical blob exceeds size cap ({size} B): {rel} ({parts[1][:12]})")
    return {
        "commits": len(commit_meta),
        "trees": len(unique_trees),
        "tree_paths": len(seen_tree_paths),
        "blobs": blob_count,
    }


def _strip_md_num(cell: str) -> float:
    cleaned = cell.replace("*", "").replace("`", "").replace(",", "").replace("DN", "").strip()
    return float(cleaned)


def _check_audit_markdown(
    audit_md_path: Path,
    label: str,
    cat_by_rel: dict[str, dict],
    b_per_file: dict[str, dict],
    noise_by_mode: dict[str, dict],
    expected_audit_tokens: list[str],
    errors: list[str],
) -> int:
    checks = 0
    audit_text = audit_md_path.read_text(encoding="utf-8")
    row_re = re.compile(r"^\|\s*`(Z61_\d+\.NEF)`\s*\|(.+)\|$")
    seen_table_files: set[str] = set()
    for line_no, line in enumerate(audit_text.splitlines(), 1):
        m = row_re.match(line.strip())
        if not m:
            continue
        fname = m.group(1)
        cols = [c.strip() for c in m.group(2).split("|")]
        if len(cols) != 9:
            errors.append(f"Unexpected column count in {label} table line {line_no}: {len(cols)}")
            continue
        seen_table_files.add(fname)
        ce = cat_by_rel.get(f"11.17_modified22/{fname}")
        if not ce:
            errors.append(f"Unknown file {fname} in {label} table line {line_no}")
            continue
        shutter_s, _exp_s, layout_s, cat_s, mode_s, r_med_s, rg_s, bin_s, peak_s = cols
        if int(shutter_s) != int(round(ce["shutter_count_0x00a7"])):
            errors.append(f"Shutter count mismatch for {fname} at {label}:{line_no}")
        if layout_s.strip("` ") != ce["verified_raw_layout"]:
            errors.append(f"Layout mismatch for {fname} at {label}:{line_no}")
        if cat_s != ce["frame_category"] or mode_s != ce["capture_mode"]:
            errors.append(f"Category/mode mismatch for {fname} at {label}:{line_no}")
        if abs(_strip_md_num(r_med_s) - ce["center_roi_channel_medians"]["R"]) > 0.11:
            errors.append(
                f"Center R median mismatch for {fname} at {label}:{line_no}: "
                f"doc={r_med_s} vs json={ce['center_roi_channel_medians']['R']}"
            )
        if abs(_strip_md_num(rg_s) - ce["center_R_G1_ratio"]) > 1.1e-4:
            errors.append(
                f"Center R/G1 mismatch for {fname} at {label}:{line_no}: "
                f"doc={rg_s} vs json={ce['center_R_G1_ratio']:.6f}"
            )
        if abs(_strip_md_num(bin_s) - ce["comb_fft_bin3729_0p2276"]) > 0.11:
            errors.append(f"bin3729 mismatch for {fname} at {label}:{line_no}")
        pm = re.match(r"^([\d,.*]+)\s*\(`?([\d.]+)`?\)$", peak_s)
        if not pm:
            errors.append(f"Unparseable band-peak cell for {fname} at {label}:{line_no}: {peak_s}")
        else:
            if abs(_strip_md_num(pm.group(1)) - ce["comb_band_0p22_0p24_peak"]) > 0.11:
                errors.append(f"Band peak mismatch for {fname} at {label}:{line_no}")
            if abs(float(pm.group(2)) - ce["comb_band_peak_freq"]) > 1.1e-5:
                errors.append(f"Band peak freq mismatch for {fname} at {label}:{line_no}")
        checks += 8

    if seen_table_files != set(b_per_file.keys()):
        errors.append(f"{label} table file set mismatch: got {len(seen_table_files)} files")

    noise_row_re = re.compile(r"^\|\s*`Z61_(5102|5113)`\s*vs\s*`(5103|5114)`\s*\|(.+)\|$")
    seen_noise_modes: set[str] = set()
    for line_no, line in enumerate(audit_text.splitlines(), 1):
        nm = noise_row_re.match(line.strip())
        if not nm:
            continue
        cols = [c.strip() for c in nm.group(3).split("|")]
        mode = cols[0]
        seen_noise_modes.add(mode)
        ref = noise_by_mode.get(mode)
        if not ref:
            errors.append(f"Missing noise reference for mode {mode} in {label}")
            continue
        c68_doc, iqr_doc, std_doc = (_strip_md_num(cols[2]), _strip_md_num(cols[3]), _strip_md_num(cols[4]))
        if abs(c68_doc - ref["central_68pct_sigma"]) > 1.1e-4:
            errors.append(f"Bias c68 sigma mismatch for {mode} at {label}:{line_no}")
        if abs(iqr_doc - ref["IQR_sigma"]) > 1.1e-4:
            errors.append(f"Bias IQR sigma mismatch for {mode} at {label}:{line_no}: {iqr_doc} vs {ref['IQR_sigma']}")
        if abs(std_doc - ref["unclipped_std"]) > 1.1e-4:
            errors.append(f"Bias unclipped std mismatch for {mode} at {label}:{line_no}: {std_doc} vs {ref['unclipped_std']}")
        checks += 3
    if seen_noise_modes != {"Astro", "Standard"}:
        errors.append(f"Expected Astro & Standard rows in {label} bias noise table, got {seen_noise_modes}")

    for tok in expected_audit_tokens:
        if tok not in audit_text:
            errors.append(f"{label} missing verified frozen-112 token '{tok}'")
        checks += 1

    return checks


def check_evidence_doc_consistency(repo: Path, errors: list[str]) -> int:
    """Cross-check committed JSON evidence against CN & EN Markdown audit & whitepaper tables."""
    cat_path = repo / "docs/SAMPLE_EVIDENCE_CATALOG.json"
    m22_path = repo / "docs/evidence/m22_audit_metrics.json"
    audit_cn_path = repo / "docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md"
    audit_en_path = repo / "docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md"

    if not (cat_path.is_file() and m22_path.is_file() and audit_cn_path.is_file()):
        return 0

    try:
        cat = json.loads(cat_path.read_text(encoding="utf-8"))
        m22 = json.loads(m22_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"Failed loading JSON evidence for consistency check: {exc}")
        return 0

    checks = 0
    files = cat.get("files") or []
    if cat.get("nef_file_count") != 130 or len(files) != 130:
        errors.append(f"Catalog NEF count mismatch: nef_file_count={cat.get('nef_file_count')}, len={len(files)}")
    checks += 1

    cat_by_rel = {}
    for entry in files:
        rel = entry.get("rel_path", "")
        cat_by_rel[rel] = entry
        roi = entry.get("center_roi") or {}
        rows = roi.get("rows")
        cols = roi.get("cols")
        px = roi.get("pixels_per_channel")
        if (
            roi.get("coord_space") != "channel_plane"
            or rows != [505, 1515]
            or cols != [758, 2274]
            or px != 1531160
            or (rows[1] - rows[0]) * (cols[1] - cols[0]) != px
        ):
            errors.append(f"Catalog center_roi coordinate mismatch in {rel}: {roi}")
        ch = entry.get("center_roi_channel_medians") or {}
        rg = entry.get("center_R_G1_ratio")
        if ch.get("G1") and rg is not None:
            if abs((ch["R"] / ch["G1"]) - rg) > 1e-9:
                errors.append(f"Catalog center R/G1 ratio mismatch in {rel}")
        checks += 2

    # Cross-check catalog vs m22_audit_metrics per_file
    b_per_file = m22.get("B_comb_pair_comparison", {}).get("per_file", {})
    if len(b_per_file) != 18:
        errors.append(f"Expected 18 files in m22 B_comb_pair_comparison.per_file, got {len(b_per_file)}")
    for fname, pf in b_per_file.items():
        rel = f"11.17_modified22/{fname}"
        ce = cat_by_rel.get(rel)
        if not ce:
            errors.append(f"Missing {rel} in SAMPLE_EVIDENCE_CATALOG.json")
            continue
        if abs(ce["center_roi_channel_medians"]["R"] - pf["roi_median"]) > 1e-6:
            errors.append(f"R median mismatch between catalog and m22 metrics for {fname}")
        if abs(ce["comb_fft_bin3729_0p2276"] - pf["comb_fft_bin3729_0p2276"]) > 1e-6:
            errors.append(f"bin3729 mismatch between catalog and m22 metrics for {fname}")
        if abs(ce["comb_band_0p22_0p24_peak"] - pf["comb_band_0p22_0p24_peak"]) > 1e-6:
            errors.append(f"band_peak mismatch between catalog and m22 metrics for {fname}")
        checks += 3

    noise_by_mode = {
        p["capture_mode"]: p["full_frame"]
        for p in m22.get("C_bias_noise_pairs", {}).get("pairs", [])
    }

    d_frames = m22.get("D_frozen112_clamp", {}).get("frames", [])
    m13_frames = [r for r in d_frames if r["rel_path"].startswith("11.14_modified13/")]
    m22_std_frames = [r for r in d_frames if r["capture_mode"] == "Standard (Modified22)"]
    m22_astro_frames = [r for r in d_frames if r["capture_mode"] == "Astro (Modified22)"]

    m13_med_lo = int(round(min(r["median_delta"] for r in m13_frames)))
    m13_med_hi = int(round(max(r["median_delta"] for r in m13_frames)))
    std_hit_lo = min(r["matches_0_8_to_56"] for r in m22_std_frames)
    std_hit_hi = max(r["matches_0_8_to_56"] for r in m22_std_frames)
    clean_blocks = [r["preview_overlay"]["hit_rate_on_fully_clean_targets"] for r in m22_astro_frames]
    astro_clean_n = clean_blocks[0]["n"]
    astro_clean_hits = max(b["matches_0_8_to_56"] for b in clean_blocks)
    astro_clean_above56 = min(b["above56"] for b in clean_blocks)
    astro_med_lo = int(round(min(b["median_delta"] for b in clean_blocks)))
    astro_med_hi = int(round(max(b["median_delta"] for b in clean_blocks)))

    if astro_clean_hits != 0:
        errors.append(f"Expected 0 clean-target clamp hits on M22 Astro darks, got {astro_clean_hits}")

    expected_audit_tokens = [
        f"{std_hit_lo}~{std_hit_hi} / 112",
        f"+{m13_med_lo:,} ~ +{m13_med_hi:,} DN",
        f"0 / {astro_clean_n} (0%)",
        f"{astro_clean_above56} / {astro_clean_n} (100%)",
        f"+{astro_med_lo:,} ~ +{astro_med_hi:,} DN",
    ]

    checks += _check_audit_markdown(
        audit_cn_path,
        "docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md",
        cat_by_rel,
        b_per_file,
        noise_by_mode,
        expected_audit_tokens,
        errors,
    )
    if audit_en_path.is_file():
        checks += _check_audit_markdown(
            audit_en_path,
            "docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md",
            cat_by_rel,
            b_per_file,
            noise_by_mode,
            expected_audit_tokens,
            errors,
        )

    # Cross-check CN & EN whitepapers, READMEs, and TOOLS
    f5119 = cat_by_rel["11.17_modified22/Z61_5119.NEF"]
    f5110 = cat_by_rel["11.17_modified22/Z61_5110.NEF"]
    f5113 = cat_by_rel["11.17_modified22/Z61_5113.NEF"]
    f5102 = cat_by_rel["11.17_modified22/Z61_5102.NEF"]

    doc01_tokens = [
        f"{round(f5119['comb_fft_bin3729_0p2276']):,}",
        f"{round(f5110['comb_fft_bin3729_0p2276']):,}",
        f"{round(f5119['comb_band_0p22_0p24_peak']):,}",
        f"{round(f5110['comb_band_0p22_0p24_peak']):,}",
        f"{round(f5113['comb_fft_bin3729_0p2276']):,}",
        f"{round(f5102['comb_fft_bin3729_0p2276']):,}",
        f"{f5119['center_R_G1_ratio']:.4f}",
        f"{f5110['center_R_G1_ratio']:.4f}",
    ]
    for rel_01 in ("docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md", "docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md"):
        p01 = repo / rel_01
        if p01.is_file():
            t01 = p01.read_text(encoding="utf-8")
            for tok in doc01_tokens:
                if tok not in t01:
                    errors.append(f"{rel_01} missing verified value '{tok}'")
                checks += 1

    astro_std_2dp = f"{noise_by_mode['Astro']['unclipped_std']:.2f}"
    doc02_tokens = ("0 / 112 (0%", "112 / 112 (100%)", astro_std_2dp, "4.24", "7.42")
    for rel_02 in ("docs/02_STAR_EATER_AND_DARK_CURRENT.md", "docs/02_STAR_EATER_AND_DARK_CURRENT_EN.md"):
        p02 = repo / rel_02
        if p02.is_file():
            t02 = p02.read_text(encoding="utf-8")
            for tok in doc02_tokens:
                if tok not in t02:
                    errors.append(f"{rel_02} missing verified value '{tok}'")
                checks += 1

    readme_tokens = (
        "0/112",
        f"{round(f5119['comb_fft_bin3729_0p2276']):,}",
        f"{round(f5110['comb_fft_bin3729_0p2276']):,}",
        EXPECTED_RELEASE_ZIP_SIZE_TOKEN,
        EXPECTED_RELEASE_ZIP_SHA256,
        "Nikon-Z6-C380-Modified23-Astro-Firmware.zip",
        "SHA256SUMS.txt",
        "01_MODIFIED23/EG162080.BIN",
        "47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029",
    )
    for rel_rm in ("README.md", "README_EN.md"):
        prm = repo / rel_rm
        if prm.is_file():
            trm = prm.read_text(encoding="utf-8")
            for tok in readme_tokens:
                if tok not in trm:
                    errors.append(f"{rel_rm} missing verified value '{tok}'")
                checks += 1

    # Ensure explanatory docs carry zero stale candidate labels, 121-frame counts, or legacy uncompressed warnings
    explanatory_docs = (
        "README.md",
        "README_EN.md",
        "THIRD_PARTY_NOTICES.md",
        "samples/README.md",
        "docs/README.md",
        "docs/README_EN.md",
        "docs/TOOLS.md",
        "docs/TOOLS_EN.md",
        "docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md",
        "docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS_EN.md",
        "docs/02_STAR_EATER_AND_DARK_CURRENT.md",
        "docs/02_STAR_EATER_AND_DARK_CURRENT_EN.md",
        "docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md",
        "docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md",
        "docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md",
        "docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER_EN.md",
        "docs/PROJECT_GOALS.md",
        "docs/NEXT_STEPS.md",
    )
    forbidden_explanatory_phrases = (
        "hardware_pixels_verified = false",
        "刷机前验证候选",
        "刷机前完备验证候选",
        "Modified23-Candidate",
        "Pre-Flash Verified Candidate",
        "awaiting physical camera capture sign-off",
        "Awaiting On-Camera Sign-Off",
        "固定选择「无损压缩",
        "固定选用「无损压缩",
        "推荐固定使用**无损压缩",
        "always select **Lossless compressed**",
        "use **Lossless compressed** for",
        "121 张",
        "121 个实机样本",
        "all **121**",
        "across **121**",
    )
    for rel_exp in explanatory_docs:
        p_exp = repo / rel_exp
        if p_exp.is_file():
            t_exp = p_exp.read_text(encoding="utf-8")
            for bad_tok in forbidden_explanatory_phrases:
                if bad_tok in t_exp:
                    errors.append(f"{rel_exp} contains stale/version-stacked phrase '{bad_tok}'")
                checks += 1
    tools_cn = repo / "docs/TOOLS.md"
    if tools_cn.is_file():
        ttl = tools_cn.read_text(encoding="utf-8")
        if "四张 256 字节" in ttl or "三张 256 字节 XOR 掩码表" not in ttl:
            errors.append("docs/TOOLS.md must state three 256-byte XOR mask tables (列、行、块)")
        checks += 1

    tools_en = repo / "docs/TOOLS_EN.md"
    if tools_en.is_file():
        ttl_en = tools_en.read_text(encoding="utf-8")
        if "four 256-byte" in ttl_en.lower() or "three 256-byte xor mask tables" not in ttl_en.lower():
            errors.append("docs/TOOLS_EN.md must state three 256-byte XOR mask tables (column, row, block)")
        checks += 1

    # Verify top-of-document CN <-> EN language switcher links on all 8 core pairs
    for cn_rel, en_rel, en_link_in_cn, cn_link_in_en in BILINGUAL_DOC_PAIRS:
        cn_p = repo / cn_rel
        en_p = repo / en_rel
        if cn_p.is_file() and en_p.is_file():
            cn_head = "\n".join(cn_p.read_text(encoding="utf-8").splitlines()[:10])
            en_head = "\n".join(en_p.read_text(encoding="utf-8").splitlines()[:10])
            if f"({en_link_in_cn})" not in cn_head:
                errors.append(f"{cn_rel} top header missing language switch link to ({en_link_in_cn})")
            if f"({cn_link_in_en})" not in en_head:
                errors.append(f"{en_rel} top header missing language switch link to ({cn_link_in_en})")
            checks += 2

    # Cross-check Modified23 recipe, native probe, updater audit, and bilingual reports
    m23_recipe_p = repo / "patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json"
    m23_probe_p = repo / "docs/evidence/probe_modified23_native_result.json"
    m23_upd_p = repo / "docs/evidence/modified23_updater_audit.json"
    m23_metrics_p = repo / "docs/evidence/m23_audit_metrics.json"
    if m23_recipe_p.is_file() and m23_probe_p.is_file() and m23_upd_p.is_file() and m23_metrics_p.is_file():
        m23_rec = json.loads(m23_recipe_p.read_text(encoding="utf-8"))
        m23_prb = json.loads(m23_probe_p.read_text(encoding="utf-8"))
        m23_upd = json.loads(m23_upd_p.read_text(encoding="utf-8"))
        m23_met = json.loads(m23_metrics_p.read_text(encoding="utf-8"))
        m23_sha = m23_rec.get("modified23_sha256", "")
        m23_crc = m23_rec.get("crc16_hqx", "")
        if m23_rec.get("total_edits") != 105 or m23_crc != "0xc083":
            errors.append("Modified23 recipe total_edits/crc16_hqx mismatch")
        if (
            m23_prb.get("status") != "PASS"
            or m23_prb.get("modified23_sha256") != m23_sha
            or m23_prb.get("measured_candidate_sha256") != m23_sha
            or m23_prb.get("measured_candidate_crc16_hqx") != m23_crc
            or m23_prb.get("measured_candidate_size_bytes") != 33502842
        ):
            errors.append("probe_modified23_native_result.json measured identity/status mismatch")
        checks += 2

        t23 = m23_prb.get("tests", {})
        bd = t23.get("raw_pipeline_matrix_breakdown", {})
        syn = t23.get("synthetic_pack", {})
        rnl = t23.get("real_nef_libraw", {})
        hw_nef = t23.get("hardware_camera_nef", {})
        if not (
            t23.get("negative_m22_binary_gate_rejected") is True
            and t23.get("negative_m22_hook14_unicorn_rejected") is True
            and t23.get("adjacent_0x100a34d4_branch_intact") is True
            and t23.get("site14_a34d0_dual_branch_and_apsr_cases") == 28
            and t23.get("raw_pipeline_matrix_cases") == 437
            and bd.get("grid_total") == 432
            and bd.get("uncompressed_strip_and_mmio_verified") == 113
            and bd.get("compressed_queue_descriptor_verified") == 216
            and bd.get("jpeg_only_encoder_skip_verified") == 108
            and bd.get("non_astro_stock_parity_verified") == 216
            and (
                bd.get("uncompressed_strip_and_mmio_verified", 0)
                + bd.get("compressed_queue_descriptor_verified", 0)
                + bd.get("jpeg_only_encoder_skip_verified", 0)
            )
            == 437
        ):
            errors.append("probe_modified23_native_result.json matrix breakdown or negative gate mismatch")
        checks += 4

        if not (
            syn.get("status") == "PASS"
            and syn.get("pixels_verified") == 24498560
            and syn.get("packed14_strip_bytes") == 42920960
            and syn.get("packed12_strip_bytes") == 36780160
            and syn.get("max_abs_adu_diff") == 0
            and rnl.get("status") == "PASS"
            and rnl.get("clean_unmodified_sensor_row_count") == 3672
            and rnl.get("clean_unmodified_sensor_pixels") == 22267008
            and rnl.get("substituted_preview_overlay_rows") == [3633, 4000]
            and rnl.get("substituted_preview_overlay_row_count") == 368
            and rnl.get("substituted_preview_overlay_pixels") == 2231552
            and rnl.get("repacked_strip_byte_counts") == 42920960
            and rnl.get("embedded_preview_jpeg_slots_preserved") == 3
            and rnl.get("max_abs_adu_diff_vs_prepack_reference") == 0
            and (rnl.get("clean_unmodified_sensor_pixels", 0) + rnl.get("substituted_preview_overlay_pixels", 0))
            == 24498560
            and hw_nef.get("status") == "PASS"
            and hw_nef.get("frames_verified") == 9
            and hw_nef.get("uncompressed_packed14_frames") == 6
            and hw_nef.get("lossless_14bit_frames") == 3
            and hw_nef.get("hardware_packed14_pixels_verified") == 146991360
            and hw_nef.get("libraw_vs_independent_pixel_diff_count") == 0
            and hw_nef.get("preview_overlap_count") == 0
            and t23.get("hardware_pixels_verified") is True
        ):
            errors.append("probe_modified23_native_result.json bit-packing or hardware_camera_nef scope mismatch")
        checks += 5

        # Cross-check m23_audit_metrics.json against catalog and recipe
        fw_ut = m23_met.get("firmware_under_test", {})
        a23 = m23_met.get("A_packed14_hardware_fullframe_verification", {})
        d23 = m23_met.get("D_frozen112_spatial_filter_bypass", {})
        if not (
            fw_ut.get("eg162080_sha256") == m23_sha
            and fw_ut.get("eg162080_crc16_hqx") == m23_crc
            and fw_ut.get("total_patch_sites") == 105
            and m23_met.get("method", {}).get("frames_total") == 9
            and a23.get("files_checked") == 6
            and a23.get("total_pixels_verified") == 146991360
            and a23.get("all_identical_to_libraw") is True
            and a23.get("total_pixel_diff_count") == 0
            and a23.get("any_preview_overlap") is False
            and a23.get("max_trailing_bytes_after_strip") == 0
            and d23.get("all_zero_clamp_hits") is True
            and d23.get("total_clamp_hits_across_9_frames") == 0
            and d23.get("total_former_overlay_zone_hits") == 0
        ):
            errors.append("m23_audit_metrics.json invariant or pixel/clamp verification mismatch")
        for pf23 in a23.get("per_file", []):
            rel23 = pf23.get("rel_path", "")
            ce23 = cat_by_rel.get(rel23)
            if not ce23 or ce23.get("sha256") != pf23.get("sha256") or ce23.get("verified_raw_layout") != "packed_14bit_stride10624":
                errors.append(f"Catalog vs m23_audit_metrics mismatch for {rel23}")
            checks += 1
        checks += 4

        upd_files = m23_upd.get("file_checks") or []
        upd_sched = m23_upd.get("scheduler") or []
        upd_neg_cnt = sum(1 for row in upd_files if row.get("expected_rejection") is True)
        if not (
            m23_upd.get("ok") is True
            and m23_upd.get("measured_modified23_sha256") == m23_sha
            and m23_upd.get("measured_modified23_crc16_hqx") == m23_crc
            and m23_upd.get("measured_modified23_size_bytes") == 33502842
            and m23_upd.get("negative_m22_binary_rejected") is True
            and m23_upd.get("physical_flash") is False
            and len(upd_files) == 7
            and upd_neg_cnt == 2
            and len(upd_sched) == 5
        ):
            errors.append("modified23_updater_audit.json measured identity, negative rejection, or count mismatch")
        checks += 3

        fx_cmp = t23.get("fx_14bit_wide1_uncompressed_comparison", {})
        m23_doc_tokens = (
            m23_sha,
            m23_crc,
            f"{fx_cmp.get('m22_strip_byte_counts', 0):,}",
            f"{fx_cmp.get('m23_strip_byte_counts', 0):,}",
            f"{t23.get('packed12_strip_bytes', 0):,}",
            f"{fx_cmp.get('preview_slot_headroom_bytes', 0):,}",
            str(t23.get("raw_pipeline_matrix_cases", 0)),
            str(bd.get("grid_total", 0)),
            str(bd.get("uncompressed_strip_and_mmio_verified", 0)),
            str(bd.get("compressed_queue_descriptor_verified", 0)),
            str(bd.get("jpeg_only_encoder_skip_verified", 0)),
            f"{rnl.get('clean_unmodified_sensor_row_count', 0):,}",
            f"{rnl.get('clean_unmodified_sensor_pixels', 0):,}",
            str(rnl.get("substituted_preview_overlay_row_count", 0)),
            f"{rnl.get('substituted_preview_overlay_pixels', 0):,}",
            "146,991,360",
            "0.99955",
            "Z61_5128",
            "Z61_5136",
            "3633..4000",
            "4001..4039",
            "hardware_pixels_verified = true",
            "negative_m22_binary_gate_rejected",
            "negative_m22_binary_rejected",
            "330",
        )
        stale_m23_phrases = (
            "Z61_5105.NEF` 硬件位打包",
            "(`Z61_5105.NEF`) hardware bit-packing",
            "Real-NEF `Z61_5105.NEF` Hardware Bit-Packing",
            "Modified16 <-> Modified23",
            "hardware_pixels_verified = false",
            "刷机前完备验证候选",
            "Pre-Flash Verified Candidate",
        )
        for rel_m23 in (
            "docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md",
            "docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md",
        ):
            pm23 = repo / rel_m23
            if pm23.is_file():
                tm23 = pm23.read_text(encoding="utf-8")
                for tok in m23_doc_tokens:
                    if tok not in tm23:
                        errors.append(f"{rel_m23} missing verified Modified23 value '{tok}'")
                    checks += 1
                for bad_phrase in stale_m23_phrases:
                    if bad_phrase in tm23:
                        errors.append(f"{rel_m23} contains stale/imprecise claim '{bad_phrase}'")
                    checks += 1
    return checks


def run_hygiene_gate(repo: Path, tracked_only: bool = False, check_history: bool = False) -> dict:
    errors: list[str] = []
    public_files, ignored_tracked = collect_public_files(repo, tracked_only=tracked_only)
    public_set = set(public_files)

    if ignored_tracked:
        errors.append(
            f"Git index tracks {len(ignored_tracked)} `.gitignore`-excluded file(s): "
            f"{ignored_tracked[:10]}"
        )

    for req in REQUIRED_ROOT_FILES:
        if req not in public_set or not (repo / req).is_file():
            errors.append(f"Missing required public file: {req}")

    json_checked = 0
    md_checked = 0
    text_checked = 0

    for rel in public_files:
        p = repo / rel
        if not p.is_file():
            errors.append(f"Tracked entry missing on disk: {rel}")
            continue

        _check_forbidden_path(rel, "Public file", errors)

        sz = p.stat().st_size
        if sz > MAX_PUBLIC_FILE_BYTES:
            errors.append(f"Public file exceeds {MAX_PUBLIC_FILE_BYTES} B limit ({sz} B): {rel}")

        ext = p.suffix.lower()
        if ext in BINARY_ASSET_EXTENSIONS:
            continue

        raw = p.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"Non-UTF8 text file {rel}: {exc}")
            continue

        text_checked += 1
        for line_no, line in enumerate(text.splitlines(), 1):
            if SENSITIVE_PATH_RE.search(line) and rel != "tools/verify_repo_hygiene.py":
                errors.append(
                    f"Host/session path leak in {rel}:{line_no}: {line.strip()[:120]}"
                )

        if ext == ".json":
            try:
                json.loads(text)
                json_checked += 1
            except json.JSONDecodeError as exc:
                errors.append(f"Invalid JSON in {rel}: {exc}")

        if ext == ".md":
            md_checked += 1
            check_markdown_file(rel, text, repo, public_set, errors)

    check_clean_room_tools(repo, errors)
    consistency_checks = check_evidence_doc_consistency(repo, errors)

    history_stats = {"commits": 0, "trees": 0, "tree_paths": 0, "blobs": 0}
    if check_history:
        history_stats = check_git_history(repo, errors)

    return {
        "status": "PASS" if not errors else "FAIL",
        "public_file_count": len(public_files),
        "ignored_tracked_count": len(ignored_tracked),
        "text_files_checked": text_checked,
        "markdown_files_checked": md_checked,
        "json_files_checked": json_checked,
        "consistency_assertions_checked": consistency_checks,
        "history_checked": check_history,
        "history_commits_checked": history_stats["commits"],
        "history_trees_checked": history_stats["trees"],
        "history_tree_paths_checked": history_stats["tree_paths"],
        "history_blobs_checked": history_stats["blobs"],
        "error_count": len(errors),
        "errors": errors[:50],
    }


def main() -> int:
    if not __debug__:
        raise RuntimeError("verify_repo_hygiene.py must not be executed with Python -O/-OO.")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--repo",
        type=Path,
        default=REPO_ROOT,
        help="Path to repository root",
    )
    ap.add_argument(
        "--tracked-only",
        action="store_true",
        help="Check strictly `git ls-files` tracked entries (for pre-push verification)",
    )
    ap.add_argument(
        "--check-history",
        action="store_true",
        help="Also audit all reachable historical Git commit trees, blobs, and commit emails",
    )
    args = ap.parse_args()

    summary = run_hygiene_gate(
        args.repo.resolve(),
        tracked_only=args.tracked_only,
        check_history=args.check_history,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

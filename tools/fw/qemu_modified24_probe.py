"""Live z6-qemu dual-core RTOS verification probe for Nikon Z6 C3.80 Modified24.

SPDX-License-Identifier: GPL-3.0-or-later

Boots the Modified24 Astro Firmware image inside z6-qemu (`nikon-z6-display`,
`--allow-modified-firmware`) across both `menu` and `shooting` profiles, verifying:
  1. Live XIP hook & cave bytes mapped at 0x1002E1B0, 0x100A34D0, and all 6 Astro Red sites;
  2. Factory reset default (`PID 0x1111 == 0` @ `0xC24DD0EC`) and Stock VGC Ch1 CSC;
  3. Setup Menu navigation & multi-language UI rendering (`Astro red display` /
     `天文红光显示`) plus real GUI menu button toggle `0 -> 1 -> 0` with live VGC Ch1
     (`0x201454F0..0x20145504`) `Mode 2A LumaRed` transitions and Ch0 HDMI isolation;
  4. Live View (`shooting` profile) with native hardware framing grid (`0x102D = 1`):
     single-frame stateless synchronization of both `0x201454F0` CSC and `0x20145618`
     hardware grid color (`R > 0, G = 0, B = 0`), rendered red grid pixels on the
     live QEMU scanout PNG, and 100% Stock restoration on `1 -> 0`.
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("qemu_modified24_probe.py must not be executed with Python -O/-OO.")

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import time
import zlib

THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = THIS_DIR.parents[1]

M24_EXPECTED_SHA256 = "168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653"
STOCK_POST_CSC_WORDS = [0x00004000, 0x00005A00, 0xEA004000, 0x0000D200, 0x71004000, 0x00000000]
LUMA_RED_POST_CSC_WORDS = [0x00003000, 0, 0, 0, 0, 0]

RAM_PROP_1111 = 0xC24DD0EC
RAM_PROP_0526 = 0xC24CDEA0
VGC_CH0_POST_CSC = 0x201414F0
VGC_CH1_POST_CSC = 0x201454F0
VGC_CH1_GRID_COLOR = 0x20145618
VGC_CH1_GRID_ENABLE = 0x20145620

KNOWN_QEMU_PROBE_ENTRIES = {
    "qemu_modified24_result.json",
    "session_menu",
    "session_shooting",
    "01_menu_boot_default_off.png",
    "02_setup_menu_en.png",
    "03_setup_submenu_options_en.png",
    "04_setup_menu_red_on.png",
    "05_setup_menu_restored_off.png",
    "06_shooting_liveview_grid_off.png",
    "07_shooting_liveview_grid_red_on.png",
    "08_shooting_liveview_grid_restored_off.png",
}

def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _sanitize_error_text(msg: str) -> str:
    cleaned = re.sub(r"(?<![A-Za-z0-9])[C-Zc-z]:[\\/][^\s\"']*", "<redacted-path>", msg)
    cleaned = re.sub(r"/(?:Users|home)/[^\s\"']*", "<redacted-path>", cleaned)
    return cleaned[:240]


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def read_u32(remote, addr: int) -> int:
    return struct.unpack("<I", remote.memory(addr, 4))[0]


def read_u32_vec(remote, addr: int, count: int) -> list[int]:
    raw = remote.memory(addr, count * 4)
    return list(struct.unpack(f"<{count}I", raw))


def decode_rgb_png(png_bytes: bytes) -> tuple[int, int, bytes]:
    require(png_bytes[:8] == b"\x89PNG\r\n\x1a\n", "Invalid PNG magic")
    pos = 8
    w = h = 0
    idat_parts: list[bytes] = []
    while pos + 8 <= len(png_bytes):
        length = struct.unpack_from(">I", png_bytes, pos)[0]
        kind = png_bytes[pos + 4 : pos + 8]
        payload = png_bytes[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            w, h, depth, ctype, _, _, _ = struct.unpack(">IIBBBBB", payload)
            require(depth == 8 and ctype == 2, f"Unsupported PNG depth/ctype: {depth}/{ctype}")
        elif kind == b"IDAT":
            idat_parts.append(payload)
        elif kind == b"IEND":
            break
    require(w > 0 and h > 0 and bool(idat_parts), "Incomplete PNG chunks")
    raw_rows = zlib.decompress(b"".join(idat_parts))
    row_stride = 1 + w * 3
    require(len(raw_rows) == h * row_stride, "Unexpected PNG decompressed row length")
    out = bytearray(w * h * 3)
    for y in range(h):
        flt = raw_rows[y * row_stride]
        require(flt == 0, f"Unexpected PNG filter type {flt}")
        out[y * w * 3 : (y + 1) * w * 3] = raw_rows[y * row_stride + 1 : (y + 1) * row_stride]
    return w, h, bytes(out)


def save_png(camera, out_dir: Path, name: str) -> tuple[int, int]:
    png_bytes = camera.png
    require(png_bytes is not None and len(png_bytes) > 0, f"Empty screenshot for {name}")
    w, h, px = decode_rgb_png(png_bytes)
    require(min(px) != max(px), f"Uniform/blank screenshot for {name}")
    (out_dir / name).write_bytes(png_bytes)
    return w, h


def settle_and_pause(camera, seconds: float = 1.0):
    camera.continue_guest()
    time.sleep(seconds)
    camera.refresh()
    camera.pause()
    pkt = camera.run_to(0x100531BC)
    camera.remote.sock.settimeout(45)
    return pkt


def set_prop_rtos(ui_mod, camera, packet: str, pid: int, value: int) -> str:
    res = ui_mod.call_fixture(camera.remote, packet, 0x101D7F02, bytes(8), [pid, value])
    packet = "T05thread:" + res["return_cpu"] + ";"
    require(int(res["return_r0"], 16) == 1, f"RTOS SetProperty({pid:#x}, {value}) failed")
    chk = ui_mod.call_fixture(camera.remote, packet, 0x1015BEBE, bytes(8), [pid])
    packet = "T05thread:" + chk["return_cpu"] + ";"
    got = int(chk["return_r0"], 16)
    require(got == value, f"RTOS GetProperty({pid:#x}) readback {got} != {value}")
    return packet


def get_prop_rtos(ui_mod, camera, packet: str, pid: int) -> tuple[str, int]:
    chk = ui_mod.call_fixture(camera.remote, packet, 0x1015BEBE, bytes(8), [pid])
    packet = "T05thread:" + chk["return_cpu"] + ";"
    return packet, int(chk["return_r0"], 16)


def run_menu_phase(ui_mod, out_dir: Path, digest: str) -> dict:
    camera = ui_mod.Camera(
        8791,
        profile="menu",
        capture_control_test=False,
        allow_modified_firmware=True,
        firmware_sha256=digest,
    )
    camera.exposure_probe = False
    camera.isp_disable_cache = False
    camera.tg_period_ms = None

    phase_report: dict = {"ok": False, "screenshots": []}
    try:
        camera.boot()
        for _ in range(3):
            time.sleep(1.0)
            camera.refresh()
        camera.pause()
        packet = camera.run_to(0x100531BC)
        camera.remote.sock.settimeout(45)

        live_checks = {
            "astro_raw_site14_0x100a34d0": camera.remote.memory(0x100A34D0, 6).hex(),
            "astro_red_cave_0x1002e1b0": camera.remote.memory(0x1002E1B0, 4).hex(),
            "astro_red_disp_a_0x1040e7d8": camera.remote.memory(0x1040E7D8, 2).hex(),
            "astro_red_disp_b_0x1043a1e0": camera.remote.memory(0x1043A1E0, 2).hex(),
            "astro_red_csc_hook_0x10243422": camera.remote.memory(0x10243422, 4).hex(),
            "astro_red_sync_hook_0x102435ae": camera.remote.memory(0x102435AE, 6).hex(),
            "astro_red_grid_hook_0x10244154": camera.remote.memory(0x10244154, 4).hex(),
            "astro_red_lang_hook_0x104c013c": camera.remote.memory(0x104C013C, 4).hex(),
        }
        require(live_checks["astro_raw_site14_0x100a34d0"] == "8af744bbe9e7", "Missing 0x100A34D0 hook in QEMU XIP")
        require(live_checks["astro_red_cave_0x1002e1b0"] == "0e461d46", "Missing Astro Red cave in QEMU XIP")
        require(live_checks["astro_red_disp_a_0x1040e7d8"] == "0024", "Missing DISP lock A in QEMU XIP")
        require(live_checks["astro_red_disp_b_0x1043a1e0"] == "18e0", "Missing DISP lock B in QEMU XIP")
        phase_report["live_code_checks"] = live_checks

        packet, boot_pid1111 = get_prop_rtos(ui_mod, camera, packet, 0x1111)
        boot_ram1111 = read_u32(camera.remote, RAM_PROP_1111)
        boot_ram0526 = read_u32(camera.remote, RAM_PROP_0526)
        boot_ch1_csc = read_u32_vec(camera.remote, VGC_CH1_POST_CSC, 6)
        boot_ch0_csc = read_u32_vec(camera.remote, VGC_CH0_POST_CSC, 6)

        require(boot_pid1111 == 0 and boot_ram1111 == 0, f"Boot PID 0x1111 not 0: {boot_pid1111}/{boot_ram1111}")
        require(boot_ram0526 == 0, f"Boot PID 0x0526 not 0: {boot_ram0526}")
        require(boot_ch1_csc == STOCK_POST_CSC_WORDS, f"Boot Ch1 CSC mismatch: {boot_ch1_csc}")

        save_png(camera, out_dir, "01_menu_boot_default_off.png")
        phase_report["screenshots"].append("01_menu_boot_default_off.png")

        packet = camera.key(packet, "left")
        packet = settle_and_pause(camera, 0.5)
        for _ in range(4):
            packet = camera.key(packet, "down")
            packet = settle_and_pause(camera, 0.45)
        packet = camera.key(packet, "right")
        packet = settle_and_pause(camera, 0.7)
        for _ in range(11):
            packet = camera.key(packet, "down")
            packet = settle_and_pause(camera, 0.45)
        save_png(camera, out_dir, "02_setup_menu_en.png")
        phase_report["screenshots"].append("02_setup_menu_en.png")

        packet = camera.key(packet, "right")
        packet = settle_and_pause(camera, 0.65)
        save_png(camera, out_dir, "03_setup_submenu_options_en.png")
        phase_report["screenshots"].append("03_setup_submenu_options_en.png")

        packet = camera.key(packet, "down")
        packet = settle_and_pause(camera, 0.45)
        packet = camera.key(packet, "ok")
        packet = settle_and_pause(camera, 0.8)

        on_ram1111 = read_u32(camera.remote, RAM_PROP_1111)
        phase_report["gui_menu_button_toggled_pid1111"] = on_ram1111 == 1
        require(
            on_ram1111 == 1,
            f"GUI submenu OK button did not set PID 0x1111 = 1 (RAM={on_ram1111})",
        )
        on_ch1_csc = read_u32_vec(camera.remote, VGC_CH1_POST_CSC, 6)
        on_ch0_csc = read_u32_vec(camera.remote, VGC_CH0_POST_CSC, 6)
        require(
            on_ch1_csc == LUMA_RED_POST_CSC_WORDS,
            f"Menu page flip did not sync Ch1 LumaRed CSC: got {on_ch1_csc}",
        )
        require(
            on_ch0_csc == boot_ch0_csc,
            f"Ch0 HDMI CSC modified during Menu On toggle: {on_ch0_csc} != {boot_ch0_csc}",
        )
        save_png(camera, out_dir, "04_setup_menu_red_on.png")
        phase_report["screenshots"].append("04_setup_menu_red_on.png")

        packet = set_prop_rtos(ui_mod, camera, packet, 0x1111, 0)
        packet = camera.key(packet, "up")
        packet = settle_and_pause(camera, 0.8)
        restored_ch1_csc = read_u32_vec(camera.remote, VGC_CH1_POST_CSC, 6)
        require(
            restored_ch1_csc == STOCK_POST_CSC_WORDS,
            f"Menu Off toggle did not restore Stock Ch1 CSC: got {restored_ch1_csc}",
        )
        save_png(camera, out_dir, "05_setup_menu_restored_off.png")
        phase_report["screenshots"].append("05_setup_menu_restored_off.png")

        phase_report.update(
            ok=True,
            boot_pid_0x1111=boot_pid1111,
            boot_ram_0x1111=boot_ram1111,
            boot_ch1_csc=[hex(x) for x in boot_ch1_csc],
            on_ch1_csc=[hex(x) for x in on_ch1_csc],
            on_ch0_csc=[hex(x) for x in on_ch0_csc],
            restored_ch1_csc=[hex(x) for x in restored_ch1_csc],
        )
    finally:
        camera.close_guest()
        shutil.copytree(camera.directory, out_dir / "session_menu", dirs_exist_ok=True)
    return phase_report


def count_pure_red_diff_pixels(
    png_off: Path, png_on: Path, expected_grid_level: int | None = None
) -> dict:
    w0, h0, px_off = decode_rgb_png(png_off.read_bytes())
    w1, h1, px_on = decode_rgb_png(png_on.read_bytes())
    require((w0, h0) == (w1, h1), "Screenshot dimensions differ between Off and On")
    total_changed = 0
    changed_nonzero_gb = 0
    red_dominant_diffs = 0
    zero_gb_red_pixels = 0
    exact_expected_red_grid = 0
    for i in range(0, len(px_on), 3):
        r0, g0, b0 = px_off[i], px_off[i + 1], px_off[i + 2]
        r1, g1, b1 = px_on[i], px_on[i + 1], px_on[i + 2]
        if (r0, g0, b0) != (r1, g1, b1):
            total_changed += 1
            if g1 != 0 or b1 != 0:
                changed_nonzero_gb += 1
            if r1 > 0 and g1 < g0 and b1 < b0 and r1 > g1 and r1 > b1:
                red_dominant_diffs += 1
            if r1 > 40 and g1 == 0 and b1 == 0:
                zero_gb_red_pixels += 1
            if (
                expected_grid_level is not None
                and (r0, g0, b0) == (expected_grid_level, expected_grid_level, expected_grid_level)
                and (r1, g1, b1) == (expected_grid_level, 0, 0)
            ):
                exact_expected_red_grid += 1
    out = {
        "total_changed_pixels": total_changed,
        "changed_nonzero_gb_pixels": changed_nonzero_gb,
        "red_dominant_changed_pixels": red_dominant_diffs,
        "pure_red_zero_gb_changed_pixels": zero_gb_red_pixels,
    }
    if expected_grid_level is not None:
        out["exact_expected_red_grid_pixels"] = exact_expected_red_grid
    return out


def verify_pure_red_grid_scanout(grid_px_diff: dict) -> None:
    total_changed = int(grid_px_diff.get("total_changed_pixels", 0))
    require(
        total_changed > 100,
        f"Expected rendered red grid lines in scanout PNG (>100 pixels), got {grid_px_diff}",
    )
    require(
        int(grid_px_diff.get("changed_nonzero_gb_pixels", -1)) == 0,
        f"Non-zero G/B channel leakage detected in scanout diff: {grid_px_diff}",
    )
    require(
        int(grid_px_diff.get("pure_red_zero_gb_changed_pixels", 0)) == total_changed,
        f"Not all changed scanout pixels are pure red (G=0, B=0): {grid_px_diff}",
    )
    if "exact_expected_red_grid_pixels" in grid_px_diff:
        require(
            int(grid_px_diff["exact_expected_red_grid_pixels"]) == total_changed,
            f"Changed scanout pixels did not match pure-red grid transition: {grid_px_diff}",
        )

def run_shooting_grid_phase(ui_mod, out_dir: Path, digest: str) -> dict:
    camera = ui_mod.Camera(
        8792,
        profile="shooting",
        capture_control_test=True,
        raw_source=ui_mod.active_manifest("native0"),
        exmcu_no_lens=True,
        tg_periodic_test=True,
        tg_paired_test=True,
        raw_ingress_test=ui_mod.active_ingress(),
        isp_boundary_test=True,
        orientation_fixture=0,
        keep_awake=True,
        photo_liveview=True,
        allow_modified_firmware=True,
        firmware_sha256=digest,
    )
    camera.exposure_probe = False
    camera.isp_disable_cache = False
    camera.tg_period_ms = None
    camera.session_grid_setting = 1

    phase_report: dict = {"ok": False, "screenshots": []}
    try:
        camera.boot_shooting()
        camera.pause()
        packet = camera.run_to(0x100531BC)
        camera.remote.sock.settimeout(45)

        packet = set_prop_rtos(ui_mod, camera, packet, 0x102D, 1)
        packet = settle_and_pause(camera, 1.2)

        off_csc = read_u32_vec(camera.remote, VGC_CH1_POST_CSC, 6)
        off_grid_en = read_u32(camera.remote, VGC_CH1_GRID_ENABLE)
        off_grid_color = read_u32(camera.remote, VGC_CH1_GRID_COLOR)
        off_r = off_grid_color & 0xFF
        off_g = (off_grid_color >> 8) & 0xFF
        off_b = (off_grid_color >> 16) & 0xFF

        require(off_csc == STOCK_POST_CSC_WORDS, f"Shooting initial CSC mismatch: {off_csc}")
        require(off_grid_en == 1, f"Expected native framing grid enabled (1), got {off_grid_en}")
        require(
            off_r > 0 and off_r == off_g == off_b,
            f"Expected neutral gray grid color in Off mode, got {off_grid_color:#010x}",
        )
        p_off = out_dir / "06_shooting_liveview_grid_off.png"
        save_png(camera, out_dir, p_off.name)
        phase_report["screenshots"].append(p_off.name)

        packet = set_prop_rtos(ui_mod, camera, packet, 0x1111, 1)
        packet = settle_and_pause(camera, 1.2)

        on_csc = read_u32_vec(camera.remote, VGC_CH1_POST_CSC, 6)
        on_ch0_csc = read_u32_vec(camera.remote, VGC_CH0_POST_CSC, 6)
        on_grid_color = read_u32(camera.remote, VGC_CH1_GRID_COLOR)
        on_r = on_grid_color & 0xFF
        on_g = (on_grid_color >> 8) & 0xFF
        on_b = (on_grid_color >> 16) & 0xFF

        require(on_csc == LUMA_RED_POST_CSC_WORDS, f"Live View On CSC mismatch: {on_csc}")
        require(on_ch0_csc[0] != 0x00003000, f"Ch0 HDMI contaminated in Live View: {on_ch0_csc}")
        require(
            on_r == off_r and on_g == 0 and on_b == 0,
            f"Expected pure red grid color (G=0, B=0, R={off_r:#x}), got {on_grid_color:#010x}",
        )
        p_on = out_dir / "07_shooting_liveview_grid_red_on.png"
        save_png(camera, out_dir, p_on.name)
        phase_report["screenshots"].append(p_on.name)

        grid_px_diff = count_pure_red_diff_pixels(p_off, p_on, expected_grid_level=off_r)
        verify_pure_red_grid_scanout(grid_px_diff)

        packet = set_prop_rtos(ui_mod, camera, packet, 0x1111, 0)
        packet = settle_and_pause(camera, 1.2)

        rest_csc = read_u32_vec(camera.remote, VGC_CH1_POST_CSC, 6)
        rest_grid_color = read_u32(camera.remote, VGC_CH1_GRID_COLOR)
        require(rest_csc == STOCK_POST_CSC_WORDS, f"Live View restored CSC mismatch: {rest_csc}")
        require(
            rest_grid_color == off_grid_color,
            f"Live View restored grid color {rest_grid_color:#010x} != {off_grid_color:#010x}",
        )
        p_rest = out_dir / "08_shooting_liveview_grid_restored_off.png"
        save_png(camera, out_dir, p_rest.name)
        phase_report["screenshots"].append(p_rest.name)

        phase_report.update(
            ok=True,
            off_ch1_csc=[hex(x) for x in off_csc],
            off_grid_enable=off_grid_en,
            off_grid_color=f"0x{off_grid_color:08x}",
            on_ch1_csc=[hex(x) for x in on_csc],
            on_ch0_csc=[hex(x) for x in on_ch0_csc],
            on_grid_color=f"0x{on_grid_color:08x}",
            scanout_grid_pixel_diff=grid_px_diff,
            restored_ch1_csc=[hex(x) for x in rest_csc],
            restored_grid_color=f"0x{rest_grid_color:08x}",
        )
    finally:
        camera.close_guest()
        shutil.copytree(camera.directory, out_dir / "session_shooting", dirs_exist_ok=True)
    return phase_report


def _is_replaceable_qemu_probe_dir(resolved: Path) -> bool:
    if not (resolved / "qemu_modified24_result.json").is_file():
        return False
    entries = {p.name for p in resolved.iterdir()}
    return bool(entries) and entries.issubset(KNOWN_QEMU_PROBE_ENTRIES)


def _validate_safe_qemu_output_dir(
    out_dir: Path, repo_dir: Path, fw_path: Path, force: bool
) -> None:
    resolved = out_dir.resolve()
    if resolved.parent == resolved:
        raise ValueError(f"Refusing filesystem root as output directory: {resolved}")
    for anc in (Path.home().resolve(), PROJECT_ROOT.resolve()):
        if resolved == anc or resolved in anc.parents:
            raise ValueError(f"Refusing unsafe output directory: {resolved}")
    protected_trees = {
        (PROJECT_ROOT / ".git").resolve(),
        (PROJECT_ROOT / "tools").resolve(),
        (PROJECT_ROOT / "patches").resolve(),
        (PROJECT_ROOT / "docs").resolve(),
        (PROJECT_ROOT / "firmware").resolve(),
        (PROJECT_ROOT / "samples").resolve(),
        (PROJECT_ROOT / "work").resolve(),
        (PROJECT_ROOT / "references").resolve(),
        repo_dir.resolve(),
    }
    for tree in protected_trees:
        if resolved == tree or resolved in tree.parents or tree in resolved.parents:
            raise ValueError(f"Refusing protected repository directory: {resolved}")
    fw_res = fw_path.resolve()
    if resolved == fw_res or resolved in fw_res.parents or fw_res in resolved.parents:
        raise ValueError(f"Refusing output directory overlapping firmware path: {resolved}")

    if out_dir.is_symlink() or (resolved.exists() and resolved.is_file()):
        raise ValueError(f"Output path is an existing file or symlink: {out_dir}")
    if resolved.exists() and any(resolved.iterdir()):
        if not force:
            raise FileExistsError(
                f"Output directory '{resolved}' already exists and is non-empty. "
                "Specify a new --output or add --force to replace a previous QEMU probe output."
            )
        if not _is_replaceable_qemu_probe_dir(resolved):
            raise ValueError(
                f"Refusing '--force' overwrite of '{resolved}': directory does not match a "
                "recognized Modified24 QEMU probe layout."
            )


def main() -> int:
    if not __debug__:
        raise RuntimeError("qemu_modified24_probe.py must not be executed with Python -O/-OO.")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, required=True, help="Path to z6-qemu repository root")
    ap.add_argument("--firmware", type=Path, required=True, help="Path to Modified24 .bi/.BIN")
    ap.add_argument("--output", type=Path, required=True, help="Output directory for screenshots & JSON")
    ap.add_argument("--expected-sha256", default=M24_EXPECTED_SHA256)
    ap.add_argument(
        "--force",
        action="store_true",
        help="Allow replacing an existing recognized Modified24 QEMU probe output directory",
    )
    args = ap.parse_args()

    repo_dir = args.repo.resolve()
    if not (repo_dir / "tools/interactive.py").is_file() or not (
        repo_dir / ".local/build-manifest.json"
    ).is_file():
        raise FileNotFoundError("Invalid --repo: missing tools/interactive.py or .local/build-manifest.json")

    fw_path = args.firmware.resolve()
    if not fw_path.is_file():
        raise FileNotFoundError(f"Firmware file does not exist: {fw_path.name}")
    fw_sha = sha256_bytes(fw_path.read_bytes())
    require(
        fw_sha == args.expected_sha256,
        f"Modified24 firmware SHA-256 mismatch: {fw_sha} != {args.expected_sha256}",
    )

    out_dir = args.output.resolve()
    _validate_safe_qemu_output_dir(out_dir, repo_dir, fw_path, args.force)
    if out_dir.exists():
        for child in list(out_dir.iterdir()):
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        out_dir.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(repo_dir / "tools"))
    import interactive as ui_mod  # type: ignore

    ui_mod.FIRMWARE = fw_path
    ui_mod.BUILD_MANIFEST = repo_dir / ".local/build-manifest.json"

    report: dict = {
        "ok": False,
        "candidate": "modified24-astro-raw-red-display-pid0526-pid1111-srgb-600s-v1",
        "firmware_sha256": fw_sha,
        "menu_phase": None,
        "shooting_grid_phase": None,
    }
    try:
        report["menu_phase"] = run_menu_phase(ui_mod, out_dir, fw_sha)
        report["shooting_grid_phase"] = run_shooting_grid_phase(ui_mod, out_dir, fw_sha)
        report["firmware_unchanged"] = sha256_bytes(fw_path.read_bytes()) == fw_sha
        require(report["firmware_unchanged"], "Firmware file mutated during QEMU run!")
        report["ok"] = True
    except Exception as exc:
        report["error"] = {
            "type": type(exc).__name__,
            "message": _sanitize_error_text(str(exc)),
        }
        print(report["error"], flush=True)
    finally:
        (out_dir / "qemu_modified24_result.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    if not report["ok"]:
        return 1
    print(
        f"MODIFIED24 QEMU PROBE PASS | SHA256={fw_sha} | "
        f"MenuCSC={report['menu_phase']['on_ch1_csc'][0]} | "
        f"GridOn={report['shooting_grid_phase']['on_grid_color']} | "
        f"PureRedZeroGBDiffPx={report['shooting_grid_phase']['scanout_grid_pixel_diff']['pure_red_zero_gb_changed_pixels']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

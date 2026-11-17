"""QEMU shooting boot, real calibration overlay, and static capture verification for Modified9 vs Modified10."""
from pathlib import Path
import argparse, hashlib, io, json, shutil, struct, sys, time, traceback
from PIL import Image


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for n in ("repo", "firmware", "output", "project"):
        p.add_argument("--" + n, type=Path, required=True)
    p.add_argument("--variant", choices=("modified9", "modified10"), required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / "probe-source.py").write_bytes(Path(__file__).read_bytes())

    sys.path.insert(0, str(a.repo / "tools"))
    import interactive as ui
    import probe

    digest = {
        "modified9": "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c",
        "modified10": "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4",
    }[a.variant]

    ui.FIRMWARE = a.firmware.resolve(strict=True)
    ui.BUILD_MANIFEST = a.repo / ".local/build-manifest.json"
    assert sha(ui.FIRMWARE.read_bytes()) == digest

    source = a.project / "analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3"
    cal = (source / "CAL38.bin").read_bytes()
    fixed = (source / "ID35.bin").read_bytes()
    assert sha(cal) == "914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372"
    assert sha(fixed) == "d52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf"

    report = dict(
        ok=False,
        scope=__doc__,
        variant=a.variant,
        firmware_sha256=digest,
        events=[],
        windows=[],
        calls=[],
        overlays=[],
        live_code_checks={},
        phase="boot",
        physical_camera=False,
        real_nef=False,
    )

    camera = ui.Camera(
        8789 if a.variant == "modified10" else 8788,
        profile="shooting",
        capture_control_test=True,
        raw_source=ui.active_manifest("native0"),
        exmcu_no_lens=True,
        tg_periodic_test=True,
        tg_paired_test=True,
        raw_ingress_test=ui.active_ingress(),
        isp_boundary_test=True,
        orientation_fixture=0,
        keep_awake=True,
        photo_liveview=True,
        allow_modified_firmware=True,
        firmware_sha256=digest,
    )
    camera.exposure_probe = True
    camera.isp_disable_cache = False
    camera.tg_period_ms = None

    points = {
        0x1017d7b6: "static_builder",
        0x1002d884: "unity_sanitizer_entry",
        0x1011d548: "frontend_dispatch",
        0x10179d5a: "id35_config_return",
        0x101229b8: "id35_descriptor",
        0x10179dd4: "temporary_exit",
        0x100bd8ec: "raw_destination",
    }
    original = ui.call_fixture

    def observe(remote, regs):
        pc = int(regs["r15"], 16)
        row = dict(
            phase=report["phase"],
            event=points[pc],
            registers=regs,
            context=remote.memory(0xc18fa844, 0xe4).hex(),
            id35_parameters=remote.memory(0xc29a3230, 0x84).hex(),
        )
        if pc == 0x1011d548:
            buf = remote.memory(0xc29a3754, 0x100)
            row["shading_dc_gains"] = [
                struct.unpack_from("<I", buf, off)[0] for off in (0x28, 0x50, 0xa0, 0xc8)
            ]
            poly_words = [
                struct.unpack_from("<I", buf, off)[0]
                for off in range(4, 0xf4, 4)
                if off not in (0x28, 0x50, 0xa0, 0xc8)
            ]
            row["nonzero_poly_terms"] = sum(x != 0 for x in poly_words)
        report["events"].append(row)

    def observed(*args, **kwargs):
        obs = dict(kwargs.get("observers") or {})
        obs.update({pc: observe for pc in points})
        kwargs["observers"] = obs
        saved = set(probe.TRACE_REPEAT)
        if report["phase"] != "boot":
            probe.TRACE_REPEAT = saved | set(points)
        try:
            r = original(*args, **kwargs)
            report["windows"].append(dict(phase=report["phase"], count=len(r["trace"]), saturated=len(r["trace"]) >= 256))
            return r
        finally:
            probe.TRACE_REPEAT = saved

    ui.call_fixture = observed
    packet = None

    def invoke(fn, payload, args):
        nonlocal packet
        r = ui.call_fixture(camera.remote, packet, fn, payload, args)
        packet = "T05thread:" + r["return_cpu"] + ";"
        report["calls"].append(dict(phase=report["phase"], function=hex(fn), result=r))
        return r

    def overlay(resource, base, offset, data):
        assert 0xc0000000 <= base < base + offset + len(data) < 0xd0000000
        before = camera.remote.memory(base + offset, len(data))
        for i in range(0, len(data), 512):
            chunk = data[i : i + 512]
            assert camera.remote.command(f"M{base + offset + i:x},{len(chunk):x}:" + chunk.hex()) == "OK"
        after = camera.remote.memory(base + offset, len(data))
        assert after == data
        report["overlays"].append(dict(
            resource=resource,
            base=hex(base),
            offset=hex(offset),
            bytes=len(data),
            before_sha256=sha(before),
            after_sha256=sha(data),
            readback_matches=True,
        ))

    def frame(name):
        data = camera.png
        im = Image.open(io.BytesIO(data)).convert("RGB")
        assert any(lo != hi for lo, hi in im.getextrema())
        (a.output / name).write_bytes(data)

    try:
        camera.boot_shooting()
        camera.pause()
        packet = camera.run_to(0x100531bc)
        camera.remote.sock.settimeout(60)
        report["boot_reached_dispatch"] = True
        frame("boot.png")

        # Verify live mapped patch bytes in QEMU XIP memory
        ae3a4_live = camera.remote.memory(0x100ae3a4, 4).hex()
        sp_live = camera.remote.memory(0x1019741a, 2).hex()
        vig_live = camera.remote.memory(0x100c2964, 4).hex()
        hook_live = camera.remote.memory(0x1017d834, 6).hex()
        report["live_code_checks"] = dict(
            ae3a4=ae3a4_live,
            spatial_1019741a=sp_live,
            vignette_100c2964=vig_live,
            builder_hook_1017d834=hook_live,
        )
        assert hook_live == "b0f626f8c046"
        if a.variant == "modified10":
            assert ae3a4_live == "0cf187f8" and sp_live == "0ee0" and vig_live == "4ff00100"
        else:
            assert ae3a4_live == "0cf166f8" and sp_live == "59b1" and vig_live == "90f85f02"

        calptr = int.from_bytes(camera.remote.memory(0xc18fa968, 4), "little")
        fixedptr = int.from_bytes(camera.remote.memory(0xc18fa96c, 4), "little")
        assert calptr and fixedptr
        report["phase"] = "real_record_overlay"
        overlay("CAL38", calptr, 0x540, cal[0x540 : 0x540 + 28 * 80])
        overlay("CAL38", calptr, 0x47180, cal[0x47180 : 0x47180 + 6600])
        overlay("CAL38", calptr, 0x49cd4, cal[0x49cd4 : 0x49da0])
        overlay("CAL38", calptr, 0x5808c, cal[0x5808c : 0x580c0])
        overlay("ID35", fixedptr, 0xacdf0, fixed[0xacdf0 : 0xb2d50])

        report["phase"] = "static_request"
        invoke(0x101efaa8, bytes(8), [1])
        request = bytearray(32)
        request[2] = 1
        struct.pack_into("<I", request, 0x10, 1)
        assert int(invoke(0x101eedb4, request, [("scratch", 0), 0x10524b7f])["return_r0"], 16) == 0
        invoke(0x10170cca, bytes(8), [100])
        report["phase"] = "static_settle"
        invoke(0x10170cca, bytes(8), [5000])

        active = [e for e in report["events"] if e["phase"].startswith("static")]
        assert len([e for e in active if e["event"] == "static_builder"]) == 1
        assert len([e for e in active if e["event"] == "unity_sanitizer_entry"]) == 1
        dispatches = [
            e for e in active
            if e["event"] == "frontend_dispatch"
            and struct.unpack_from("<I", bytes.fromhex(e["context"]), 0x84)[0] == 1
            and int(e["registers"]["r0"], 16) == 1
        ]
        assert dispatches, "Static frontend_dispatch not observed!"
        for d in dispatches:
            assert d["shading_dc_gains"] == [16384, 16384, 16384, 16384]
            assert d["nonzero_poly_terms"] == 0

        gates = [e for e in active if e["event"] == "id35_config_return"]
        assert len(gates) == 1 and struct.unpack_from("<I", bytes.fromhex(gates[0]["id35_parameters"]), 0x1c)[0] == 1
        descriptors = [e for e in active if e["event"] == "id35_descriptor"]
        assert any(int(e["registers"]["r0"], 16) == fixedptr + 0xacdf0 and int(e["registers"]["r1"], 16) == 0x5f60 for e in descriptors)
        assert any(e["event"] == "temporary_exit" for e in active)
        assert any(e["event"] == "raw_destination" for e in active)
        assert not any(w["saturated"] for w in report["windows"])

        report["phase"] = "resume"
        camera.continue_guest()
        time.sleep(1)
        camera.refresh()
        camera.pause()
        frame("after.png")
        report["final_state"] = camera.snapshot()
        assert report["final_state"]["error"] is None
        report.update(
            ok=True,
            static_unity_dispatch_count=len(dispatches),
            original_id35_transfer_preserved=True,
        )
    except Exception:
        report["error"] = traceback.format_exc()
        print(report["error"], flush=True)
    finally:
        ui.call_fixture = original
        camera.close_guest()
        report["firmware_unchanged"] = sha(ui.FIRMWARE.read_bytes()) == digest
        report["model_sources"] = {
            n: sha((a.repo / "qemu" / n).read_bytes())
            for n in ("nikon-z6.c", "nikon-z6-profile.h", "nikon-functional-isp.h", "nikon-isp-pixels.h")
        }
        report["controller_sources"] = {
            n: sha((a.repo / "tools" / n).read_bytes())
            for n in ("interactive.py", "probe.py")
        }
        shutil.copytree(camera.directory, a.output / "session")
        (a.output / "result.json").write_text(json.dumps(report, indent=2), encoding="utf8")
        print(json.dumps(dict(ok=report["ok"], variant=a.variant, events=len(report["events"]))), flush=True)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

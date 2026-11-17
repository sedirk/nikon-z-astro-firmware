"""Comprehensive Unicorn ARM/Thumb native verification for Modified10 vs Modified9 and Stock C3.80."""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP
from probe_raw_candidates import (
    Rig, ROOT, BASE, RAM, STACK, CAL, REGS, OWNER, FRAME, A, DRIVER, MMIO,
    MAINREQ, VECTOR, SPATIAL, FLAGS, TABLES, STAGE, REQ, PACKET, STORAGE,
    INPUT, OUTPUT, ENCODED, CACHE, sha,
)
from probe_still_vignette_neutral import seed, serialize, VREQ, VOUT, CURVE, MIXED, TCTX, HISTORY, AUX
import probe_release_contract as rel

STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M9_SHA = "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c"
M10_SHA = "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4"

CTX, STATE, PKT, ID35 = 0xc18fa844, 0xc18fa954, 0xc29a34c0, 0x56000000
START = 0x1017d7b6
P_REQ, P_OUT = RAM + 0x36000, RAM + 0x36100
M_CONTEXT = 0xc27631c0


def run_frontend_and_abi(blobs: dict[str, bytes], snap: dict, cal: bytes, fixed: bytes, ctx_bytes: bytes) -> dict:
    configs = [
        dict(mode=1, temp=t, submode=s, category=c, dc=d)
        for t in (0, 1) for s in (0, 2) for c in (0, 1) for d in (0, 1)
    ]
    configs += [
        dict(mode=m, temp=1, submode=0, category=c, dc=0)
        for m in range(13) if m != 1 for c in (0, 1)
    ]
    out = dict(builder_cases=0, abi_cases=0, error_cases=0, m9_m10_exact_match=True, sample_unity_regs={})
    traces = {}

    for name in ("stock", "modified9", "modified10"):
        rig = Rig(blobs[name], snap)
        u, p, g = rig.uc, rig.put, rig.get
        for addr, size in ((CAL + 0x100000, 0x68000), (ID35, 0x100000), (0x20061000, 0x1000)):
            u.mem_map(addr, size)
            rig.regions += ((addr, size),)
        writes = []

        def on_write(uc, kind, addr, size, value, _):
            writes.append((addr, size, value & ((1 << (size * 8)) - 1)))

        for lo, hi in ((0x20061000, 0x20061fff), (0x20068000, 0x20069fff)):
            u.hook_add(un.UC_HOOK_MEM_WRITE, on_write, begin=lo, end=hi)

        for idx, cfg in enumerate(configs):
            rig.reset(dict(scalar=1008, bank=0, cached=0))
            u.mem_write(CTX, ctx_bytes)
            u.mem_write(CAL, cal)
            u.mem_write(ID35, fixed)
            p(STATE + 0x18, ID35)
            p(CTX, cfg["mode"], "B")
            p(CTX + 0x84, cfg["temp"])
            p(CTX + 0x21, cfg["submode"], "B")
            p(CTX + 4, 192, "h")
            p(CTX + 8, 1536 if cfg["category"] else 1535, "i")
            p(CTX + 0xdc, cfg["dc"])
            writes.clear()
            rig.call(0x1011c750, [0, CTX], until=0x100cd752)
            rig.call(0x1011c3f4, [CTX])
            id35_writes = list(writes)
            writes.clear()
            build = rig.call(START, until=0x1011d548)
            assert int(build["registers"]["r0"], 16) == 1
            cache = bytes(u.mem_read(0xc29a3230, 0x1000))
            pkt = bytes(u.mem_read(PKT, 0x60))
            rig.call(0x100bccd0, [PKT])
            mmio_writes = list(writes)
            assert len(mmio_writes) == 507, f"Expected 507 MMIO writes, got {len(mmio_writes)}"
            traces[name, idx] = (id35_writes, cache, pkt, mmio_writes)
            out["builder_cases"] += 1

            if name in ("modified9", "modified10") and idx == 8:  # mode=1, temp=1, submode=0, cat=0, dc=0
                reg_map = {hex(a): hex(v) for a, _, v in mmio_writes}
                assert reg_map["0x20068718"] == "0x37663420"
                assert reg_map["0x20068730"] == "0x20004000"
                assert reg_map["0x2006874c"] == "0x20004000"
                assert reg_map["0x20068768"] == "0x20000000"
                assert reg_map["0x20068784"] == "0x20004000"
                assert reg_map["0x200687a0"] == "0x20004000"
                assert sum(v != 0 for a, _, v in mmio_writes if 0x20068718 <= a <= 0x200687d4) == 6
                if name == "modified10":
                    out["sample_unity_regs"] = {
                        k: reg_map[k]
                        for k in ("0x20068718", "0x2006871c", "0x20068730", "0x2006874c", "0x20068768", "0x20068784", "0x200687a0")
                    }

        # ABI & NZCV & error return checks on Modified9 and Modified10
        if name in ("modified9", "modified10"):
            seen_dispatch = []
            inject_target = [None]
            inject_code = [0]

            def dispatch_stub(uc, pc, size, _):
                seen_dispatch.append(uc.reg_read(UC_ARM_REG_R0))
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

            def err_stub(uc, pc, size, _):
                if inject_target[0] is not None and pc == inject_target[0]:
                    uc.reg_write(UC_ARM_REG_R0, inject_code[0])
                    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

            u.hook_add(un.UC_HOOK_CODE, dispatch_stub, begin=0x1011d548, end=0x1011d548)
            u.hook_add(un.UC_HOOK_CODE, err_stub)

            for temp in (0, 1):
                for flags in range(16):
                    rig.reset(dict(scalar=1008, bank=0, cached=0))
                    u.mem_write(CTX, ctx_bytes)
                    p(CTX + 0x84, temp)
                    u.mem_write(CAL, cal)
                    p(STACK + 0xf000, 0x6a6a1122)
                    p(STACK + 0x100, 0x5566aa55)
                    saved = {r: 0x90101010 + r * 0x10101 for r in range(4, 12)}
                    u.reg_write(UC_ARM_REG_CPSR, (u.reg_read(UC_ARM_REG_CPSR) & 0x0fffffff) | (flags << 28))
                    seen_dispatch.clear()
                    c_res = rig.call(START, regs=saved)
                    assert all(u.reg_read(REGS[r]) == v for r, v in saved.items())
                    assert u.reg_read(UC_ARM_REG_SP) == STACK + 0xf000
                    assert g(STACK + 0xf000) == 0x6a6a1122 and g(STACK + 0x100) == 0x5566aa55
                    assert seen_dispatch == [1] and int(c_res["registers"]["r0"], 16) == 0
                    out["abi_cases"] += 1

            # Variable-return operator error propagation check
            for op_entry, err_val in ((0x1011d6b8, 0x4), (0x1011db02, 0x80), (0x1011e940, 0x80000001), (0x1011ebb8, 0x10)):
                inject_target[0] = op_entry
                inject_code[0] = err_val
                rig.reset(dict(scalar=1008, bank=0, cached=0))
                u.mem_write(CTX, ctx_bytes)
                p(CTX + 0x84, 1)
                u.mem_write(CAL, cal)
                seen_dispatch.clear()
                c_res = rig.call(START)
                assert seen_dispatch == [1]
                assert int(c_res["registers"]["r0"], 16) == err_val
                out["error_cases"] += 1
            inject_target[0] = None

        rig.uc = None
        rig = None
        gc.collect()

    for idx in range(len(configs)):
        assert traces["modified9", idx] == traces["modified10", idx], f"Frontend trace diverged at config {idx}"
        # Descriptors and ID35 writes must also match Stock
        assert traces["stock", idx][0] == traces["modified10", idx][0], f"ID35 diverged at config {idx}"
        assert traces["stock", idx][2] == traces["modified10", idx][2], f"Packet descriptor diverged at config {idx}"

    return out


def run_release_contract(blobs: dict[str, bytes], snap: dict) -> dict:
    configs = [
        dict(name=f"f{depth}{wide}-m{mode}-s{size}-a0", depth=depth, wide=wide, mode=mode, size=size, area=0)
        for depth, wide in ((0, 0), (1, 0), (1, 1))
        for mode in (0, 1, 2)
        for size in (0, 1, 2)
    ]
    configs.append(dict(name="f10-m1-s0-a1", depth=1, wide=0, mode=1, size=0, area=1))
    configs.extend(
        dict(name=f"observed-readout-f{depth}0-m{mode}", depth=depth, wide=0, mode=mode, size=0, area=0, readout=1)
        for depth in (0, 1) for mode in (0, 1, 2)
    )

    contract_rows = {}
    guard_rows = {}
    for name, role in (("modified9", "original"), ("modified10", "still-preserve-fullsize-raw")):
        rig = Rig(blobs[name], snap)
        rig.uc.mem_map(rel.CODEC_MMIO, 4096)
        rig.uc.hook_add(un.UC_HOOK_MEM_WRITE, rig.on_write, begin=rel.CODEC_MMIO, end=rel.CODEC_MMIO + 4095)
        for cfg in configs:
            res = rel.run(rig, role, cfg)
            if role == "still-preserve-fullsize-raw" and cfg["size"] == 0:
                assert res["selected_handle"] == hex(INPUT)
                assert res["geometry_equals_backend"] is True
                assert res["early_cleanup_selected"] == hex(OUTPUT)
                assert res["release_selected"] == hex(INPUT)
            elif cfg["size"] in (1, 2):
                assert res["selected_handle"] == hex(OUTPUT)
            contract_rows[name, cfg["name"]] = res

        for kind in (0, 2, 3, 6, 7):
            for mode in (0, 1, 2, 3):
                for size in (0, 1, 2):
                    for has_output in (False, True):
                        cfg_g = dict(scalar=300, bank=0, cached=0, owner_mode=mode, kind=kind, output=has_output)
                        rig.reset(cfg_g)
                        rig.put(OWNER + 0x192, size, "B")
                        rig.put(REQ + 0x1a8, 0x5a5a5a5a)
                        rig.call(0x100ae33e, [STAGE], until=0x100b4c78)
                        expected = has_output and mode in (0, 1) and kind not in (3, 4, 5, 6)
                        if name == "modified10":
                            expected = expected and size != 0
                        val = rig.get(REQ + 0x1a8)
                        assert val == (OUTPUT if expected else 0)
                        guard_rows[name, (kind, mode, size, has_output)] = val

        rig.uc = None
        rig = None
        gc.collect()

    # Verify medium/small sizes (size 1 and 2) are byte-for-byte identical in request & encoder setup
    for cfg in configs:
        if cfg["size"] in (1, 2):
            a, b = contract_rows["modified9", cfg["name"]], contract_rows["modified10", cfg["name"]]
            assert a["prepared_request"] == b["prepared_request"]
            assert a["encoder_packet"] == b["encoder_packet"]
            assert a["codec_registers"] == b["codec_registers"]

    changed_guards = [
        k for k in (
            (kind, mode, size, has_output)
            for kind in (0, 2, 3, 6, 7)
            for mode in (0, 1, 2, 3)
            for size in (0, 1, 2)
            for has_output in (False, True)
        )
        if guard_rows["modified9", k] != guard_rows["modified10", k]
    ]
    # Exactly 3 non-special kinds (0, 2, 7) * 2 RAW modes (0, 1) * size=0 * has_output=True = 6 cases
    assert len(changed_guards) == 6 and all(k[2] == 0 and k[3] is True and k[1] in (0, 1) for k in changed_guards)

    return dict(
        descriptor_encoder_cases=len(configs) * 2,
        guard_cases=len(guard_rows),
        changed_guard_cases_vs_m9=len(changed_guards),
        resized_sizes_unchanged=True,
        fullsize_geometry_matches_backend=True,
    )


def run_spatial_and_backend_chains(blobs: dict[str, bytes], snap: dict) -> dict:
    # Real non-zero coefficients observed on Z61_4945.NEF (Modified9)
    coefs = [2122853, -1812904, 1751073, 0]
    spatial = [142, -79, 0, -74, -6, 61]
    cfgs = [
        dict(cached=c, bank=b, slot=s, cache_flags=f, size=sz)
        for c, b, s, f, sz in itertools.product((0, 1), (0, 1), (0, 1), ([0, 1], [1, 1]), (0, 1))
    ]
    summary = dict(chain_executions=0, m9_active_tag7_count=0, m10_active_tag7_count=0, m10_zero_spatial_mmio=True)

    for name in ("modified9", "modified10"):
        rig = Rig(blobs[name], snap)
        u, p, g = rig.uc, rig.put, rig.get
        for cfg in cfgs:
            seed(rig, dict(cached=cfg["cached"], strength=2, owner_neutral=0, bank=cfg["bank"]), coefs, spatial)
            p(OWNER + 0x192, cfg["size"], "B")
            p(OWNER + 0x308 + 0x26, 256, "H")
            u.mem_write(OWNER + 0x308 + 0x28, struct.pack("<9H", *([256] * 9)))
            u.mem_write(OWNER + 0x308 + 0x3a, struct.pack("<4H", *([512] * 4)))
            u.mem_write(OWNER + 0x308 + 0x42, struct.pack("<5HB", 300, 300, 300, 300, 32000, 0))
            u.mem_write(OWNER + 0x378, struct.pack("<4B6i", *cfg["cache_flags"], 0, 0, *spatial))
            p(OWNER + 0x227c + 0x5a, 0, "B")
            p(P_REQ, FRAME)
            p(P_REQ + 4, CACHE)
            if cfg["cached"]:
                p(P_REQ + 8, OWNER + 0x308)
                p(P_REQ + 12, OWNER + 0x342)
                p(P_REQ + 16, OWNER + 0x34a)
            u.mem_write(P_REQ + 0x14, struct.pack("<2H", 6064, 4040))
            p(P_REQ + 0x18, 1)
            p(P_REQ + 0x1c, 0)
            p(P_REQ + 0x20, 0, "B")
            p(P_REQ + 0x21, cfg["cached"], "B")
            u.mem_write(P_OUT, struct.pack("<4I", STAGE + 0x3e8, STAGE + 0x468, OWNER + 0x85c, 0))
            for ptr, n in ((STAGE + 0x3e8, 0x34), (STAGE + 0x468, 0x6c), (SPATIAL, 68)):
                u.mem_write(ptr, b"\x6b" * n)

            rig.call(0x100c24d4, [P_REQ, P_OUT])
            for off, val in (
                (4, CACHE),
                (8, OWNER + 0x308 if cfg["cached"] else 0),
                (12, OWNER + 0x342 if cfg["cached"] else 0),
                (16, OWNER + 0x34a if cfg["cached"] else 0),
                (20, STAGE + 0x3e8),
                (24, STAGE + 0x468),
                (36, 1),
                (40, 0),
            ):
                p(MAINREQ + off, val)
            p(MAINREQ + 0x2e, cfg["cached"], "B")
            rig.call(0x100c2824, [MAINREQ, VECTOR])

            if not cfg["cached"]:
                p(OWNER + 0x227c, 0, "B")
            rig.call(0x100c29c6, [VREQ, VOUT])

            p(FLAGS + 0x2c, cfg["slot"], "B")
            for off, val in ((0, FLAGS), (4, SPATIAL), (8, 0), (12, MIXED), (20, TCTX)):
                p(VREQ + off, val)
            p(VREQ + 16, 1, "B")
            p(VREQ + 17, 0, "B")
            p(AUX, TABLES)
            p(AUX + 4, AUX + 0x100)
            p(AUX + 8, AUX + 0x200)
            rig.call(0x10171dbc, [VREQ, HISTORY, AUX])
            rig.call(0x100ae33e, [STAGE], until=0x100b4c78)
            rig.call(0x100b5716, [REQ, PACKET, STORAGE])
            bank = MMIO + cfg["bank"] * 0x40000
            u.mem_write(bank + 0x1200, b"\x5a" * 72)
            rig.call(0x100d5c86, [DRIVER, PACKET, 0, 0])

            # Neighborhood clamping off in BOTH Modified9 and Modified10
            assert g(bank + 0x584) == 0 and g(bank + 0x594) == 0

            rig.call(0x10305628)
            tag6, _ = serialize(rig, 6)
            tag7, _ = serialize(rig, 7)

            rig.call(0x100ae41e, until=0x100ae438, regs={4: FRAME, 5: REQ})
            enc = rig.call(0x100af648, [STAGE], until=0x100a323e)

            if name == "modified9":
                summary["m9_active_tag7_count"] += int(tag7[0x5a] != 0)
                assert g(bank + 0x580) == 1 and g(bank + 0x67c) == 0x300
                assert g(FRAME + 0x1f8) == OUTPUT and enc["registers"]["r0"] == hex(OUTPUT + 0x24)
            else:
                # Modified10 assertions:
                assert bytes(u.mem_read(CURVE, 514)) == struct.pack("<257H", *([1024] * 257))
                selected = 0x2a94 if cfg["slot"] else 0x2890
                assert bytes(u.mem_read(bank + selected, 516)) == struct.pack("<257H", *([1024] * 257)) + b"\0\0"
                assert bytes(u.mem_read(bank + 0x1200, 72)) == bytes(72)
                # NEFInfo 0x0006 & 0x0007 neutralized
                assert bytes(u.mem_read(OWNER + 0x1014, 18)) == bytes(18)
                c6 = [struct.unpack_from("<i", tag6, k)[0] for k in (0x44, 0x34, 0x24, 0x14)]
                l6 = struct.unpack_from("<I", tag6, 0x60)[0]
                c7 = [struct.unpack_from("<i", tag7, k)[0] for k in (0x2c, 0x1c, 0x14, 0x50, 0x40, 0x38)]
                assert c6 == [0, 0, 0, 0] and l6 == 0
                assert tag7[0x5a] == 0 and (c7 == [0, 0, 0, 0, 0, 0] if not cfg["cached"] else True)
                summary["m10_active_tag7_count"] += int(tag7[0x5a] != 0)

                if cfg["size"] == 0:
                    # Full-size RAW bypasses backend replacement buffer!
                    assert g(REQ + 0x1a8) == 0
                    assert g(bank + 0x580) == 0 and g(bank + 0x67c) == 0x100
                    assert g(FRAME + 0x1f8) == INPUT
                    assert enc["registers"]["r0"] == hex(INPUT + 0x24)
                else:
                    # Medium/small RAW retains backend resize replacement buffer!
                    assert g(REQ + 0x1a8) == OUTPUT
                    assert g(bank + 0x580) == 1 and g(bank + 0x67c) == 0x300
                    assert g(FRAME + 0x1f8) == OUTPUT
                    assert enc["registers"]["r0"] == hex(OUTPUT + 0x24)

            summary["chain_executions"] += 1

        rig.uc = None
        rig = None
        gc.collect()

    assert summary["m9_active_tag7_count"] > 0 and summary["m10_active_tag7_count"] == 0
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / Path(__file__).name).write_bytes(Path(__file__).read_bytes())

    blobs = {
        "stock": (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes(),
        "modified9": (ROOT / "outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN").read_bytes(),
        "modified10": (ROOT / "analysis/modified10-preflash-2026-11-13/lab-build/modified10-candidate.bi").read_bytes(),
    }
    assert sha(blobs["stock"]) == STOCK_SHA
    assert sha(blobs["modified9"]) == M9_SHA
    assert sha(blobs["modified10"]) == M10_SHA

    cal = (ROOT / "analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/CAL38.bin").read_bytes()
    fixed = (ROOT / "analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/ID35.bin").read_bytes()
    assert sha(cal) == "914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372"
    assert sha(fixed) == "d52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf"

    snap = json.loads((ROOT / "analysis/raw-vignette-state-2026-11-08/native-selector/result.json").read_text(encoding="utf8"))["final"]
    ev = json.loads((ROOT / "analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json").read_text(encoding="utf8"))
    ctx_bytes = bytes.fromhex(next(e for e in ev if e["event"] == "static_front_builder")["memory"]["context"]["bytes"])

    report = dict(ok=False, candidate_sha256=M10_SHA, parent_sha256=M9_SHA, stock_sha256=STOCK_SHA)
    try:
        report["frontend_and_abi"] = run_frontend_and_abi(blobs, snap, cal, fixed, ctx_bytes)
        report["release_contract"] = run_release_contract(blobs, snap)
        report["spatial_and_backend_chains"] = run_spatial_and_backend_chains(blobs, snap)
        report["ok"] = True
    except Exception:
        report["error"] = traceback.format_exc()
        raise
    finally:
        (args.output / "result.json").write_text(json.dumps(report, indent=2), encoding="utf8")
        print(json.dumps({
            "ok": report["ok"],
            "frontend_cases": report.get("frontend_and_abi", {}).get("builder_cases"),
            "abi_cases": report.get("frontend_and_abi", {}).get("abi_cases"),
            "error_cases": report.get("frontend_and_abi", {}).get("error_cases"),
            "contract_cases": report.get("release_contract", {}).get("descriptor_encoder_cases"),
            "guard_cases": report.get("release_contract", {}).get("guard_cases"),
            "chain_cases": report.get("spatial_and_backend_chains", {}).get("chain_executions"),
        }))


if __name__ == "__main__":
    main()

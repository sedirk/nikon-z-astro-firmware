"""Bounded native completion-path diagnosis; no emulated capture success.

Run the original frontend start, interrupt callback, event wrapper and error
branch against m4 and the recalled m5 bytes. RTOS event and mutex services are
explicit fixtures. Interrupt status is injected between stopped native segments;
no hardware-generated interrupt, sensor pixels, shutter movement or NEF exists.
"""
from pathlib import Path
import argparse, gc, json, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP
from probe_raw_candidates import Rig, ROOT, REGS, STOP, sha
from verify_modified5_recovery import DIGESTS, REVOKED

EVENT, HANDLE, CTX = 0xc29a31d4, 0x50055000, 0xc18fa844
MUTEX = (0x10170df0, 0x10170dea)
OS_SET, OS_CLEAR, OS_WAIT = 0x10036334, 0x10035e94, 0x10036504


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); a.output.mkdir(parents=True, exist_ok=False)
    snapshots_path = ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json'
    snapshots = json.loads(snapshots_path.read_text(encoding='utf8'))['final']
    report = dict(ok=False, scope=__doc__, source_snapshots_sha256=sha(snapshots_path.read_bytes()),
                  cases=[], interrupt_is_injected=True, hardware_causality_proven=False,
                  physical_recovery_confirmed=False, image_algorithm_supplied=False)
    variants = [('modified4', ROOT/'outputs/Z6-C380-recovery-from-modified5-2026-11-10/01_RECOVER_MODIFIED4/EG162080.BIN', DIGESTS['modified4']),
                ('recalled_modified5', ROOT/'analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED', REVOKED)]
    for name in (Path(__file__).name, 'probe_raw_candidates.py', 'verify_modified5_recovery.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    try:
        for variant, path, digest in variants:
            blob = path.read_bytes(); assert sha(blob) == digest
            r = Rig(blob, snapshots); u = r.uc
            u.mem_map(0x20060000, 0x2000); r.regions += ((0x20060000, 0x2000),)
            services, hardware = [], []
            state = dict(flags=0)

            def service(uc, pc, size, _):
                args = [uc.reg_read(reg) for reg in REGS[:4]]
                row = dict(pc=hex(pc), args=[hex(x) for x in args])
                result = 0
                if pc in (OS_SET, OS_CLEAR, OS_WAIT):
                    assert args[0] == HANDLE
                    if pc == OS_SET:
                        state['flags'] |= args[1]
                    elif pc == OS_CLEAR:
                        state['flags'] &= args[1]
                    else:
                        assert args[1] == 8 and args[2] == 0
                        row['timeout_argument'] = r.get(uc.reg_read(UC_ARM_REG_SP))
                        assert row['timeout_argument'] == 50
                        got = state['flags'] & args[1]
                        r.put(args[3], got)
                        result = 0 if got else 1  # fixture: 0 is RTOS success
                        row.update(observed_flags=hex(state['flags']), written_result=hex(got),
                                   injected_rtos_result=result)
                row['flags_after'] = hex(state['flags']); services.append(row)
                uc.reg_write(UC_ARM_REG_R0, result)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

            def write(uc, access, addr, size, value, _):
                hardware.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)), address=hex(addr),
                                     size=size, value=hex(value)))

            for pc in (*MUTEX, OS_SET, OS_CLEAR, OS_WAIT):
                u.hook_add(un.UC_HOOK_CODE, service, begin=pc, end=pc)
            u.hook_add(un.UC_HOOK_MEM_WRITE, write, begin=0x20060000, end=0x20061fff)
            for status in (0, 0x10, 0x80, 0x400, 0x40000, 0x90):
                for previous_error in (0, 4):
                    report['current_case'] = [variant, hex(status), previous_error]
                    r.reset(dict(scalar=1008, bank=0, cached=0))
                    r.put(EVENT, HANDLE); r.put(0xc18fa7a0+4, 0)
                    state['flags'] = 0xfff; services.clear(); hardware.clear()
                    # Begin after table construction. This is NOT a whole shot.
                    start = r.call(0x10179d82, until=0x10179da4, regs={4:CTX, 5:previous_error})
                    assert state['flags'] == 0xff7
                    state['flags'] = 0  # other events excluded from this fixture
                    saved = u.context_save()
                    callback = r.call(0x10178de8, [0, status])
                    after_callback = state['flags']
                    u.context_restore(saved)
                    r.blocks.clear()
                    u.emu_start(0x10179da5, 0x10179dc4, count=10000)
                    assert u.reg_read(UC_ARM_REG_PC) == 0x10179dc4
                    status_after_wait = u.reg_read(REGS[5])
                    expected = previous_error | (0 if status & 0x10 else 0x20)
                    assert status_after_wait == expected
                    expected_flags = (8 if status & 0x10 else 0) | (4 if status & 0x80 else 0) | (32 if status & 0x400 else 0) | (16 if status & 0x40000 else 0)
                    assert after_callback == expected_flags
                    assert state['flags'] & 8 == 0
                    report['cases'].append(dict(variant=variant, module_sha256=digest,
                        injected_callback_status=hex(status), previous_error=hex(previous_error),
                        flags_from_native_callback=hex(after_callback), status_after_native_wait_branch=hex(status_after_wait),
                        start_blocks=start['blocks'], callback_blocks=callback['blocks'], wait_blocks=list(r.blocks),
                        services=list(services), hardware_writes=list(hardware)))
            del u, r; gc.collect()
        first, second = report['cases'][:12], report['cases'][12:]
        keys = ('injected_callback_status', 'previous_error', 'flags_from_native_callback',
                'status_after_native_wait_branch', 'start_blocks', 'callback_blocks', 'wait_blocks', 'services', 'hardware_writes')
        assert len(first) == len(second) == 12
        for x, y in zip(first, second):
            for key in keys: assert x[key] == y[key], key
        report.update(ok=True, native_case_count=24, identical_completion_paths=True,
            conclusion='Callback bit 0x10 sets event 8; absent event 8, the unchanged native wait branch ORs 0x20 into local status. This does not establish that ID35 suppression caused the missing event on hardware.')
        report.pop('current_case', None)
    except Exception:
        report['error'] = traceback.format_exc()
    (a.output/'result.json').write_bytes(json.dumps(report, ensure_ascii=False, indent=2).encode('utf8'))
    print(json.dumps(dict(ok=report['ok'], cases=len(report['cases']), output=str(a.output), error=report.get('error'))))
    return 0 if report['ok'] else 1


if __name__ == '__main__': raise SystemExit(main())

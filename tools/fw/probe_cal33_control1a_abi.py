"""Native control1a LAB ABI and incoming-flag audit; only final hardware dispatch is stubbed."""
from pathlib import Path
import argparse, json, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_CPSR
from probe_raw_candidates import Rig, ROOT, CAL, REGS, STACK, sha
from prepare_cal33_control1a_lab import START, TARGET, PARENT, PARENT_SHA

ROUND = ROOT / 'analysis/raw-spatial-controls-2026-11-12'
CTX = 0xc18fa844

def read(p):
    return json.loads(p.read_text())

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    a = ap.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    m = read(ROUND / 'static-cal33-lab/manifest.json')
    cal = (ROOT / 'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/CAL38.bin').read_bytes()
    snap = read(ROOT / 'analysis/raw-vignette-state-2026-11-08/native-selector/result.json')['final']
    ev = read(ROOT / 'analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json')
    ctx = bytes.fromhex(next(e for e in ev if e['event'] == 'static_front_builder')['memory']['context']['bytes'])
    report = dict(ok=False, scope=__doc__, rows=[], lab_sha256=m['sha256'])
    cache = {}
    rig = None
    try:
        for name, path, digest in [('modified4', ROOT / PARENT, PARENT_SHA), ('lab', ROUND / 'static-cal33-lab' / m['module'], m['sha256'])]:
            b = path.read_bytes()
            assert sha(b) == digest
            rig = Rig(b, snap)
            u, p, g = rig.uc, rig.put, rig.get
            u.mem_map(CAL + 0x100000, 0x68000)
            rig.regions += ((CAL + 0x100000, 0x68000),)
            seen = []
            def dispatch(uc, pc, size, _):
                seen.append(uc.reg_read(UC_ARM_REG_R0))
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            u.hook_add(un.UC_HOOK_CODE, dispatch, begin=0x1011d548, end=0x1011d548)
            for temp in (0, 1):
                for flags in range(16):
                    rig.reset(dict(scalar=1008, bank=0, cached=0))
                    u.mem_write(CTX, ctx)
                    p(CTX + 0x84, temp)
                    u.mem_write(CAL, cal)
                    p(STACK + 0xf000, 0x6a6a1122)
                    p(STACK + 0x100, 0x5566aa55)
                    saved = {i: 0x90101010 + i * 0x10101 for i in range(4, 12)}
                    u.reg_write(UC_ARM_REG_CPSR, (u.reg_read(UC_ARM_REG_CPSR) & 0x0fffffff) | (flags << 28))
                    seen.clear()
                    call = rig.call(START, regs=saved)
                    assert all(u.reg_read(REGS[i]) == v for i, v in saved.items())
                    assert u.reg_read(UC_ARM_REG_SP) == STACK + 0xf000 and g(STACK + 0xf000) == 0x6a6a1122 and g(STACK + 0x100) == 0x5566aa55
                    assert seen == [1] and bytes(u.mem_read(CAL, len(cal))) == cal
                    data = bytes(u.mem_read(0xc29a3230, 0x1000))
                    cache[name, temp, flags] = data
                    assert data == cache[name, temp, 0]
                    report['rows'].append(dict(variant=name, temporary=temp, incoming_nzcv=flags, callee_saved=True, stack_preserved=True,
                        dispatched_argument=seen[0], return_value=call['registers']['r0'], cached_control=g(TARGET, 'B'), cache_sha256=sha(data)))
        for temp in (0, 1):
            for flags in range(16):
                x, y = cache['modified4', temp, flags], cache['lab', temp, flags]
                assert [k for k, (a_b, b_b) in enumerate(zip(x, y)) if a_b != b_b] == [TARGET - 0xc29a3230]
        report['ok'] = True
    except Exception:
        report['error'] = traceback.format_exc()
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf8')
        print(json.dumps(dict(ok=report['ok'], rows=len(report['rows']))))

if __name__ == '__main__':
    main()

"""Native automatic-parameter arithmetic on explicit synthetic scalar inputs.

No firmware patch, service stub, forced return, MMIO or RAW pixel operation.
External-context kind=0 selects the native false scaling-flag path. The physical
units of coefficients, calibration fields and returned parameters are unknown.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import traceback
import unicorn as un
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
BASE, CONTEXT = 0x10020000, 0xc1884918
CONFIG, READY, EXTERNAL = 0xc20aa7c8, 0xc18812b4, 0xc18844e8
INPUT, FRAME, FRAME_CONFIG = 0x50000000, 0x50001000, 0x50002000
CAL, STATS, OUTPUT, AUTO = 0x50003000, 0x50004000, 0x50005000, 0x50006000
STACK, STOP = 0x52000000, 0x53000000
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output / 'probe-source.py').write_bytes(source)
firmware = ROOT / 'firmware/decoded/eg1620_038000.bi'
blob = firmware.read_bytes()
assert hashlib.sha256(blob).hexdigest() == SHA
uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
rom_size = (len(blob) + 4095) & ~4095
uc.mem_map(BASE, rom_size)
uc.mem_write(BASE, blob)
uc.mem_protect(BASE, rom_size, un.UC_PROT_READ | un.UC_PROT_EXEC)
for addr, size in ((INPUT, 0x10000), (STACK, 0x10000), (STOP, 4096)):
    uc.mem_map(addr, size)
for page in sorted({CONTEXT & ~4095, READY & ~4095, CONFIG & ~4095}):
    uc.mem_map(page, 4096)
    for off in range(0x14000, 0x14120, 16):
        src, dst, size, handler = struct.unpack_from('<4I', blob, off)
        lo, hi = max(page, dst), min(page + 4096, dst + size)
        if lo < hi and handler == 0x1002006c:
            uc.mem_write(lo, blob[src - BASE + lo - dst:src - BASE + hi - dst])


def word(address, value):
    uc.mem_write(address, struct.pack('<I', value & 0xffffffff))


def signed(value, bits=32):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def trunc(n, d):
    return abs(n) // d * (-1 if n < 0 else 1)


blocks = set()
uc.hook_add(un.UC_HOOK_BLOCK, lambda _uc, address, _size, _data: blocks.add(address))


def execute(entry, args):
    blocks.clear()
    for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
        uc.reg_write(register, value)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0xf000)
    uc.reg_write(UC_ARM_REG_LR, STOP | 1)
    uc.emu_start(entry | 1, STOP, count=30000)
    assert uc.reg_read(UC_ARM_REG_PC) == STOP
    return dict(entry=hex(entry), arguments=[hex(v) for v in args],
                returned_signed=signed(uc.reg_read(UC_ARM_REG_R0)),
                blocks=[hex(v) for v in sorted(blocks)])


word(READY, 1)
word(EXTERNAL, 0)
word(CONTEXT + 0x24, STATS)
word(CONTEXT + 0x34, CAL)
word(INPUT, FRAME)
word(FRAME + 0x130, FRAME_CONFIG)
word(CAL + 0x110, 0)  # Native automatic branch, unlike the preceding experiment.
word(CAL + 0x154, 4096)
word(CAL + 0x1b8, 16)
word(CAL + 0x1bc, 500)
word(CAL + 0x1c0, 1000)
report = dict(ok=False, firmware_sha256=SHA, probe_sha256=hashlib.sha256(source).hexdigest(),
              unicorn_version=un.__version__, scope=__doc__, polynomial_cases=[], automatic_cases=[], alternate_cases=[],
              assumptions=dict(external_context_kind=0, config_ready=1, calibration_110=0,
                  calibration_154=4096, calibration_1b8=16, calibration_1bc=500, calibration_1c0=1000,
                  pointers='Private scratch objects; three RAM pages initialized from ROM startup copies.',
                  mode_scale=bytes(uc.mem_read(0xc1884d53, 9)).hex()))
try:
    # With x << 8 representable as a positive int32, the instruction sequence
    # is a 64-bit fixed-point polynomial. Cases stay inside that explicit domain.
    for x in (0, 65536, 250000, 1000000):
        for coefficients in ((15872, 0, 0), (10000, 1, 2), (10000, -1, -2), (-10000, 1, 2)):
            uc.mem_write(AUTO, struct.pack('<3i', *coefficients))
            uc.mem_write(OUTPUT, b'Z' * 36)
            row = execute(0x1011300e, [x, AUTO, OUTPUT])
            actual = struct.unpack('<i', uc.mem_read(OUTPUT, 4))[0]
            c, quadratic, linear = coefficients
            numerator = signed((c << 32) + quadratic * x * x + linear * x * (1 << 18), 64)
            expected = signed(trunc(trunc(numerator, 65536), 65536))
            row.update(x=x, coefficients=list(coefficients), output=actual, expected=expected,
                       guard_unchanged=uc.mem_read(OUTPUT + 4, 32) == b'Z' * 32)
            report['polynomial_cases'].append(row)
            assert actual == expected and row['guard_unchanged'], row
    # Reference parameter below, inside and above the polynomial-output interval.
    for selector, reference in enumerate((8000, 15872, 30000)):
        word(CAL + 0x1ac + 4 * selector, reference)
    for strength in (128, 512, 2048):
        for selector in (0, 1, 2):
            for mode in (0, 5, 9):
                uc.mem_write(FRAME_CONFIG + 0x54, bytes([selector]))
                uc.mem_write(AUTO, struct.pack('<4i', strength, 15872, 0, 0))
                automatic = execute(0x1011308c, [INPUT, mode, AUTO])
                result = automatic['returned_signed']
                if selector == 1 or mode == 9:
                    assert result == 0
                row = dict(strength=strength, coefficients=[15872, 0, 0], selector=selector,
                           mode=mode, reference=(8000, 15872, 30000)[selector], automatic_call=automatic,
                           parameter_calls=[])
                report['automatic_cases'].append(row)
                for flag in (0, 1):
                    uc.mem_write(CONFIG + 0x29c, bytes([flag]))
                    uc.mem_write(OUTPUT, b'Z' * (0xac + 32))
                    word(CONTEXT + 0x1c, 0x13572468)
                    call = execute(0x10114136, [INPUT, mode, AUTO, OUTPUT])
                    cache = struct.unpack('<I', uc.mem_read(CONTEXT + 0x1c, 4))[0]
                    half = trunc(result, 2)
                    if result & 1:
                        half += 1 if half > 0 else -1
                    expected = 0 if flag else max(-512, min(511, half)) & 0x3ff
                    output = bytes(uc.mem_read(OUTPUT, 0xac))
                    slots = list(struct.unpack_from('<4H', output, 0x62))
                    expected_slots = [0] * 4
                    expected_slots[selector if mode == 0 else 3] = expected
                    call.update(config_29c=flag, cached=cache, expected_cached=expected,
                                slots=slots, output=output.hex(),
                                guard_unchanged=uc.mem_read(OUTPUT + 0xac, 32) == b'Z' * 32)
                    row['parameter_calls'].append(call)
                    assert cache == expected and slots == expected_slots and call['guard_unchanged']
                    assert ('0x1011308c' in call['blocks']) == (flag == 0)
    # With all else fixed, mode 5 selects ROM scale 3 versus mode 0 scale 1.
    for strength in (128, 512, 2048):
        for selector in (0, 1, 2):
            pair = [r['automatic_call']['returned_signed'] for r in report['automatic_cases']
                    if r['strength'] == strength and r['selector'] == selector and r['mode'] in (0, 5)]
            assert pair[1] == 3 * pair[0]
    assert any(r['automatic_call']['returned_signed'] < 0 for r in report['automatic_cases'])
    assert any(r['automatic_call']['returned_signed'] > 0 for r in report['automatic_cases'])
    # Wrapper 10114aca selects this separate builder when calibration +1a4=1.
    # It copies four native fields without consulting 0x29c or refreshing +1c.
    alternate = INPUT + 0x8000
    word(CONTEXT + 0x38, alternate)
    word(CONTEXT + 0x3c, 0x51000000)  # Addresses are selected but table bytes are not read.
    for offset, value in ((0xb4, 0x155), (0xbc, 0x21), (0xb8, 0x12), (0xc0, 0x33), (0xc4, 0x44)):
        word(alternate + offset, value)
    report['assumptions']['alternate'] = dict(context_38=hex(alternate), context_3c='0x51000000',
        calibration_fields={'0xb4': 0x155, '0xbc': 0x21, '0xb8': 0x12, '0xc0': 0x33, '0xc4': 0x44},
        scope='Direct 101146f4 call; its wrapper selection is established separately by disassembly.')
    for flag in (0, 1):
        for mode in (0, 2, 5):
            for selector in (0, 2):
                uc.mem_write(CONFIG + 0x29c, bytes([flag]))
                uc.mem_write(FRAME_CONFIG + 0x54, bytes([selector]))
                word(CONTEXT + 0x1c, 0x13572468)
                uc.mem_write(OUTPUT, bytes(0xac) + b'Z' * 32)
                call = execute(0x101146f4, [INPUT, mode, OUTPUT])
                params = bytes(uc.mem_read(OUTPUT, 0xac))
                slots = list(struct.unpack_from('<4H', params, 0x62))
                cache = struct.unpack('<I', uc.mem_read(CONTEXT + 0x1c, 4))[0]
                row = dict(config_29c=flag, mode=mode, selector=selector, call=call, parameters=params.hex(),
                           slots=slots, cached_after=hex(cache),
                           guard_unchanged=uc.mem_read(OUTPUT + 0xac, 32) == b'Z' * 32)
                report['alternate_cases'].append(row)
                assert call['returned_signed'] == 0 and slots == [0x21, 0x12, 0x33, 0x44]
                assert '0x101cb734' not in call['blocks'] and cache == 0x13572468 and row['guard_unchanged']
    report['ok'] = True
except Exception:
    report['error'] = traceback.format_exc()
    raise
finally:
    report['firmware_unchanged'] = hashlib.sha256(firmware.read_bytes()).hexdigest() == SHA
    (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'], polynomial_cases=len(report['polynomial_cases']),
                         automatic_cases=len(report['automatic_cases']), alternate_cases=len(report['alternate_cases']),
                         firmware_unchanged=report['firmware_unchanged'])))

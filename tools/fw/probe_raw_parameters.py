"""Execute C3.80 parameter builders on declared synthetic inputs, not RAW pixels.

No function stubs or firmware patches. No memory-write hook. The signed-value
cases select the native override-input branch, not a real sensor measurement.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys
import capstone
import unicorn as un
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
CONTEXT, CONFIG, READY = 0xc1884918, 0xc20aa7c8, 0xc18812b4
INPUT, FRAME, FRAME_CONFIG = 0x50000000, 0x50001000, 0x50002000
OVERRIDE, STATS, OUTPUT = 0x50003000, 0x50004000, 0x50005000
TABLE, STACK, STOP = 0x51000000, 0x52000000, 0x53000000

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output / 'probe-source.py').write_bytes(source)
image = ROOT / 'firmware/decoded/eg1620_038000.bi'
data = image.read_bytes()
assert hashlib.sha256(data).hexdigest() == SHA
uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
rom_size = (len(data) + 4095) & ~4095
uc.mem_map(BASE, rom_size)
uc.mem_write(BASE, data)
uc.mem_protect(BASE, rom_size, un.UC_PROT_READ | un.UC_PROT_EXEC)
for addr, size in ((INPUT, 0x10000), (STACK, 0x10000), (STOP, 0x1000)):
    uc.mem_map(addr, size)
for page in (0xc25ee000, 0xc180b000, 0x2006b000):
    uc.mem_map(page, 4096)
for page in sorted({CONTEXT & ~4095, CONFIG & ~4095, READY & ~4095}):
    uc.mem_map(page, 4096)
    for offset in range(0x14000, 0x14120, 16):
        src, dest, size, handler = struct.unpack_from('<4I', data, offset)
        lo, hi = max(page, dest), min(page + 4096, dest + size)
        if lo < hi and handler == 0x1002006c:
            rom = src - BASE + lo - dest
            uc.mem_write(lo, data[rom:rom + hi - lo])

def word(addr, value):
    uc.mem_write(addr, struct.pack('<I', value & 0xffffffff))

word(READY, 1)
word(CONTEXT + 0x24, STATS)
word(CONTEXT + 0x34, OVERRIDE)
word(CONTEXT + 0x3c, TABLE)
word(OVERRIDE + 0x110, 1)
word(INPUT, FRAME)
word(FRAME + 0x130, FRAME_CONFIG)
blocks = set()
uc.hook_add(un.UC_HOOK_BLOCK, lambda _uc, address, _size, _user: blocks.add(address))

def execute(entry, args):
    blocks.clear()
    for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
        uc.reg_write(reg, value)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0xf000)
    uc.reg_write(UC_ARM_REG_LR, STOP | 1)
    uc.emu_start(entry | 1, STOP, count=10000)
    assert uc.reg_read(UC_ARM_REG_PC) == STOP, 'native function did not return'
    return dict(entry=hex(entry), arguments=[hex(x) for x in args],
                return_r0=hex(uc.reg_read(UC_ARM_REG_R0)),
                blocks=[hex(x) for x in sorted(blocks)])

report = dict(ok=False, firmware_sha256=SHA,
              probe_sha256=hashlib.sha256(source).hexdigest(),
              versions=dict(python=sys.version, unicorn=un.__version__, capstone=capstone.__version__),
              scope='Native parameter code on synthetic RAM; MMIO is inert RAM for packing checks, with no pixel operation. '
                    'The physical meaning of the signed parameter, mode and selector is unverified.',
              assumptions=['Startup copy bytes seed three RAM pages, not a complete boot.',
                           'Configuration ready flag=1 avoids its loader.',
                           'All request and context pointers refer to private synthetic objects.',
                           'Override +0x110=1 selects native +0x114 input; automatic estimation is not tested.',
                           'Table base is an artificial address; selector does not read table contents.',
                           'No memory-write hook, forced return, service stub or code patch.'],
              signed_cases=[], table_cases=[], register_cases=[])
try:
    values = [-66000, -65536, -65408, -129, -128, -127, -1, 0, 63, 64, 65408, 65536]
    routes = [(0, 0), (0, 1), (0, 2), (2, 0), (8, 2), (9, 0)]
    for flag in (0, 1):
        for mode, selector in routes:
            for value in values:
                uc.mem_write(CONFIG + 0x29c, bytes([flag]))
                uc.mem_write(FRAME_CONFIG + 0x54, bytes([selector]))
                word(OVERRIDE + 0x114, value)
                word(CONTEXT + 0x1c, 0x13572468)
                uc.mem_write(STATS, b'Z' * 0x40)
                before = b'Z' * (0xac + 32)
                uc.mem_write(OUTPUT, before)
                result = execute(0x10114136, [INPUT, mode, INPUT + 0x100, OUTPUT])
                after = bytes(uc.mem_read(OUTPUT, len(before)))
                expected = bytearray(before)
                if flag:
                    encoded, slot = 0, None
                    expected[0x62:0x6a] = bytes(8)
                    assert uc.mem_read(STATS, 0x40) == b'Z' * 0x40
                else:
                    quotient = abs(value) // 128 * (1 if value >= 0 else -1)
                    if value - 128 * quotient >= 64:
                        # 101141a6 branches to 10114188, which tests the
                        # quotient itself: zero takes the decrement path.
                        # Do not replace this with conventional rounding.
                        quotient += 1 if quotient > 0 else -1
                    clamped = max(-512, min(511, quotient))
                    encoded = clamped & 0x3ff
                    slot = selector if mode in (0, 1, 6, 7, 8) else 3
                    expected[0x60:0x62] = bytes(uc.mem_read(CONTEXT + 0x50 + 2 * mode, 2))
                    expected[0x62:0x6a] = bytes(8)
                    struct.pack_into('<H', expected, 0x62 + 2 * slot, encoded)
                    actual_stat = struct.unpack('<h', uc.mem_read(STATS + 0x2c, 2))[0]
                    assert actual_stat == quotient, (value, actual_stat, quotient)
                assert after == expected, (flag, mode, selector, value, after.hex(), expected.hex())
                assert struct.unpack('<I', uc.mem_read(CONTEXT + 0x1c, 4))[0] == encoded
                result.update(config_29c=flag, mode=mode, selector=selector, input_114=value,
                              encoded_value=encoded, output_slot=slot,
                              output=after[:0xac].hex(), output_sha256=hashlib.sha256(after[:0xac]).hexdigest(),
                              unchanged_elsewhere_and_guards=True)
                report['signed_cases'].append(result)

    offsets = {
        0: [0, 0x9720, 0x12e40],
        1: [0x855c0, 0x8eca0, 0x98380],
        2: [0x855c0, 0x8eca0, 0x98380],
        3: [0x855c0, 0x8eca0, 0x98380],
        4: [0x354c0, 0x3d9e0, 0x45f00],
        5: [0x5d540, 0x65a60, 0x6df80],
        6: [0x1c560, 0x24a80, 0x2cfa0],
        7: [0x4e420, 0x53480, 0x584e0],
        8: [0x4e420, 0x53480, 0x584e0],
        9: [0x855c0, 0x8eca0, 0x98380],
    }
    for mode, selected in offsets.items():
        for selector in (0, 1, 2):
            uc.mem_write(FRAME_CONFIG + 0x54, bytes([selector]))
            before = b'Z' * (0xac + 32)
            uc.mem_write(OUTPUT, before)
            result = execute(0x1011424a, [INPUT, mode, OUTPUT])
            after = bytes(uc.mem_read(OUTPUT, len(before)))
            expected = bytearray(before)
            struct.pack_into('<3I2B', expected, 0x20, *(TABLE + x for x in selected), 13, selector)
            assert after == expected
            result.update(mode=mode, selector=selector, table_base=hex(TABLE),
                          selected_offsets=[hex(x) for x in selected], output=after[:0xac].hex(),
                          unchanged_elsewhere_and_guards=True)
            report['table_cases'].append(result)
    # Execute the original field mapper and low-level register packer. This
    # mapped MMIO page is ordinary scratch RAM: it has NO pixel semantics.
    report['assumptions'].append('MMIO 0x2006b000 is inert scratch RAM; register packing only.')
    for flag in (0, 1):
        for mode, selector in ((0, 0), (0, 1), (0, 2), (2, 0)):
            for value in (-65536, -128, 64, 65408):
                uc.mem_write(CONFIG + 0x29c, bytes([flag]))
                uc.mem_write(FRAME_CONFIG + 0x54, bytes([selector]))
                word(OVERRIDE + 0x114, value)
                uc.mem_write(OUTPUT, bytes(0xac) + b'Z' * 32)
                parameter_call = execute(0x10114136, [INPUT, mode, INPUT + 0x100, OUTPUT])
                parameters = bytes(uc.mem_read(OUTPUT, 0xac))
                uc.mem_write(0xc25ee130, b'Z' * 0x100)
                mapper_call = execute(0x100bed06, [0, OUTPUT])
                mapped = bytes(uc.mem_read(0xc25ee130, 0x100))
                for src, dst in ((0x60, 0x88), (0x62, 0x8a), (0x64, 0x8c), (0x66, 0x8e), (0x68, 0x94)):
                    assert mapped[dst:dst + 2] == parameters[src:src + 2]
                assert mapped[0x90:0x94] == bytes(4)
                uc.mem_write(0x2006b000, b'Z' * 4096)
                driver_call = execute(0x100d8582, [0xc25ee18c])
                mmio = bytes(uc.mem_read(0x2006b000, 4096))
                value60, s0, s1, s2, s3 = struct.unpack_from('<5H', parameters, 0x60)
                expected_regs = {0x384: value60, 0x388: s0 | (s1 << 16),
                                 0x38c: s2, 0x390: s3 << 16}
                for off, expected in expected_regs.items():
                    assert struct.unpack_from('<I', mmio, off)[0] == expected
                assert uc.mem_read(OUTPUT + 0xac, 32) == b'Z' * 32
                report['register_cases'].append(dict(config_29c=flag, mode=mode, selector=selector,
                    input_114=value, parameters=parameters.hex(), mapped_parameters=mapped.hex(),
                    calls=[parameter_call, mapper_call, driver_call],
                    registers={hex(0x2006b000 + off): hex(v) for off, v in expected_regs.items()},
                    mmio_page_sha256=hashlib.sha256(mmio).hexdigest(), output_guard_unchanged=True))
    report['ok'] = True
finally:
    report['firmware_unchanged'] = hashlib.sha256(image.read_bytes()).hexdigest() == SHA
    (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'], signed_cases=len(report['signed_cases']),
                          table_cases=len(report['table_cases']), register_cases=len(report['register_cases']),
                          firmware_unchanged=report['firmware_unchanged'])))

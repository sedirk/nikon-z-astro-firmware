"""Native RAW descriptor-to-register dataflow; no pixel/codec emulation.

The high-level function stops BEFORE its queue submission. Its prepared packet
is passed through the original mapper and register packer using private RAM.
Input/output pixel addresses remain unmapped: no pixel read/write can succeed.
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
BASE, GLOBAL, CONTEXT = 0x10020000, 0xc23234c8, 0xc180b704
SCRATCH, STACK, STOP, MMIO = 0x50000000, 0x52000000, 0x53000000, 0x20204000
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
for addr, size in ((SCRATCH, 0x10000), (STACK, 0x10000), (STOP, 4096),
                   (MMIO, 4096), (GLOBAL & ~4095, 4096),
                   (CONTEXT & ~4095, 4096), (0xc1801000, 4096)):
    uc.mem_map(addr, size)
# Explicitly zero private contexts; no complete boot or camera calibration.
blocks = set()
uc.hook_add(un.UC_HOOK_BLOCK, lambda _uc, address, _size, _data: blocks.add(address))


def word(addr, value):
    uc.mem_write(addr, struct.pack('<I', value))


def execute(entry, args, until=STOP):
    blocks.clear()
    for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
        uc.reg_write(reg, value)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0xf000)
    uc.reg_write(UC_ARM_REG_LR, STOP | 1)
    uc.emu_start(entry | 1, until, count=30000)
    assert uc.reg_read(UC_ARM_REG_PC) == until
    return dict(entry=hex(entry), arguments=[hex(v) for v in args], stopped_at=hex(until),
                r0=hex(uc.reg_read(UC_ARM_REG_R0)),
                blocks=[hex(v) for v in sorted(blocks)])


report = dict(ok=False, firmware_sha256=SHA, probe_sha256=hashlib.sha256(source).hexdigest(),
    unicorn_version=un.__version__, scope=__doc__, cases=[],
    assumptions=dict(input_pixel_address='0x60000000 (unmapped)',
                     output_pixel_address='0x62000000 (unmapped)',
                     mmio='Ordinary private RAM, no hardware semantics or completion.',
                     context='Zero initialized private RAM; mapper context+c points to native prepared packet.',
                     modes='Numeric format/output-mode IDs only; camera menu names not assigned.'))
try:
    for fmt in (2, 3, 4):
        for mode in (1, 2):
            uc.mem_write(GLOBAL, bytes(0x80))
            uc.mem_write(SCRATCH, bytes(0x5000))
            uc.mem_write(MMIO, bytes(4096))
            inp = bytearray(0x20)
            inp[0] = fmt
            # The native source descriptor uses a byte stride, crop origin,
            # and base; dimensions in the output descriptor select the region.
            struct.pack_into('<H', inp, 2, 0x3000)
            struct.pack_into('<2H', inp, 8, 6048, 4024)
            struct.pack_into('<2H', inp, 0xc, 12, 8)
            struct.pack_into('<I', inp, 0x10, 0x60000000)
            out = bytearray(0x20)
            out[0] = mode
            struct.pack_into('<2H', out, 2, 6000, 4000)
            struct.pack_into('<I', out, 8, 0x62000000)
            uc.mem_write(SCRATCH, bytes(inp))
            uc.mem_write(SCRATCH + 0x100, bytes(out))
            builder = execute(0x100a323e, [SCRATCH, SCRATCH+0x100, SCRATCH+0x200], until=0x101caad8)
            packet = bytes(uc.mem_read(GLOBAL, 0x68))
            u32 = lambda off: struct.unpack_from('<I', packet, off)[0]
            crop_bytes = {2: 12 * 3 // 2, 3: 12 * 2, 4: 12 * 7 // 4}[fmt]
            expected_input = 0x60000000 + 8 * 0x3000 + crop_bytes
            assert u32(0x40) == expected_input and u32(0x48) == 0x62000000
            assert builder['r0'] == hex(GLOBAL)
            assert bytes(uc.mem_read(SCRATCH, 0x20)) == inp
            assert bytes(uc.mem_read(SCRATCH+0x100, 0x20)) == out
            word(CONTEXT + 0xc, GLOBAL)
            mapper = execute(0x101ca6c6, [SCRATCH+0x1000])
            mapped = bytes(uc.mem_read(SCRATCH+0x1000, 0x48))
            assert mapped[0x38:0x3c] == packet[0x40:0x44]
            assert mapped[0x40:0x44] == packet[0x48:0x4c]
            packer = execute(0x10108f8a, [SCRATCH+0x2000, SCRATCH+0x1000])
            regs = bytes(uc.mem_read(MMIO, 0x428))
            reg = lambda off: struct.unpack_from('<I', regs, off)[0]
            assert reg(0x400) == expected_input and reg(0x420) == 0x62000000
            assert reg(0x404) == 0x3000
            assert reg(0x424) == struct.unpack_from('<H', packet, 0x4c)[0]
            assert reg(0x4c) == 6000 and reg(0x50) == 4000
            table = struct.unpack_from('<I', mapped, 0xc)[0]
            uploaded = []
            if table:
                values = struct.unpack_from('<256H', blob, table-BASE)
                uploaded = [(values[i] & 0x3fff) | ((values[i+1] & 0x3fff) << 16)
                            for i in range(0, 256, 2)]
                assert list(struct.unpack_from('<128I', regs, 0x200)) == uploaded
            else:
                assert regs[0x200:0x400] == bytes(0x200)
            assert bool(table) == (mode == 2)
            report['cases'].append(dict(format_id=fmt, output_mode_id=mode,
                input_descriptor=inp.hex(), output_descriptor=out.hex(),
                prepared_packet=packet.hex(), mapped_packet=mapped.hex(),
                register_image=regs.hex(), register_sha256=hashlib.sha256(regs).hexdigest(),
                input_address=hex(reg(0x400)), output_address=hex(reg(0x420)),
                input_stride=reg(0x404), output_stride=reg(0x424),
                conversion_table=hex(table), table_word_count=len(uploaded),
                calls=[builder, mapper, packer]))
    report['ok'] = True
except Exception:
    report['error'] = traceback.format_exc()
    report['failure_pc'] = hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks'] = [hex(v) for v in sorted(blocks)]
    raise
finally:
    report['firmware_unchanged'] = hashlib.sha256(firmware.read_bytes()).hexdigest() == SHA
    (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'], cases=len(report['cases']))))

"""Original RAW configuration dataflow in Unicorn; no pixel/hardware emulation.

Selected original builders and a driver run with private synthetic descriptors.
The driver's r2=0 deliberately selects its configuration-only path: no reset,
queue, start, interrupt or completion. MMIO is ordinary RAM. Pixel addresses
are unmapped. Retention here describes skipped writes, not physical ISP state.
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
BASE, SCRATCH, STACK, STOP = 0x10020000, 0x50000000, 0x52000000, 0x53000000
REQ, PACKET, STORAGE = SCRATCH, SCRATCH+0x1000, SCRATCH+0x2000
PARAM, TABLES, FLAGS = SCRATCH+0x3000, SCRATCH+0x4000, SCRATCH+0x9000
DRIVER, INPUT, OUTPUT = SCRATCH+0xa000, SCRATCH+0xb000, SCRATCH+0xb100
MMIO, BANK_SIZE, BANK_STEP = 0x20380000, 0x10000, 0x40000
CALIBRATION, CALIBRATION_CONTEXT = 0x54000000, 0xc18fa954
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output/'probe-source.py').write_bytes(source)
firmware = ROOT/'firmware/decoded/eg1620_038000.bi'
blob = firmware.read_bytes()
assert hashlib.sha256(blob).hexdigest() == SHA
uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
size = (len(blob)+4095)&~4095
uc.mem_map(BASE, size)
uc.mem_write(BASE, blob)
uc.mem_protect(BASE, size, un.UC_PROT_READ | un.UC_PROT_EXEC)
for addr, size in ((SCRATCH, 0x20000), (STACK, 0x10000), (STOP, 4096),
                   (MMIO, BANK_SIZE), (MMIO+BANK_STEP, BANK_SIZE),
                   (CALIBRATION, 0xc0000), (CALIBRATION_CONTEXT&~4095, 4096)):
    uc.mem_map(addr, size)
blocks = set()
uc.hook_add(un.UC_HOOK_BLOCK, lambda _uc, address, _size, _data: blocks.add(address))


def put32(addr, value):
    uc.mem_write(addr, struct.pack('<I', value))


def get32(addr):
    return struct.unpack('<I', uc.mem_read(addr, 4))[0]


def execute(entry, args):
    blocks.clear()
    for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
        uc.reg_write(reg, value)
    uc.reg_write(UC_ARM_REG_SP, STACK+0xf000)
    uc.reg_write(UC_ARM_REG_LR, STOP|1)
    uc.emu_start(entry|1, STOP, count=100000)
    assert uc.reg_read(UC_ARM_REG_PC) == STOP
    return dict(entry=hex(entry), arguments=[hex(x) for x in args],
                r0=hex(uc.reg_read(UC_ARM_REG_R0)), stopped_at=hex(STOP),
                blocks=[hex(x) for x in sorted(blocks)])


def reset():
    uc.mem_write(SCRATCH, bytes(0x20000))
    for bank in (0, 1):
        uc.mem_write(MMIO+bank*BANK_STEP, bytes(BANK_SIZE))


def image(bank):
    return bytes(uc.mem_read(MMIO+bank*BANK_STEP, BANK_SIZE))


def changes(before, after, base):
    return [dict(address=hex(base+i), before=hex(struct.unpack_from('<I', before, i)[0]),
                 after=hex(struct.unpack_from('<I', after, i)[0]))
            for i in range(0, len(after), 4) if before[i:i+4] != after[i:i+4]]


def initialize_request(output_present, input_group=0, table_present=True, mode=0):
    uc.mem_write(SCRATCH, bytes(0x20000))
    put32(REQ+4, 1)
    put32(REQ+8, INPUT)
    put32(REQ+0x1a8, OUTPUT if output_present else 0)
    put32(REQ+0x35c, PARAM)
    put32(REQ+0x360, TABLES)
    put32(REQ+0x364, FLAGS)
    put32(REQ+0x374, mode)
    uc.mem_write(REQ, bytes([input_group]))
    for handle, base in ((INPUT, 0x60000000), (OUTPUT, 0x62000000)):
        uc.mem_write(handle+0x24, bytes([2]))
        uc.mem_write(handle+0x26, struct.pack('<3H', 9168, 6104, 4222))
        put32(handle+0x34, base)
    uc.mem_write(TABLES, struct.pack('<16I', *(0x11220000+i for i in range(16))))
    uc.mem_write(TABLES+0x39a8, bytes([int(table_present)]))
    # Raw u32 and packed-byte patterns identify the special-path writes.
    uc.mem_write(PARAM+0x368, bytes(range(0x10, 0x28)))
    uc.mem_write(PARAM+0x4a0, bytes(range(0x30, 0x58)))
    calls = [execute(0x100b4b1c, [PACKET, STORAGE]),
             execute(0x100b3f94, [REQ, PACKET]),
             execute(0x100b37de, [REQ, PACKET]),
             execute(0x100b36f0, [REQ, PACKET]),
             execute(0x100b33bc, [REQ, PACKET])]
    # The complete constructor is NOT replayed. Keep only these explicit blocks.
    retained = (0, 0xc, 0x20, 0x28, 0x2c, 0x30, 0x58, 0xc8)
    wired = {hex(i): hex(get32(PACKET+i)) for i in range(0, 0xcc, 4)}
    for off in range(0, 0xcc, 4):
        if off not in retained:
            put32(PACKET+off, 0)
    put32(PACKET+0xcc, mode)
    put32(PACKET+0xd0, 0)
    assert get32(PACKET) == PARAM
    assert get32(PACKET+0x30) == PARAM+0x62
    assert get32(PACKET+0x28) == PARAM+0x44
    assert get32(PACKET+0x58) == (PARAM+0x368 if mode else 0)
    assert get32(PACKET+0xc8) == (PARAM+0x4a0 if mode else 0)
    return calls, wired


report = dict(ok=False, scope=__doc__, firmware_sha256=SHA,
    probe_sha256=hashlib.sha256(source).hexdigest(), unicorn_version=un.__version__,
    pixel_addresses='0x60000000, 0x62000000, 0x64000000, 0x66000000: all unmapped',
    cases=[], limitations=['Numeric IDs, banks and register fields have no assumed pixel semantics.',
      'The full 0x100b5716 constructor, queue worker and physical hardware are not executed.',
      'Synthetic request+37c/+380 are zero, so 0x100b33bc skips external calibration lookup.'])
try:
    for bank in (0, 1):
        for output_present in (False, True):
            reset()
            calls, wiring = initialize_request(output_present, input_group=bank)
            uc.mem_write(DRIVER+4, bytes([bank]))
            before = image(bank)
            calls.append(execute(0x100d5c86, [DRIVER, PACKET, 0, 0]))
            after = image(bank)
            mmio = MMIO+bank*BANK_STEP
            assert get32(mmio+0x310+bank*0x10) == 0x60000000
            assert get32(mmio+0x30c) == 9168
            assert get32(mmio+0x3ec) == (0x62000000 if output_present else 0)
            assert get32(mmio+0x3f0) == (9168 if output_present else 0)
            assert get32(mmio+0x580) == int(output_present)
            # +1c/+1d are packed in reverse byte positions by 10106d74.
            assert get32(mmio+0x67c) == (3 if output_present else 1)<<8
            assert bytes(uc.mem_read(mmio+0x1100, 0x40)) == bytes(uc.mem_read(TABLES, 0x40))
            assert image(1-bank) == bytes(BANK_SIZE)
            name = f'bank-{bank}-output-{int(output_present)}'
            (a.output/f'{name}-registers.bin').write_bytes(after)
            report['cases'].append(dict(name=name, bank=bank, output_present=output_present,
                input_group=bank, packet=bytes(uc.mem_read(PACKET, 0xd4)).hex(),
                pointer_builder_output=wiring, calls=calls, changed_words=changes(before, after, mmio),
                register_file=f'{name}-registers.bin', register_sha256=hashlib.sha256(after).hexdigest()))

    # The bank-1 mode branch must be distinguished from a universal bypass.
    # Seed normal-path registers, then use different addresses with mode=1.
    reset()
    calls, _ = initialize_request(True)
    uc.mem_write(DRIVER+4, b'\x01')
    calls.append(execute(0x100d5c86, [DRIVER, PACKET, 0, 0]))
    before = image(1)
    put32(get32(PACKET+0xc)+0xc, 0x64000000)
    put32(get32(PACKET+0x20), 0x66000000)
    put32(PACKET+0x58, PARAM+0x368)
    put32(PACKET+0xc8, PARAM+0x4a0)
    put32(PACKET+0xcc, 1)
    special = execute(0x100d5c86, [DRIVER, PACKET, 0, 0])
    calls.append(special)
    after = image(1)
    mmio = MMIO+BANK_STEP
    assert get32(mmio+0x310) == 0x60000000 and get32(mmio+0x3ec) == 0x62000000
    assert get32(mmio+0xb20) == get32(PARAM+0x368)
    assert get32(mmio+0xdf8) == get32(PARAM+0x4a0)
    assert '0x1010657a' not in special['blocks'] and '0x10106980' not in special['blocks']
    assert '0x10107b62' in special['blocks'] and '0x1010876a' in special['blocks']
    (a.output/'special-before.bin').write_bytes(before)
    (a.output/'special-after.bin').write_bytes(after)
    report['cases'].append(dict(name='bank-1-mode-1-config-only', calls=calls,
        retained_raw_input=hex(get32(mmio+0x310)), retained_raw_output=hex(get32(mmio+0x3ec)),
        skipped_new_input='0x64000000', skipped_new_output='0x66000000',
        changed_words=changes(before, after, mmio)))

    # Table-present flag controls upload, not a verified hardware enable bit.
    reset()
    calls, _ = initialize_request(True, table_present=True)
    calls.append(execute(0x100d5c86, [DRIVER, PACKET, 0, 0]))
    before = image(0)
    uc.mem_write(TABLES+0x39a8, b'\0')
    # Restore destinations required by the original pointer builder; the
    # deliberately reduced dispatcher packet has cleared its memcpy targets.
    calls.append(execute(0x100b4b1c, [PACKET, STORAGE]))
    calls.append(execute(0x100b3f94, [REQ, PACKET]))
    assert get32(PACKET+0x2c) == 0
    # Avoid introducing unrelated blocks restored by the pointer builder.
    for off in range(0, 0xcc, 4):
        if off != 0x2c:
            put32(PACKET+off, 0)
    calls.append(execute(0x100d5c86, [DRIVER, PACKET, 0, 0]))
    after = image(0)
    assert before[0x1100:0x1140] == after[0x1100:0x1140]
    report['cases'].append(dict(name='table-flag-skips-upload-config-only', calls=calls,
        table_flag_offset='0x39a8', table_byte_count=0x40,
        retained_words=list(struct.unpack_from('<16I', after, 0x1100)),
        changed_words=changes(before, after, MMIO)))

    for bank, flags in ((0, 0x15), (1, 0x0a)):
        reset()
        uc.mem_write(DRIVER+4, bytes([bank]))
        call = execute(0x10106360, [DRIVER, flags])
        values = [get32(MMIO+bank*BANK_STEP+0x120+4*i) for i in range(5)]
        assert values == [(flags>>i)&1 for i in range(5)]
        report['cases'].append(dict(name=f'five-fields-bank-{bank}', flags=flags,
            register_base=hex(MMIO+bank*BANK_STEP+0x120), values=values, calls=[call]))

    # Independently follow one scalar source through four negative-offset
    # slots and the original four-slot register packer. No pixel subtraction
    # is emulated, and neither CFA color names nor the RAW tap are assumed.
    for bank in (0, 1):
        for source_offset in (0, 64, 300):
            reset()
            calls, _ = initialize_request(True)
            context, properties = SCRATCH+0xc000, SCRATCH+0xd000
            put32(context, properties)
            put32(context+0xd0, PARAM)
            uc.mem_write(context+0x26, struct.pack('<H', 512))
            uc.mem_write(context+0x2e, struct.pack('<2H', 768, 1024))
            uc.mem_write(properties+0x86, struct.pack('<H', source_offset))
            calls.append(execute(0x1019f3d0, [context]))
            gain_offsets = (0x184, 0x18a, 0x190, 0x196)
            offset_offsets = (0x186, 0x18c, 0x192, 0x198)
            half = lambda off: struct.unpack('<H', uc.mem_read(PARAM+off, 2))[0]
            gains = [half(o) for o in gain_offsets]
            negatives = [half(o) for o in offset_offsets]
            assert gains == [768, 512, 512, 1024]
            assert negatives == [(-source_offset)&0xffff]*4
            # Restore the packet's original parameter reference, then follow
            # the exact +34 -> block+6 pointer used by 100d5c86.
            calls.append(execute(0x100b4b1c, [PACKET, STORAGE]))
            calls.append(execute(0x100b3f94, [REQ, PACKET]))
            assert get32(PACKET+0x34) == PARAM+0x17e
            uc.mem_write(DRIVER+4, bytes([bank]))
            calls.append(execute(0x10107262, [DRIVER, get32(PACKET+0x34)+6]))
            mmio = MMIO+bank*BANK_STEP
            encoded = (-source_offset)&0x1fff
            expected = (encoded<<16)|encoded
            assert get32(mmio+0x710) == expected and get32(mmio+0x714) == expected
            assert get32(mmio+0x708) == (768<<16)|512
            assert get32(mmio+0x70c) == (512<<16)|1024
            report['cases'].append(dict(name=f'four-slot-offset-bank-{bank}-value-{source_offset}',
                source_offset=source_offset, bank=bank, gains=gains, negative_halfwords=negatives,
                encoded_13bit=encoded, calls=calls,
                registers={hex(mmio+off): hex(get32(mmio+off)) for off in (0x708, 0x70c, 0x710, 0x714)},
                scope='Scalar parameter computation and register packing only; no claim of signed ISP '
                      'interpretation, channel colors, RAW-pixel effect or bypass capability.'))
    # The upstream original function receives configuration 0x3e1 as byte+10.
    # Only two native tail bins are exercised; earlier interpolation is not.
    for second_value, index in ((15, 31), (16, 32)):
        for inhibit in (0, 1, 2):
            reset()
            uc.mem_write(CALIBRATION, bytes(0xc0000))
            put32(CALIBRATION_CONTEXT+0x14, CALIBRATION)
            request = SCRATCH+0xe000
            # Numeric selector bytes zero -> native group selector result 0.
            uc.mem_write(request+8, struct.pack('<2I', 1, second_value))
            uc.mem_write(request+0x10, bytes([inhibit]))
            table_address = CALIBRATION+0xbc7f6+index*12
            sample = 300 if index == 31 else 320
            uc.mem_write(table_address, struct.pack('<H', sample))
            call = execute(0x101224ce, [request])
            value = int(call['r0'], 16)
            assert value == (0 if inhibit else sample)
            assert ('0x1011ee50' in call['blocks']) == (inhibit == 0)
            report['cases'].append(dict(name=f'calibration-flag-{inhibit}-tail-index-{index}',
                input_packet=bytes(uc.mem_read(request, 0x14)).hex(), selector_group=0,
                calibration_byte10=inhibit, table_address=hex(table_address),
                table_value=sample, returned_value=value, calls=[call],
                scope='Synthetic calibration values; internal branch only. Does not set persistent '
                      'configuration 0x3e1 or prove physical black-level/RAW semantics.'))
    report['ok'] = True
except Exception:
    report['error'] = traceback.format_exc()
    report['failure_pc'] = hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks'] = [hex(x) for x in sorted(blocks)]
    raise
finally:
    report['firmware_unchanged'] = hashlib.sha256(firmware.read_bytes()).hexdigest() == SHA
    (a.output/'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'], cases=len(report['cases']), pc=hex(uc.reg_read(UC_ARM_REG_PC)))))

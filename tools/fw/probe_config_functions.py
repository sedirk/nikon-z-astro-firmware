"""Read-only firmware analysis and bounded execution in isolated synthetic RAM.

No camera access, code patches, persistent configuration, or complete boot.
The native byte-setting functions and one consumer branch execute unchanged.
Synthetic initialization and omitted services are recorded explicitly.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

import capstone
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_BLOCK
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R6, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ROOT / 'firmware/decoded/eg1620_038000.bi'
EXPECTED = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
BASE = 0x10020000
STOP = 0x60000000
STACK = 0x60010000
BUFFER = 0x50000000
CONFIG = 0xC20AA7C8
INIT_FLAG = 0xC18812B4
STATE = 0xC18FA954

def main():
    data = IMAGE.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise ValueError('Wrong firmware identity')
    def word(address):
        return struct.unpack_from('<I', data, address - BASE)[0]

    # Native Thumb startup at 10020038 obtains relative table bounds here.
    table_anchor = 0x10020064
    start = table_anchor + word(table_anchor)
    end = table_anchor + word(table_anchor + 4)
    if (start, end) != (0x10034000, 0x10034120):
        raise ValueError('Unexpected native scatter table')
    regions = []
    for address in range(start, end, 16):
        source, destination, size, handler = struct.unpack_from('<4I', data, address - BASE)
        if handler not in (0x1002006C, 0x10020088):
            raise ValueError('Unreviewed startup handler')
        regions.append(dict(table_address=address, source=source, destination=destination,
                            bytes=size, handler=handler,
                            operation='copy' if handler == 0x1002006C else 'zero'))

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    spans = [(0x10020038, 0x10020064), (0x1002006C, 0x10020086),
             (0x10020088, 0x100200A4), (0x101CB734, 0x101CB784),
             (0x1012284C, 0x1012285A), (0x10122828, 0x1012282A),
             (0x101B087A, 0x101B08DC), (0x100BC118, 0x100BC218),
             (0x100BC590, 0x100BC5E4), (0x100BFB54, 0x100BFBD4)]
    assembly = []
    for first, last in spans:
        assembly.append(f'\n; range {first:#x} .. {last:#x}, Thumb')
        decoded_end = first
        for insn in md.disasm(data[first-BASE:last-BASE], first):
            annotation = ''
            for operand in insn.operands:
                if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                    pointer = ((insn.address + 4) & ~3) + operand.mem.disp
                    annotation += f' ; literal[{pointer:#x}]={word(pointer):#x}'
            assembly.append(f'{insn.address:08x} {insn.bytes.hex():12s} {insn.mnemonic:9s} {insn.op_str}{annotation}')
            decoded_end = insn.address + insn.size
        if decoded_end != last:
            raise ValueError(f'Disassembly stopped early at {decoded_end:#x}')

    # The full startup has not run. Only explicitly listed RAM pages are seeded
    # from the recovered copy/zero table. Runtime calibration is not supplied.
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(BASE, (len(data) + 0xFFF) & ~0xFFF)
    uc.mem_write(BASE, data)
    uc.mem_protect(BASE, (len(data) + 0xFFF) & ~0xFFF, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
    pages = set()
    seeded = []
    for address, size in ((INIT_FLAG, 4), (CONFIG, 0x410), (STATE, 0x80), (0xC2086B34, 0x50)):
        for page in range(address & ~0xFFF, (address + size + 0xFFF) & ~0xFFF, 0x1000):
            if page in pages:
                continue
            uc.mem_map(page, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            pages.add(page)
            for region in regions:
                low = max(page, region['destination'])
                high = min(page + 0x1000, region['destination'] + region['bytes'])
                if low < high and region['operation'] == 'copy':
                    offset = region['source'] - BASE + low - region['destination']
                    uc.mem_write(low, data[offset:offset + high - low])
            seeded.append(hex(page))
    uc.mem_map(STOP, 0x1000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(BUFFER, 0x190000)
    uc.mem_write(INIT_FLAG, struct.pack('<I', 1))
    blocks = set()
    def observe_block(_uc, address, _size, _user):
        blocks.add(address)
    uc.hook_add(UC_HOOK_BLOCK, observe_block)

    # On this installed Unicorn build, a UC_HOOK_MEM_WRITE callback changes the
    # observed result of the native IT-block memset tail (64 -> 79 bytes).
    # Do not install that hook. Observe before/after memory, and check guards.
    watched = [(CONFIG + x, 1) for x in (0x29E, 0x3DC, 0x3DD)] + [(STATE + 0x1C, 4)]

    def execute(address, arguments=(), until=STOP):
        blocks.clear()
        before = {a: bytes(uc.mem_read(a, n)) for a, n in watched}
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), arguments):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM_REG_SP, STACK + 0xF000)
        uc.reg_write(UC_ARM_REG_LR, STOP | 1)
        uc.emu_start(address | 1, until, count=2_000_000)
        if uc.reg_read(UC_ARM_REG_PC) != until:
            raise RuntimeError('Native execution did not reach the expected boundary')
        changes = [dict(address=hex(a), before=before[a].hex(), after=bytes(uc.mem_read(a, n)).hex())
                   for a, n in watched if before[a] != bytes(uc.mem_read(a, n))]
        return dict(entry=hex(address), arguments=[hex(x) for x in arguments],
                    stop=hex(until), r0=hex(uc.reg_read(UC_ARM_REG_R0)),
                    r1=hex(uc.reg_read(UC_ARM_REG_R1)), watched_memory_changes=changes,
                    executed_blocks=[hex(x) for x in sorted(blocks)])

    config_calls = []
    for offset in (0x29E, 0x3DC, 0x3DD):
        config_calls.append(execute(0x101CB734, [offset]))
        config_calls.append(execute(0x101CB766, [offset, 1]))
        config_calls.append(execute(0x101CB734, [offset]))
        if uc.mem_read(CONFIG + offset, 1) != b'\x01':
            raise AssertionError('Native setting write not observed')
    state_calls = [execute(0x10122852, [0x12345678]), execute(0x10122852, [0])]
    branch_calls = []
    for flag, boundary in ((0, 0x100BC164), (1, 0x100BC204)):
        uc.mem_write(CONFIG + 0x29E, bytes([flag]))
        uc.mem_write(BUFFER, b'\x5a' * 0x190000)
        uc.reg_write(UC_ARM_REG_R4, 0)
        uc.reg_write(UC_ARM_REG_R6, BUFFER)
        row = execute(0x100BC150, until=boundary)
        produced = bytes(uc.mem_read(BUFFER, 0x18F000))
        clear_size = 0x18F000 if flag == 0 else 0x39000
        guard = bytes(uc.mem_read(BUFFER + clear_size, 32))
        if guard != b'\x5a' * 32:
            raise AssertionError('Native clear exceeded its requested range')
        row.update(flag=flag, bytes_zero=produced.count(0), bytes_ff=produced.count(255),
                   bytes_untouched_5a=produced.count(0x5A), buffer_sha256=hashlib.sha256(produced).hexdigest(),
                   first_32_bytes=produced[:32].hex(), clear_boundary_guard_unchanged=True,
                   sentinel_word_count=sum(struct.unpack_from('<I', produced, x)[0] == 0xFFFFFFFF for x in range(0, 0x39000, 0x200)))
        branch_calls.append(row)

    report = dict(firmware_sha256=digest, versions=dict(python=sys.version, capstone=capstone.__version__, unicorn=unicorn.__version__),
                  kind='native isolated function/branch execution, not full-camera or QEMU boot',
                  firmware_file_modified=False, native_instructions_patched=False,
                  memory_write_hooks_enabled=False,
                  assumptions=['RAM pages seeded from startup copy/zero table only; no RTOS or peripheral initialization',
                               'Generic configuration initialization flag manually set to 1 to avoid calling its loader',
                               'Configuration bytes and notification callback slots start at synthetic zero values',
                               'Notification dispatcher executes native code with no registered callbacks',
                               'Table branch entry uses synthetic R4=0, R6=scratch buffer; normal prologue/allocation/locking omitted',
                               'Flag=0 stops after buffer clear, before real table input; flag=1 stops before cache/locking epilogue',
                               'No sensor calibration, RAW pixels, NEF, persistence, or physical camera behavior verified'],
                  scatter_table_bounds=[hex(start), hex(end)], scatter_regions=regions,
                  seeded_ram_pages=seeded, configuration_base=hex(CONFIG), configuration_29e_address=hex(CONFIG + 0x29E),
                  state_base=hex(STATE), state_field_address=hex(STATE + 0x1C),
                  config_calls=config_calls, state_calls=state_calls, table_branch_calls=branch_calls)
    out = ROOT / 'analysis/local-2026-11-02'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'config_probe.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (out / 'config_disassembly.txt').write_text('\n'.join(assembly) + '\n', encoding='utf-8')
    if hashlib.sha256(IMAGE.read_bytes()).hexdigest() != digest:
        raise AssertionError('Input image changed')
    print(json.dumps(dict(report=str(out / 'config_probe.json'), scatter_regions=len(regions),
                          config_calls=len(config_calls), state_calls=state_calls,
                          table_branch_calls=branch_calls), indent=2))

if __name__ == '__main__':
    main()

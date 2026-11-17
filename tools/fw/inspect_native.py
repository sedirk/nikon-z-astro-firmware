"""Read-only C3.80 Thumb inspection; xrefs are candidates, not a code map."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import capstone
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
EXPECTED = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'

def main():
    global BASE, EXPECTED
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--module',choices=('main','companion'),default='main')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--range', action='append', default=[], dest='ranges', help='start:end, both hex')
    p.add_argument('--literal', action='append', default=[], type=lambda s: int(s, 0))
    p.add_argument('--branch', action='append', default=[], type=lambda s: int(s, 0))
    a = p.parse_args()
    name='eg1620_038000.bi'
    if a.module=='companion':
        name='ex1620_037000.bi';BASE=0x08000000
        EXPECTED='72f1fb29e24b36b872eec697a486abeff8bcef77f6020fa89473fd014aa18131'
    data = (ROOT / 'firmware/decoded' / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    def word(addr):
        return struct.unpack_from('<I', data, addr - BASE)[0]
    def describe(ins):
        row = dict(pc=hex(ins.address), bytes=ins.bytes.hex(), mnemonic=ins.mnemonic, operands=ins.op_str)
        for operand in ins.operands:
            # Literal loads align PC to a word; TBB/TBH use PC+4 without
            # that alignment and read a jump table, not a literal word.
            if ins.mnemonic.startswith('ldr') and operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                addr = ((ins.address + 4) & ~3) + operand.mem.disp
                if BASE <= addr <= BASE + len(data) - 4:
                    row.update(literal_address=hex(addr), literal_value=hex(word(addr)))
        return row
    report = dict(firmware_sha256=EXPECTED, module=name, instruction_set='Thumb',
                  limitations='Halfword-aligned searches and linear ranges can include data, literal pools, jump tables or mid-instruction decodes; candidates need control-flow/runtime validation. Does not cover ARM, MOVW/MOVT, indirect or computed xrefs. A complete linear decode does not prove that all bytes are code.',
                  ranges=[], literals=[], branches=[])
    for span in a.ranges:
        lo, hi = (int(x, 16) for x in span.split(':'))
        assert BASE <= lo < hi <= BASE + len(data)
        instructions = [describe(x) for x in md.disasm(data[lo-BASE:hi-BASE], lo)]
        decoded_end=int(instructions[-1]['pc'],16)+len(bytes.fromhex(instructions[-1]['bytes'])) if instructions else lo
        report['ranges'].append(dict(start=hex(lo), end=hex(hi), decoded_end=hex(decoded_end),
                                     decoded_to_end=decoded_end==hi, instructions=instructions))
    for value in a.literal:
        occurrences = []
        start = 0
        needle = struct.pack('<I', value)
        while True:
            offset = data.find(needle, start)
            if offset < 0:
                break
            start = offset + 1
            addr = BASE + offset
            refs = []
            if addr % 4 == 0:
                for pc in range(max(BASE, addr - 4100), min(BASE + len(data) - 4, addr + 4100), 2):
                    h = struct.unpack_from('<H', data, pc-BASE)[0]
                    if h & 0xf800 != 0x4800 and h not in (0xf8df, 0xf85f):
                        continue
                    ins = next(md.disasm(data[pc-BASE:pc-BASE+4], pc, count=1), None)
                    if ins:
                        row = describe(ins)
                        if row.get('literal_address') == hex(addr):
                            refs.append(row)
            occurrences.append(dict(address=hex(addr), aligned=addr % 4 == 0, refs=refs))
        report['literals'].append(dict(value=hex(value), occurrences=occurrences))
    targets = set(a.branch)
    if targets:
        for offset in range(0, len(data)-4, 2):
            h1, h2 = struct.unpack_from('<HH', data, offset)
            if h1 & 0xf800 != 0xf000 or h2 & 0x9000 != 0x9000:
                continue
            # Decode signed Thumb-2 B.W/BL immediate before invoking Capstone.
            s=(h1>>10)&1; j1=(h2>>13)&1; j2=(h2>>11)&1
            imm=(s<<24)|((1^(j1^s))<<23)|((1^(j2^s))<<22)|((h1&0x3ff)<<12)|((h2&0x7ff)<<1)
            if s: imm -= 1 << 25
            if BASE+offset+4+imm not in targets:
                continue
            ins = next(md.disasm(data[offset:offset+4], BASE+offset, count=1), None)
            if ins and ins.mnemonic in ('bl', 'b.w') and ins.operands[0].type == ARM_OP_IMM and ins.operands[0].imm in targets:
                report['branches'].append(describe(ins))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    lines=[]
    for span in report['ranges']:
        lines.append('\n; ' + span['start'] + '..' + span['end'])
        for ins in span['instructions']:
            extra = ' ; [' + ins['literal_address'] + ']=' + ins['literal_value'] if 'literal_address' in ins else ''
            lines.append(f"{ins['pc']} {ins['mnemonic']:9s} {ins['operands']}{extra}")
    a.output.with_suffix('.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps(dict(output=str(a.output), ranges=len(report['ranges']),
                         literals=[dict(value=x['value'], occurrences=len(x['occurrences']),
                                        refs=sum(len(y['refs']) for y in x['occurrences'])) for x in report['literals']],
                         branches=report['branches']), indent=2))

if __name__ == '__main__':
    main()

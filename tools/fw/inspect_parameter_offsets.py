"""Find selected positive Thumb immediate address operations, as candidates only."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import capstone
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM

ROOT = Path(__file__).resolve().parents[2]
BASE, END = 0x10020000, 0x10610000
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--offset', action='append', required=True, type=lambda x: int(x, 0))
a = p.parse_args()
blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
sha = hashlib.sha256(blob).hexdigest()
assert sha == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True
offsets, hits = set(a.offset), []
for pos in range(0, END-BASE, 2):
    h1, h2 = struct.unpack_from('<2H', blob, pos)
    address_op = h1 & 0xfbf0 in (0xf100, 0xf200) and not h2 & 0x8000
    memory_op = h1 & 0xfff0 in (0xf8b0, 0xf8c0, 0xf8d0, 0xf880, 0xf890, 0xf8a0) and h2 & 0xfff in offsets
    if not (address_op or memory_op):
        continue
    ins = next(md.disasm(blob[pos:pos+4], BASE+pos, count=1), None)
    if ins and ins.size == 4 and any(
            x.type == ARM_OP_IMM and x.imm in offsets or
            x.type == ARM_OP_MEM and x.mem.disp in offsets for x in ins.operands):
        hits.append(dict(pc=hex(ins.address), bytes=ins.bytes.hex(),
                         mnemonic=ins.mnemonic, operands=ins.op_str))
report = dict(firmware_sha256=sha, offsets=[hex(x) for x in sorted(offsets)], hits=hits,
    scope='Halfword scan 10020000..10610000, selected immediate ADD/ADDW and '
          'byte/halfword/word loads/stores only. Same offsets may belong to unrelated '
          'objects; no reachability, object identity or completeness is implied.')
assert not a.output.exists()
a.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))

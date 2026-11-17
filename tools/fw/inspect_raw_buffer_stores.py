"""Find explicit Thumb STR.W pointer stores; halfword candidates need validation."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
digest = hashlib.sha256(blob).hexdigest()
assert digest == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
offsets = {0x1f8, 0x330}
hits = []
for pos in range(0, 0x10610000 - BASE, 2):
    h1, h2 = struct.unpack_from('<2H', blob, pos)
    if h1 & 0xfff0 != 0xf8c0 or h2 & 0xfff not in offsets:
        continue
    code = next(md.disasm(blob[pos:pos+4], BASE+pos, count=1), None)
    if code and code.mnemonic == 'str.w':
        hits.append(dict(pc=hex(code.address), bytes=code.bytes.hex(), operands=code.op_str))
report = dict(firmware_sha256=digest, offsets=[hex(v) for v in sorted(offsets)], stores=hits,
    scope='Halfword scan 10020000..10610000 for explicit positive-immediate STR.W only. '
          'Same displacement can belong to unrelated objects. Does not cover STRD, copies, '
          'computed addresses or prove reachability. Candidates, not a complete producer map.')
assert not a.output.exists()
a.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))

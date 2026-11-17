"""Bounded Thumb operand inventory. Hits may be data or mid-instruction candidates."""
from pathlib import Path
import argparse, hashlib, json, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    offsets = {0x255, 0x256, 0x258, 0x259}
    rows = []
    for off in range(0, 0x500000, 2):
        h1,h2 = struct.unpack_from('<HH',blob,off)
        if h1 & 0xfe00 != 0xf800 or h2 & 0xfff not in offsets:
            continue
        ins = next(md.disasm(blob[off:off+4],BASE+off,count=1),None)
        if ins is not None and ins.size == 4 and ins.mnemonic.startswith(('str','ldr')):
            rows.append(dict(address=hex(ins.address),bytes=ins.bytes.hex(),
                             mnemonic=ins.mnemonic,operands=ins.op_str))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    assert not a.output.exists()
    a.output.write_text(json.dumps(dict(scope=__doc__,firmware_sha256=digest,
        offsets=[hex(x) for x in sorted(offsets)],candidates=rows),indent=2),encoding='utf8')
    print(json.dumps(rows,indent=2))

if __name__ == '__main__':main()

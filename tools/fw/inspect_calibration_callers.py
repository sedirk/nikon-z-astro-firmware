"""Candidate resource call windows; decoding windows alone is not control-flow proof."""
from pathlib import Path
import argparse,json,hashlib
import capstone
ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    x=json.loads((ROOT/'analysis/raw-spatial-identity-2026-11-09/resource-update-xrefs.json').read_text())
    rows=[]
    for branch in x['branches']:
        pc=int(branch['pc'],16);start=pc-28;data=b[start-BASE:pc+8-BASE]
        # Include ID35/0b/38 loads and all calls of the bounded resource update wrapper.
        if branch['operands']=='#0x1014731c' or any(bytes((i,0x20)) in data[:28] for i in (0x35,0xb,0x38)):
            rows.append(dict(branch=branch,instructions=[dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in md.disasm(data,start)]))
    report=dict(scope=__doc__,firmware_sha256=hashlib.sha256(b).hexdigest(),windows=rows)
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    lines=[]
    for row in rows:
        lines.append('\n; '+row['branch']['pc']+' '+row['branch']['operands'])
        lines += [f"{i['pc']} {i['mnemonic']:9s} {i['operands']}" for i in row['instructions']]
    (a.output/'windows.txt').write_text('\n'.join(lines),encoding='utf8')
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(windows=len(rows))))

if __name__=='__main__':main()

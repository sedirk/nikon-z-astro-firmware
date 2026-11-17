"""Read-only whole-module Thumb MOVW and data-table leads for calibration retrieval.

These are candidates, not proof of executable code or supported camera commands.
No USB or firmware modification is performed.
"""
from pathlib import Path
import argparse,hashlib,json,struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB

ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000
VALUES={0xfc01,0xfc02,0xfe01,0xfe02,0xfe31,0xfe34,0xfe63,0xfeb1}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert not a.output.exists()
    b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();digest=hashlib.sha256(b).hexdigest()
    assert digest=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);rows=[]
    for off in range(0,len(b)-4,2):
        h1,h2=struct.unpack_from('<HH',b,off)
        if h1 & 0xfbf0 != 0xf240 or h2 & 0x8000:continue
        value=((h1&15)<<12)|(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&255)
        if value not in VALUES:continue
        ins=next(md.disasm(b[off:off+4],BASE+off,count=1),None)
        if not ins or ins.mnemonic!='movw':continue
        rows.append(dict(pc=hex(BASE+off),bytes=b[off:off+4].hex(),operands=ins.op_str,value=hex(value)))
    literals=[]
    for value in sorted(VALUES):
        needle=struct.pack('<H',value);pos=0;hits=[]
        while True:
            pos=b.find(needle,pos)
            if pos<0:break
            if pos%2==0:
                lo=max(0,pos-24);hi=min(len(b),pos+40)
                hits.append(dict(address=hex(BASE+pos),window_base=hex(BASE+lo),bytes=b[lo:hi].hex()))
            pos+=1
        literals.append(dict(value=hex(value),hits=hits))
    strings=[]
    for term in (b'SDES',b'PTP',b'Service',b'Calib',b'Dump',b'FE34'):
        pos=0;hits=[]
        while True:
            pos=b.find(term,pos)
            if pos<0:break
            hits.append(dict(address=hex(BASE+pos),context=b[max(0,pos-25):pos+80].decode('ascii','replace')));pos+=len(term)
        strings.append(dict(term=term.decode(),hits=hits))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(dict(scope=__doc__,sha256=digest,movw_candidates=rows,halfword_data_candidates=literals,string_candidates=strings),indent=2),encoding='utf8')
    print(json.dumps(dict(movw=rows,halfword_counts={x['value']:len(x['hits']) for x in literals},string_counts={x['term']:len(x['hits']) for x in strings}),indent=2))

if __name__=='__main__':main()

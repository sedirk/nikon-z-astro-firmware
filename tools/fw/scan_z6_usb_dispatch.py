"""Offline leads for the actual observed Z6 USB command set; no device I/O."""
from pathlib import Path
import hashlib,json,struct
import numpy as np
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'analysis/raw-front-completion-2026-11-10';BASE=0x10020000
def main():
    target=OUT/'usb-native-leads.json';assert not target.exists()
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();digest=hashlib.sha256(blob).hexdigest()
    assert digest=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    mapping=json.loads((OUT/'usb-opcode-map.json').read_text(encoding='utf8'))
    ops={int(x['opcode'],16) for x in mapping['opcodes']}
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);movw=[]
    for off in range(0,len(blob)-4,2):
        a,b=struct.unpack_from('<HH',blob,off)
        if a&0xfbf0!=0xf240 or b&0x8000:continue
        value=((a&15)<<12)|(((a>>10)&1)<<11)|(((b>>12)&7)<<8)|(b&255)
        if value not in ops:continue
        ins=next(md.disasm(blob[off:off+4],BASE+off,count=1),None)
        if ins and ins.mnemonic=='movw':movw.append(dict(pc=hex(BASE+off),opcode=hex(value),operands=ins.op_str))
    a=np.frombuffer(blob[:len(blob)//2*2],dtype='<u2');hits=np.flatnonzero(np.isin(a,list(ops)))
    clusters=[];i=0
    # Dense table leads only: at least 12 occurrences and 8 distinct known
    # opcodes in a 512-byte window. A match still needs native references.
    while i<len(hits):
        j=int(np.searchsorted(hits,hits[i]+256))
        if j-i>=12 and len(set(int(x) for x in a[hits[i:j]]))>=8:
            lo=int(hits[i])*2;hi=int(hits[j-1])*2+2
            clusters.append(dict(start=hex(BASE+lo),end=hex(BASE+hi),hits=[dict(address=hex(BASE+int(x)*2),opcode=hex(int(a[x]))) for x in hits[i:j]],bytes=blob[max(0,lo-16):hi+16].hex()))
            i=j
        else:i+=1
    seq=[];ordered=[int(x['opcode'],16) for x in mapping['opcodes']]
    for fmt in ('H','I'):
        for start in range(len(ordered)-2):
            needle=struct.pack('<'+fmt*3,*ordered[start:start+3]);pos=0
            while True:
                pos=blob.find(needle,pos)
                if pos<0:break
                seq.append(dict(format=fmt,offset=hex(BASE+pos),opcodes=[hex(x) for x in ordered[start:start+3]]));pos+=1
    report=dict(ok=True,scope=__doc__,firmware_sha256=digest,movw_candidates=movw,dense_data_candidates=clusters,observed_order_triplet_hits=seq,
        note='Instruction/data candidates only; strings, fonts, pool words and alternate instruction alignment can mimic opcodes.')
    target.write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(dict(movw=movw,dense_clusters=[x['start'] for x in clusters],ordered_triplets=seq)))
if __name__=='__main__':main()

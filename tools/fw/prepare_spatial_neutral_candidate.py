"""Define a three-instruction shared spatial neutral LAB addition to modified2.

The module is a research copy, not an installation package. Shared 17-entry
consumers include static precomputation and another caller: scope is not static
only. No code cave, new routine, calibration erase or boot/updater change.
"""
from pathlib import Path
import argparse, json, struct
import capstone
from build_raw_candidates import ROOT, sha

BASE=0x10020000

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--catalog',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    prior=json.loads((ROOT/'patches/z6-c380-still-vignette-neutral-lab.json').read_text())
    assert sha(blob)==prior['source_sha256']
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    definitions=[
        (0x1019741a,'0ee0','cbz','r1, #0x10197434','b','#0x1019743a',
         'After native flag/coordinate setup, enter the original zero-table function without copying cached coefficients or evaluating lens grids.'),
        (0x10197868,'4a77','strb','r6, [r1, #0x1d]','strb','r2, [r1, #0x1d]',
         'Ordinary enabled-source case exports active=0 using r2 already zero; retain inhibit and coordinate rules.'),
        (0x10197876,'0020','ldrb','r0, [r0, #1]','movs','r0, #0',
         'Cached non-inhibited case exports active=0; cache contents are not modified.'),
    ]
    edits=[]
    for addr,after,mn,op,newmn,newop,why in definitions:
        before=blob[addr-BASE:addr-BASE+2]
        old=list(md.disasm(before,addr));new=list(md.disasm(bytes.fromhex(after),addr))
        assert len(old)==len(new)==1 and old[0].size==new[0].size==2
        assert (old[0].mnemonic,old[0].op_str)==(mn,op),(addr,old[0].mnemonic,old[0].op_str)
        assert (new[0].mnemonic,new[0].op_str)==(newmn,newop)
        edits.append(dict(address=hex(addr),before=before.hex(),after=after,
            instruction_before=mn+' '+op,instruction_after=newmn+' '+newop,reason=why))
    result={k:prior[k] for k in ('schema','model','version','module','load_base','source_size','source_sha256')}
    result['status']='LAB ONLY: shared two-17-table neutral control; native call/ABI/retained-state review required; no physical pixel result or installation approval'
    result['candidates']=[dict(id='neighborhood-vignette-spatial-neutral-lab',
        scope='Retain modified1 neighborhood and modified2 vignette edits. The three new edits are in shared spatial functions 10197410/10197820, covering both precomputed and main-generated two-17 paths, including non-static callers. Native coordinate/inhibit rules, cache mode of unrelated consumers, calibration contents and RAW routing are preserved.',
        intent='Single additional processing family versus modified2. Zero tables and active=0 are offline configuration goals; physical ring removal and preview/JPEG effects require actual NEFs and hardware testing.',
        edits=prior['candidates'][0]['edits']+edits)]
    with a.catalog.open('x',encoding='utf8') as f:json.dump(result,f,indent=2)
    with a.output.open('x',encoding='utf8') as f:json.dump(dict(scope=__doc__,new_edits=edits,
        source_sha256=sha(blob),catalog_sha256=sha(a.catalog.read_bytes())),f,indent=2)
    print(json.dumps(dict(ok=True,new_instructions=len(edits),catalog=str(a.catalog))))

if __name__=='__main__':main()

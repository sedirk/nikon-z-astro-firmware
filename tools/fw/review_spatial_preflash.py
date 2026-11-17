"""Static independent review of the exact shared 17-table candidate."""
from pathlib import Path
import argparse, datetime, json, shutil, struct, subprocess
import capstone
from verify_spatial_preflash_kit import BASE,SIZE,DIGESTS,EDITS,need,sha,reconstruct,read_module
from finalize_spatial_neutral import pinned

ROOT=Path(__file__).resolve().parents[2]
ROUND=ROOT/'analysis/spatial-preflash-2026-11-09'
SOURCES={
 'stock':ROOT/'firmware/decoded/eg1620_038000.bi',
 'modified1':ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN',
 'modified2':ROOT/'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN',
 'test':ROOT/'analysis/raw-spatial-neutral-2026-11-09/lab-module/neighborhood-vignette-spatial-neutral-lab.bi',
}
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);pins=pinned()
    before=ROUND/'progress-before';before.mkdir(exist_ok=False)
    for name in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md'):shutil.copyfile(ROOT/name,before/Path(name).name)
    (ROUND/'git-status-before.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    blobs={k:read_module(p,k) for k,p in SOURCES.items()}
    for mode,n in (('modified1',3),('modified2',6),('test',9)):
        need(reconstruct(blobs['stock'],EDITS[:n])==blobs[mode],'Independent rebuild '+mode)
    prior=ROOT/'analysis/raw-spatial-neutral-2026-11-09/evidence-index.json';frozen=json.loads(prior.read_text())
    for row in frozen['files']:need(sha((ROOT/row['path']).read_bytes())==row['sha256'],'Frozen evidence changed: '+row['path'])
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);md.detail=True
    contexts=[];instructions=[]
    for lo,hi in ((0x10197410,0x10197444),(0x10197820,0x1019788a)):
        for mode in ('stock','modified2','test'):
            decoded=list(md.disasm(blobs[mode][lo-BASE:hi-BASE],lo));starts={i.address for i in decoded}
            for pc,_,_ in EDITS[6:]:
                if lo<=pc<hi:need(pc in starts,'Instruction boundary')
            contexts.append(dict(variant=mode,start=hex(lo),end=hex(hi),instructions=[dict(pc=hex(i.address),bytes=i.bytes.hex(),text=i.mnemonic+' '+i.op_str) for i in decoded]))
    for pc,before_bytes,after_bytes in EDITS:
        row=dict(pc=hex(pc),before=before_bytes,after=after_bytes)
        for label,data in (('old',bytes.fromhex(before_bytes)),('new',bytes.fromhex(after_bytes))):
            ins=list(md.disasm(data,pc));need(len(ins)==1 and ins[0].size==len(data),'Bad instruction')
            row[label]=dict(text=ins[0].mnemonic+' '+ins[0].op_str,updates_flags=ins[0].update_flags)
        instructions.append(row)
    comparisons=[]
    for mode,count,start in (('stock',23,0),('modified1',13,3),('modified2',7,6)):
        allowed={j for pc,old,new in EDITS[start:] for j in range(pc-BASE,pc-BASE+len(bytes.fromhex(old)))}|{SIZE-2,SIZE-1}
        diff=[i for i,(x,y) in enumerate(zip(blobs[mode],blobs['test'])) if x!=y]
        need(set(diff)<=allowed and len(diff)==count,'Unexpected delta '+mode)
        restored=bytearray(blobs['test'])
        for i in allowed:restored[i]=blobs[mode][i]
        need(restored==blobs[mode],'Exact restoration failed '+mode)
        comparisons.append(dict(baseline=mode,bytes=len(diff),offsets=[hex(i) for i in diff],exact_restore=True))
    protected=[]
    for label,lo,hi in (('startup_scatter',BASE,BASE+0x15000),('updater',0x101b4000,0x101ba000),('flash_veneers',0x1014a674,0x1014a6a4)):
        chunks=[b[lo-BASE:hi-BASE] for b in blobs.values()];need(len(set(chunks))==1,'Protected bytes differ')
        protected.append(dict(name=label,start=hex(lo),end=hex(hi),sha256=sha(chunks[0])))
    scatter=[]
    for off in range(0x14000,0x14120,16):
        src,dst,n,handler=struct.unpack_from('<4I',blobs['stock'],off)
        if dst<=0xc2a10c28<dst+n:
            chunks=[b[src-BASE:src-BASE+n] for b in blobs.values()];need(len(set(chunks))==1,'RAM flash scheduler changed')
            scatter.append(dict(source=hex(src),destination=hex(dst),bytes=n,sha256=sha(chunks[0])))
    need(scatter,'Scheduler mapping missing')
    report=dict(ok=True,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),inputs=pins,
        candidate_sha256=DIGESTS['test'],comparisons=comparisons,instructions=instructions,protected=protected,
        scheduler_scatter=scatter,prior_index_sha256=sha(prior.read_bytes()),prior_files_verified=len(frozen['files']),
        new_code_bytes_since_lab=False,shared_scope=True,physical_test=False)
    for name,obj in (('result.json',report),('contexts.json',contexts)):(a.output/name).write_text(json.dumps(obj,indent=2),encoding='utf8')
    for name in (Path(__file__).name,'verify_spatial_preflash_kit.py'):shutil.copyfile(ROOT/'tools/fw'/name,a.output/name)
    print(json.dumps(dict(ok=True,comparisons=comparisons,prior_files=len(frozen['files']))))
if __name__=='__main__':main()

"""Independent exact-byte review of modified4 single front bit11 override."""
from pathlib import Path
import argparse,json,shutil,struct,subprocess
import capstone
from verify_front_preflash_kit import SIZE,BASE,DIGESTS,EDITS,need,sha,read_module,reconstruct
ROOT=Path(__file__).resolve().parents[2];ROUND=ROOT/'analysis/raw-front-owner-2026-11-09'
SOURCES={
 'stock':ROOT/'firmware/decoded/eg1620_038000.bi',
 'modified1':ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN',
 'modified3':ROOT/'outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09/01_TEST_MODIFIED3/EG162080.BIN',
 'test':ROOT/'analysis/raw-front-controls-2026-11-09/lab-module/modified3-front-bit11-off-lab.bi'}
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    before=ROUND/'progress-before';before.mkdir(exist_ok=False)
    for name in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md'):shutil.copyfile(ROOT/name,before/Path(name).name)
    (ROUND/'git-status-before.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    frozen=json.loads((ROOT/'analysis/raw-front-controls-2026-11-09/evidence-index.json').read_text())
    for r in frozen['files']:need(sha((ROOT/r['path']).read_bytes())==r['sha256'],'Prior frozen evidence changed '+r['path'])
    blobs={k:read_module(p,k) for k,p in SOURCES.items()}
    comparisons=[]
    for mode,n in (('modified1',3),('modified3',9),('test',10)):need(reconstruct(blobs['stock'],EDITS[:n])==blobs[mode],'Rebuild '+mode)
    for mode,start in (('stock',0),('modified1',3),('modified3',9)):
        allowed={i for pc,old,_ in EDITS[start:] for i in range(pc-BASE,pc-BASE+len(bytes.fromhex(old)))}|{SIZE-2,SIZE-1}
        diff=[i for i,(x,y) in enumerate(zip(blobs[mode],blobs['test'])) if x!=y]
        need(set(diff)<=allowed,'Unapproved byte changes')
        if mode=='modified3':need(len(diff)==6,'Single-instruction delta changed')
        restored=bytearray(blobs['test'])
        for i in allowed:restored[i]=blobs[mode][i]
        need(restored==blobs[mode],'Restoration failed')
        comparisons.append(dict(baseline=mode,changed_bytes=len(diff),offsets=[hex(i) for i in diff],exact_restore=True))
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);md.detail=True;contexts=[]
    for variant,b in blobs.items():
        ins=list(md.disasm(b[0x100f6494-BASE:0x100f64d4-BASE],0x100f6494))
        need(ins[-1].address+ins[-1].size==0x100f64d4,'Partial context')
        at=next(i for i in ins if i.address==0x100f64b4)
        need(at.size==4 and not at.update_flags,'ABI extent/flags')
        contexts.append(dict(variant=variant,instructions=[dict(pc=hex(i.address),bytes=i.bytes.hex(),text=i.mnemonic+' '+i.op_str) for i in ins]))
    protected=[]
    for label,lo,hi in (('startup',BASE,BASE+0x15000),('updater',0x101b4000,0x101ba000),('flash_veneers',0x1014a674,0x1014a6a4),('static_config_producer',0x1013f0b2,0x1013f0ea),('config_default',0x114732e0,0x114932dc)):
        chunks=[b[lo-BASE:hi-BASE] for b in blobs.values()];need(len(set(chunks))==1,label)
        protected.append(dict(name=label,start=hex(lo),end=hex(hi),sha256=sha(chunks[0])))
    scatter=[]
    for off in range(0x14000,0x14120,16):
        src,dst,n,h=struct.unpack_from('<4I',blobs['stock'],off)
        if dst<=0xc2a10c28<dst+n:
            parts=[b[src-BASE:src-BASE+n] for b in blobs.values()];need(len(set(parts))==1,'RAM flash scheduler')
            scatter.append(dict(source=hex(src),destination=hex(dst),bytes=n,sha256=sha(parts[0])))
    need(scatter,'Scheduler region absent')
    need(sha((ROOT/'firmware/original/Z_6_0380.bin').read_bytes())=='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54','Original container')
    report=dict(ok=True,candidate_sha256=DIGESTS['test'],comparisons=comparisons,protected=protected,scheduler_scatter=scatter,
        frozen_prior_files_verified=len(frozen['files']),original_container_preserved=True,lab_bytes_unchanged=True,
        limits='Static capture frontend, not proven NEF-only. Bit11 processing identity and physical effects remain open.')
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/'contexts.json').write_text(json.dumps(contexts,indent=2),encoding='utf8')
    for n in (Path(__file__).name,'verify_front_preflash_kit.py'):(a.output/n).write_bytes((ROOT/'tools/fw'/n).read_bytes())
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()

"""Independent modified5 byte, update-region and inherited-evidence review."""
from pathlib import Path
import argparse,json,struct,subprocess
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from verify_id35_preflash_kit import BASE,SIZE,DIGESTS,EDITS,need,sha,read_module,reconstruct

ROOT=Path(__file__).resolve().parents[2];ROUND=ROOT/'analysis/id35-preflash-2026-11-09'
PREVIOUS=ROOT/'analysis/raw-fixed-operators-2026-11-09'
SOURCES={
 'stock':ROOT/'firmware/decoded/eg1620_038000.bi',
 'modified1':ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN',
 'modified4':ROOT/'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN',
 'test':PREVIOUS/'static-call-lab/modified4-id35-static-call-off-lab.bi'}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    backups=ROUND/'progress-before';backups.mkdir(exist_ok=False)
    for name in ('README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md'):
        (backups/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    (ROUND/'git-status-before.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    frozen=json.loads((PREVIOUS/'evidence-index.json').read_text(encoding='utf8'))
    for row in frozen['files']:need(sha((ROOT/row['path']).read_bytes())==row['sha256'],'Prior evidence changed '+row['path'])
    blobs={n:read_module(p,n) for n,p in SOURCES.items()}
    for mode,n in (('modified1',3),('modified4',10),('test',14)):
        need(reconstruct(blobs['stock'],EDITS[:n])==blobs[mode],'Exact reconstruction '+mode)
    deltas=[]
    for mode,n in (('stock',0),('modified1',3),('modified4',10)):
        allowed={i for pc,old,_ in EDITS[n:] for i in range(pc-BASE,pc-BASE+len(bytes.fromhex(old)))}|{SIZE-2,SIZE-1}
        diff=[i for i,(x,y) in enumerate(zip(blobs[mode],blobs['test'])) if x!=y]
        need(set(diff)<=allowed,'Unexpected change outside whitelist')
        if mode=='modified4':need(len(diff)==53,'Expected exact 51 code + 2 CRC bytes')
        restored=bytearray(blobs['test'])
        for i in allowed:restored[i]=blobs[mode][i]
        need(restored==blobs[mode],'Exact restoration '+mode)
        deltas.append(dict(baseline=mode,bytes=len(diff),offsets=[hex(i) for i in diff],exact_restore=True))
    protected=[]
    for name,lo,hi in [('startup',BASE,BASE+0x15000),('updater',0x101b4000,0x101ba000),
        ('flash_veneers',0x1014a674,0x1014a6a4),('resource_directory',0x11f15000,0x11f17000),
        ('table33_selector_and_copy',0x1011e23e,0x1011e36a),('table33_upload',0x1010b1c0,0x1010b45e),
        ('config_producer',0x1013f0b2,0x1013f0ea),('config_defaults',0x114732e0,0x114932dc)]:
        chunks=[b[lo-BASE:hi-BASE] for b in blobs.values()];need(len(set(chunks))==1,name)
        protected.append(dict(name=name,start=hex(lo),end=hex(hi),sha256=sha(chunks[0])))
    scatter=[]
    for off in range(0x14000,0x14120,16):
        src,dst,n,h=struct.unpack_from('<4I',blobs['stock'],off)
        if dst<=0xc2a10c28<dst+n:
            chunks=[b[src-BASE:src-BASE+n] for b in blobs.values()];need(len(set(chunks))==1,'RAM flash scheduler changed')
            scatter.append(dict(source=hex(src),destination=hex(dst),bytes=n,sha256=sha(chunks[0])))
    need(scatter,'RAM scheduler not located')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);contexts=[]
    for name in ('modified4','test'):
        for lo,hi in ((0x1011c750,0x1011c81e),(0x10179d48,0x10179d64)):
            ins=list(md.disasm(blobs[name][lo-BASE:hi-BASE],lo))
            need(sum(i.size for i in ins)==hi-lo,'Instruction decode gap')
            contexts.append(dict(variant=name,start=hex(lo),instructions=[dict(pc=hex(i.address),bytes=i.bytes.hex(),text=i.mnemonic+' '+i.op_str) for i in ins]))
    original=ROOT/'firmware/original/Z_6_0380.bin'
    need(sha(original.read_bytes())=='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54','Original container changed')
    previous=json.loads((PREVIOUS/'independent-review-v2/result.json').read_text())
    need(previous['ok'] and previous['sha256']==DIGESTS['test'] and previous['native_pairs']==244,'Wrong prior native evidence')
    result=dict(ok=True,candidate='modified5',candidate_sha256=DIGESTS['test'],prior_lab_bytes_unchanged=True,
        inherited_edits=10,new_edit_regions=4,changed_code_bytes=51,changed_crc_bytes=2,
        comparisons=deltas,protected=protected,scheduler_scatter=scatter,
        prior_frozen_files_verified=len(frozen['files']),prior_native_pairs=244,
        prior_review_sha256=sha((PREVIOUS/'independent-review-v2/result.json').read_bytes()),
        original_container_preserved=True,nef_exclusive=False,
        scope='One marked static frontend call; physical post-capture/liveview schedule and hardware pixel operation remain separate evidence.')
    for name,data in (('result.json',result),('contexts.json',contexts)):
        (a.output/name).write_text(json.dumps(data,indent=2),encoding='utf8')
    for name in (Path(__file__).name,'verify_id35_preflash_kit.py'):(a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    print(json.dumps(dict(ok=True,candidate_sha256=DIGESTS['test'],prior_files=len(frozen['files']),byte_changes=53)))

if __name__=='__main__':main()

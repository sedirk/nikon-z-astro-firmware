"""Cross-check physical sample evidence and preserve originals/candidate bytes."""
from pathlib import Path
import argparse,hashlib,json
import numpy as np
from audit_nef import file_sha
ROOT=Path(__file__).resolve().parents[2];ROUND=ROOT/'analysis/modified1-nef-2026-11-09'
def load(p):return json.loads(p.read_text(encoding='utf8'))
def need(test,msg):
    if not test:raise ValueError(msg)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    pre=load(ROOT/'analysis/preflash-review-2026-11-09/verification.json');preserved={}
    for rel,digest in pre['immutable_inputs'].items():
        need(file_sha(ROOT/rel)==digest,'Immutable input changed: '+rel);preserved[rel]=digest
    candidate='eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875'
    for rel in ('outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN',
                'outputs/Z6-C380-neighborhood-candidate-2026-11-09/candidate/EG162080.BIN'):
        need(file_sha(ROOT/rel)==candidate,'Candidate changed');preserved[rel]=candidate
    earlier=load(ROOT/'analysis/raw-control-convergence-2026-11-09/verification.json')
    modelroot=ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu'
    for name,digest in earlier['model_sources'].items():need(file_sha(modelroot/name)==digest,'Model source changed')
    r=load(ROUND/'pixels-v2/result.json');d=load(ROUND/'independent-decoding/result.json');s=load(ROUND/'assessment/result.json')
    need(r['ok'] and d['ok'] and s['ok'],'Study stage failed')
    need(len(r['files'])==12 and len(d['files'])==7,'Wrong input count')
    need(r['locked_targets_sha256']==file_sha(ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json'),'Locked sites changed')
    need(d['audit_sha256']==file_sha(ROUND/'pixels-v2/result.json')==s['audit_sha256'],'Audit linkage mismatch')
    need(s['arrays_sha256']==file_sha(ROUND/'pixels-v2/arrays.npz'),'Statistics changed')
    need(s['scalar_patch_checks']==1344,'Scalar check count')
    frames={f['id']:f for f in r['files']};decoded={f['name']:f for f in d['files']};sources={}
    with np.load(ROUND/'pixels-v2/arrays.npz') as z:
        for i,ident in enumerate(z['ids'].tolist()):
            f=frames[ident];need(file_sha(Path(f['path']))==f['sha256'],'NEF changed: '+f['name']);sources[f['name']]=f['sha256']
            h=z['histograms'][i];need(h.shape==(4,65536) and np.all(h.sum(axis=1,dtype=np.uint64)==6048*4024//4),'Histogram count')
            for channel in range(4):
                q=f['phases'][channel];hist=h[channel]
                need(q['white_count']==int(hist[16383]) and q['zero_count']==int(hist[0]),'Histogram summary')
                need(abs(q['mean']-np.dot(hist.astype(np.float64),np.arange(65536))/q['n'])<1e-10,'Histogram mean')
            if ident>=4856:
                q=decoded[f['name']];need(q['source_sha256']==f['sha256'] and q['pixels_sha256']==f['stored_pixels_sha256'],'Independent decoder linkage')
                need(q['pixels']==24498560 and q['mismatches']==0,'Independent decode failed')
    need(d['total_pixels']==171489920,'Total pixels')
    need(r['locked_target_results']['stock_dark']['frame_fit_counts']==[112,112],'Original fingerprint differs')
    need(r['locked_target_results']['modified_dark']['frame_fit_counts']==[0,0] and r['locked_target_results']['modified_dark_f20']['frame_fit_counts']==[0],'Candidate fingerprint differs')
    need(r['locked_target_results']['modified_dark']['all_frames_above_max56']==112,'Target scope differs')
    need(s['matched_f18_comparison']['old_fit']==112 and s['matched_f18_comparison']['new_fit']==[0,0],'Matched aperture result')
    need([v['whole_saturated'] for v in s['frames'] if v['id'] in (4860,4861,4862)]==[106,99,95],'Saturation count')
    for plot in s['plots']:need(file_sha(ROUND/'assessment'/plot['path'])==plot['sha256'],'Plot changed')
    changes=load(ROUND/'progress-update/changes.json')['changes'];need(len(changes)==3,'Progress docs count')
    for row in changes:
        need(file_sha(ROOT/row['path'])==row['after_sha256'],'Progress doc changed')
        need(file_sha(ROOT/row['before_copy'])==row['before_sha256'],'Progress backup differs')
    commands=[]
    for f in sorted((ROUND/'commands').glob('*/command.json')):
        q=load(f)
        if 'exit_code' not in q:continue
        want={'01-metadata':2,'03-stored-pixel-comparison':1}.get(f.parent.name,0)
        need(q['exit_code']==want,'Unexpected failed command');commands.append(dict(name=f.parent.name,exit_code=q['exit_code']))
    report=dict(ok=True,new_nefs=7,reference_nefs=5,independently_checked_pixels=171489920,
        independently_checked_mismatches=0,locked_sites=112,modified_dark_fit_counts=[0,0,0],
        immutable=preserved,all_source_nef_sha256=sources,model_sources_unchanged=4,
        document_changes_recorded=3,physical_firmware_provenance='User confirmed installed reviewed candidate; no flash readback performed',
        physical_recovery_test_supplied=False,commands=commands)
    with a.output.open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
    print(json.dumps({k:v for k,v in report.items() if k not in ('immutable','all_source_nef_sha256','commands')},indent=2))
if __name__=='__main__':main()

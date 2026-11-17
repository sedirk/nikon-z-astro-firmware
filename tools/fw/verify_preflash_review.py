"""Freeze-check the completed review, delivered bytes and preserved evidence."""
from pathlib import Path
import argparse,hashlib,json
from verify_preflash_kit import need,check_kit
ROOT=Path(__file__).resolve().parents[2];ROUND=ROOT/'analysis/preflash-review-2026-11-09'

def load(p):return json.loads(p.read_text(encoding='utf8'))
def file_sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    old=ROOT/'analysis/raw-control-convergence-2026-11-09'
    frozen=load(old/'evidence-index.json');checked=0
    for value in frozen.values():
        if isinstance(value,list):
            for row in value:
                if isinstance(row,dict) and {'path','sha256','bytes'}<=row.keys():
                    f=ROOT/row['path'];need(f.stat().st_size==row['bytes'] and file_sha(f)==row['sha256'],'Old evidence changed: '+row['path']);checked+=1
    previous=load(old/'verification.json');inputs={}
    for section in ('immutable','samples'):
        for path,digest in previous[section].items():
            need(file_sha(ROOT/path)==digest,'Input changed: '+path);inputs[path]=digest
    models=ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu'
    for name,digest in previous['model_sources'].items():need(file_sha(models/name)==digest,'Model changed: '+name)
    native=load(ROUND/'rollback-scheduler/result.json');need(native['ok'] and len(native['scheduler'])==4,'Native check failed')
    need(native['inverse_acceptance'][0]['integrity_return']==0,'Inverse preflight failed')
    abi=load(ROUND/'abi/result.json');need(abi['ok'] and abi['executions']==192,'ABI check failed')
    static=load(ROUND/'static-final/result.json');need(static['ok'] and len(static['changed_byte_offsets'])==12,'Static check failed')
    card=load(ROUND/'verifier-fixtures/result.json');need(card['ok'] and len(card['cases'])==7,'Verifier tests failed')
    kit=ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09';delivery=check_kit(kit)
    need((kit/'REVIEW.md').read_bytes()==(ROOT/'docs/PREFLASH_REVIEW_2026-11-09.md').read_bytes(),'Report copy mismatch')
    need((kit/'START_HERE.txt').read_bytes()==(ROOT/'docs/Z6_PREFLASH_STEPS_2026-11-09.txt').read_bytes(),'Steps copy mismatch')
    commands=[]
    for f in sorted((ROUND/'commands').glob('*/command.json')):
        m=load(f)
        if 'exit_code' not in m:continue # this verification may be the running recorder
        need(m['exit_code']==(2 if f.parent.name=='01-updater-boundary' else 0),'Unexpected command failure: '+str(f))
        commands.append(dict(name=f.parent.name,exit_code=m['exit_code']))
    report=dict(ok=True,preserved_prior_index_files=checked,immutable_inputs=inputs,unchanged_model_sources=4,
        abi_executions=192,patch_changed_bytes=12,native_inverse_acceptance_cases=1,
        scheduler_cases=4,scheduler_uses_private_memory_flash_model=True,verifier_fixture_cases=7,
        delivered_kit=delivery,completed_commands=commands,physical_flash_executed=False,
        actual_card_accessed=False,physical_installation_verified=False,physical_recovery_verified=False)
    with a.output.open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
    print(json.dumps({k:v for k,v in report.items() if k not in ('immutable_inputs','completed_commands')},indent=2))
if __name__=='__main__':main()

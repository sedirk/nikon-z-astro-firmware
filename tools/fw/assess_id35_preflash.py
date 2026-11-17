"""Gate modified5 controlled-test packaging on exact, bounded offline evidence."""
from pathlib import Path
import json
from PIL import Image
from review_id35_preflash import ROOT,ROUND,PREVIOUS,SOURCES
from verify_id35_preflash_kit import DIGESTS,sha,need,read_module

def read(p):return json.loads(p.read_text(encoding='utf8'))
def main():
    for mode,p in SOURCES.items():read_module(p,mode)
    static=read(ROUND/'static/result.json');update=read(ROUND/'updater/result.json');state=read(ROUND/'native-state/result.json')
    need(all(r['ok'] for r in (static,update,state)),'Failed review component')
    need(len(update['file_checks'])==9 and len(update['scheduler'])==6,'Updater coverage')
    need(len(state['sequences'])==24 and len(state['invalid_selectors'])==8 and state['source_hashes_unchanged'],'State coverage')
    need(sum(len(r['steps']) for r in state['sequences'])==360,'State step count')
    for row in state['sequences']:
        off=0 if row['variant']=='test' else row['field']
        need([s['gate'] for s in row['steps']]==[row['field'],off,off,off,row['field']]*3,'Gate sequence')
        need(row['calibration_unchanged'],'CAL source mutated')
    prior=read(PREVIOUS/'independent-review-v2/result.json')
    need(prior['ok'] and prior['sha256']==DIGESTS['test'] and prior['native_pairs']==244,'Native differential evidence')
    traces=[];data={};pixels={}
    for variant,short in (('modified4','m4'),('modified5','m5')):
        for profile in ('menu','shooting'):
            suffix='-repeat' if variant=='modified5' and profile=='shooting' else ''
            folder=ROUND/f'qemu-{short}-{profile}{suffix}';j=read(folder/'result.json')
            need(j['ok'] and j['firmware_unchanged'] and j['boot_reached_dispatch'],'QEMU '+str(folder))
            need(j['variant']==variant and j['profile']==profile,'Mismatched QEMU run')
            need(j['firmware_sha256']==DIGESTS['test' if variant=='modified5' else variant],'QEMU digest')
            need(j['final_state']['error'] is None and not any(w['saturated'] for w in j['windows']),'QEMU final state')
            if profile=='shooting':
                need(j['dial']['returned_to_baseline'] and j['static_control']['expected']==2,'Inherited frontend or dial')
                need(j['id35_dispatch_kinds']==([4,1,2] if variant=='modified5' else [0,1,2]),'Static tag')
            else:need(j['menu_key_submitted'],'Missing menu action')
            data[variant,profile]=j
            for name in ('boot.png','after.png'):
                im=Image.open(folder/name).convert('RGB');need(any(lo!=hi for lo,hi in im.getextrema()),'Blank image')
                h=sha(im.tobytes());need(h==j['image_pixels'][name],'Image digest')
                pixels[variant,profile,name]=h
            traces.append(dict(path=(folder/'result.json').relative_to(ROOT).as_posix(),sha256=sha((folder/'result.json').read_bytes()),
                variant=variant,profile=profile,events=len(j['events']),models=j['model_sources'],controllers=j['controller_sources']))
    need(all(t['models']==traces[0]['models'] and t['controllers']==traces[0]['controllers'] for t in traces),'QEMU sources changed')
    need(pixels['modified4','menu','after.png']==pixels['modified5','menu','after.png'],'Menu image mismatch')
    differences=[]
    for event,key,n,allowed in (('static_input','input',0x4c,set()),
          ('static_builder','context',0xe4,{0xa0,0xa1,0xa4,0xa5}),('raw_destination','front_parameters',0x28,set())):
        pair=[[e for e in data[v,'shooting']['events'] if e['event']==event and e['phase'].startswith('static')] for v in ('modified4','modified5')]
        need(len(pair[0])==len(pair[1]) and pair[0],'Event count '+event)
        for x,y in zip(*pair):
            a,b=bytes.fromhex(x[key]),bytes.fromhex(y[key]);need(len(a)==len(b) and len(a)>=n,'Captured extent')
            changed=[i for i,(u,v) in enumerate(zip(a,b)) if u!=v]
            need(set(i for i in changed if i<n)<=allowed,'Unexplained state delta '+event)
            differences.append(dict(event=event,compared_bytes=n,allowed_runtime_offsets=[hex(i) for i in sorted(allowed)],
                all_captured_changed_offsets=[hex(i) for i in changed],
                retained_limit='Context a0/a4 variability and RAW tail addresses were also present within unchanged firmware in prior frozen runs; no full-memory equality claim.'))
            if event=='raw_destination':
                need(a[0x24:0x28]==b[0x24:0x28]==bytes.fromhex('00e048a4'),'Primary RAW pointer')
    failed=read(ROUND/'qemu-m5-shooting/result.json')
    need(not failed['ok'] and 'TimeoutError' in failed['error'],'Unexpected failed-run diagnosis')
    need(not any(e['event']=='id35_return' or (e['event']=='id35_dispatch' and int(e['registers']['r0'],16)==4) for e in failed['events']),'Failure crossed target static call')
    replay=read(ROUND/'timeout-context-replay/result.json')
    need(replay['ok'] and len(replay['comparisons'])==2,'Captured-context replay failed')
    # This repeat is a same-parent control, not a condition selected after seeing
    # its result. Preserve either outcome and never label the failed attempt PASS.
    control_path=ROUND/'qemu-m4-shooting-repeat/result.json';control=read(control_path)
    need(control['firmware_sha256']==DIGESTS['modified4'] and control['firmware_unchanged'],'Repeat control changed')
    need(control['model_sources']==traces[0]['models'] and control['controller_sources']==traces[0]['controllers'],'Repeat control model')
    if not control['ok']:need('TimeoutError' in control['error'],'Unclassified control failure')
    timeout_audit=dict(candidate_failed_attempt='qemu-m5-shooting/result.json',candidate_failed_sha256=sha((ROUND/'qemu-m5-shooting/result.json').read_bytes()),
        phase=failed['phase'],target_static_call_not_reached=True,captured_context_native_pairs=2,
        same_candidate_retry_passed=True,code_and_models_unchanged=True,
        parent_repeat_passed=control['ok'],parent_repeat=str(control_path.relative_to(ROOT)),
        interpretation='The first candidate attempt timed out in a synthetic RTOS wait before the tagged call. Captured periodic calls are natively equivalent and unchanged-candidate replay passes. This does not prove the timeout is unrelated to firmware; root cause remains open.')
    result=dict(ok=True,candidate='modified5',candidate_sha256=DIGESTS['test'],prior_lab_bytes_unchanged=True,
        verdict='Exact LAB bytes passed bounded offline preflash review for a controlled single-static-NEF camera test. This is an experimental candidate, not a verified ring-removal or general-use release.',
        inherited_modified4=True,new_semantic_variable='ID35 gate zero at static call 10179d56',table33x4_unchanged=True,
        native_differential_pairs=244,retained_state_sequences=24,retained_state_steps=360,invalid_selector_cases=8,
        updater_file_cases=9,scheduler_cases=6,qemu_runs=traces,qemu_attempts=6,qemu_timeout_audit=timeout_audit,qemu_state_differences=differences,menu_pixels_identical=True,
        static_scope='One tagged static frontend call; not proven NEF-format exclusive.',
        restoration='Gate stays off through tested exit/kind2; next original live kind0 snippet restores CAL. Hardware post-exposure scheduling remains for physical validation.',
        hardware_pixel_operation_known=False,physical_modified5_boot=False,physical_modified5_nef=False,
        physical_dark_regression=False,ring_removal_verified=False,physical_recovery_verified=False,
        risk_scope='Native updater discovery/CRC and RAM flash scheduler tested with private service adapters; actual power, card, flash timing and recovery are not modeled guarantees.')
    with (ROUND/'assessment.json').open('x',encoding='utf8') as f:json.dump(result,f,indent=2)
    print(json.dumps(dict(ok=True,candidate='modified5',sha256=DIGESTS['test'],qemu_runs=4,native_steps=360,updater_cases=15)))

if __name__=='__main__':main()

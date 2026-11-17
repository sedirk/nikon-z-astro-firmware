"""Gate modified4 controlled-test delivery on exact bytes and bounded evidence."""
from pathlib import Path
import json
from PIL import Image
from review_front_preflash import ROOT,ROUND,SOURCES
from verify_front_preflash_kit import DIGESTS,sha,need,read_module
def read(p):return json.loads(p.read_text(encoding='utf8'))
def main():
    for mode,path in SOURCES.items():read_module(path,mode)
    s=read(ROUND/'static/result.json');u=read(ROUND/'updater/result.json');p=read(ROUND/'actual-owner-probe/result.json')
    need(s['ok'] and u['ok'] and p['ok'],'Review component failed')
    need(len(u['file_checks'])==9 and len(u['scheduler'])==6,'Updater cases')
    need(len(p['rows'])==20 and len(p['comparisons'])==10,'Actual-owner cases')
    previous=ROOT/'analysis/raw-front-controls-2026-11-09'
    prior=read(previous/'verification.json');need(prior['ok'],'Previous lab verification')
    traces=[];images={};states={};repeated={}
    for variant,short in (('modified3','m3'),('modified4','m4')):
        for name,profile in (('shooting','shooting'),('menu','menu'),('shooting-repeat','shooting')):
            folder=ROUND/f'qemu-{short}-{name}';r=read(folder/'result.json')
            need(r['ok'] and r['firmware_unchanged'] and r['boot_reached_dispatch'],'QEMU '+str(folder))
            need(r['variant']==variant and r['profile']==profile,'Variant mismatch')
            need(r['firmware_sha256']==DIGESTS['test' if variant=='modified4' else variant],'Digest mismatch')
            need(r['final_state']['error'] is None and not any(w['saturated'] for w in r['windows']),'Bad final state')
            if profile=='shooting':
                need(r['dial']['returned_to_baseline'],'Dial regression')
                need(r['static_control']['expected']==(2 if variant=='modified4' else 0),'Static override')
                if name=='shooting':states[variant]=r
                else:repeated[variant]=r
            else:need(r['menu_key_submitted'],'Menu input not sent')
            for file in ('boot.png','after.png'):
                img=Image.open(folder/file).convert('RGB');need(any(lo!=hi for lo,hi in img.getextrema()),'Blank screen')
                images[variant,name,file]=sha(img.tobytes());need(images[variant,name,file]==r['image_pixels'][file],'Screen bytes')
            traces.append(dict(path=(folder/'result.json').relative_to(ROOT).as_posix(),sha256=sha((folder/'result.json').read_bytes()),
                variant=variant,profile=profile,events=len(r['events']),models=r['model_sources'],controllers=r['controller_sources']))
    need(all(t['models']==traces[0]['models'] and t['controllers']==traces[0]['controllers'] for t in traces),'Model changed')
    need(images['modified3','menu','after.png']==images['modified4','menu','after.png'],'Menu pixels changed')
    # Actual input block is 0x4c bytes (100f62b2 zeroes exactly that size).
    # The previous 0x50-byte snapshot included one unrelated stack word.
    # Front parameters+24 is primary RAW; +28 onward are rotating secondary slots.
    # Context+a0/a4 differed within the SAME modified4 binary on a fresh boot.
    # Keep every raw snapshot, record variability, and compare defined stable fields.
    variability=[]
    for variant in ('modified3','modified4'):
        for event,key in (('static_input','input'),('static_builder','context'),('raw_destination','front_parameters')):
            old=[e for e in states[variant]['events'] if e['event']==event]
            new=[e for e in repeated[variant]['events'] if e['event']==event]
            need(len(old)==len(new),'Repeat event count')
            for left,right in zip(old,new):
                x,y=bytes.fromhex(left[key]),bytes.fromhex(right[key])
                variability.append(dict(variant=variant,event=event,changed_offsets=[hex(i) for i,(u,v) in enumerate(zip(x,y)) if u!=v]))
    m4ctx=next(r for r in variability if r['variant']=='modified4' and r['event']=='static_builder')
    need(set(m4ctx['changed_offsets'])=={'0xa0','0xa1','0xa4','0xa5'},'Context variability diagnosis changed')
    deltas=[]
    for event,key,n,allowed in (('static_input','input',0x4c,{0x45}),('static_builder','context',0xe4,{0x5d}),('raw_destination','front_parameters',0x28,set())):
        # Repeated modified4 has the same full context tail as BOTH m3 runs;
        # initial modified4 variation remains explicitly recorded above.
        rows=[[e for e in d['events'] if e['event']==event] for d in (states['modified3'],repeated['modified4'])]
        need(len(rows[0])==len(rows[1]) and len(rows[0])>0,'Event count '+event)
        for left,right in zip(*rows):
            x,y=bytes.fromhex(left[key])[:n],bytes.fromhex(right[key])[:n];diff=[i for i,(a,b) in enumerate(zip(x,y)) if a!=b]
            need(len(x)==len(y) and set(diff)<=allowed,'Unexplained state delta '+event)
            deltas.append(dict(event=event,checked_bytes=n,changed_offsets=[hex(i) for i in diff]))
    # The source producer is confirmed by actual RAM write watchpoints, not just offsets.
    watch=read(ROUND/'native-request-watch/result.json');need(watch['ok'],'Source watch failure')
    w=watch['watched_writes'];need(any(e['watch']['address']=='0xc236f879' and e['registers']['r15']=='0x1013f0e6' for e in w),'Producer absent')
    need(any(e['watch']['address']=='0xc236d5d1' and e['registers']['r15']=='0x10170ee4' for e in w),'Copy absent')
    result=dict(ok=True,candidate='modified4',candidate_sha256=DIGESTS['test'],
        verdict='Exact file passed offline preflash review for a controlled single-variable camera test; no physical modified4 efficacy or reliability claim.',
        new_code_this_round=False,inherits_modified3=True,static_capture_scope=True,nef_exclusive=False,
        actual_config3d2_source_verified=True,owner_probe_pairs=10,updater_cases=9,scheduler_cases=6,
        qemu_runs=traces,qemu_state_deltas=deltas,qemu_same_binary_variability=variability,menu_pixels_identical=True,
        failed_initial_assessment='Compared 4 bytes beyond static input and demanded equality of rotating auxiliary slots / context runtime tail; retained as command22.',
        observed_limits='No claim of deterministic full-memory identity or complete mode-transition coverage. Context a0/a4 writer not identified; its variation occurred within identical modified4 firmware.',
        hardware_bit11_identity_known=False,physical_modified4_boot=False,physical_modified4_nef=False,
        ring_removal_verified=False,physical_recovery_verified=False,prior_lab_verification_sha256=sha((previous/'verification.json').read_bytes()))
    with (ROUND/'assessment.json').open('x',encoding='utf8') as f:json.dump(result,f,indent=2)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()

"""Gate delivery on exact bytes, native updater and QEMU/Unicorn cross-checks."""
from pathlib import Path
import collections,json
from PIL import Image
from review_spatial_preflash import ROOT,ROUND,SOURCES
from verify_spatial_preflash_kit import DIGESTS,need,sha,read_module

def main():
    static=json.loads((ROUND/'static/result.json').read_text());updater=json.loads((ROUND/'updater/result.json').read_text())
    need(static['ok'] and updater['ok'],'Static/updater review failed')
    need(len(updater['file_checks'])==9 and len(updater['scheduler'])==6,'Updater coverage incomplete')
    for k,p in SOURCES.items():read_module(p,k)
    rows=[];states={};images={}
    for name,variant,profile in (
        ('qemu-modified2-final','modified2','shooting'),('qemu-modified3','spatial-neutral-lab','shooting'),
        ('qemu-menu-modified2-final','modified2','menu'),('qemu-menu-modified3-final','spatial-neutral-lab','menu')):
        path=ROUND/name/'result.json';d=json.loads(path.read_text())
        need(d['ok'] and d['firmware_unchanged'] and d['boot_reached_dispatch'],'QEMU check failed '+name)
        need(d['profile']==profile and d['variant']==variant,'Wrong QEMU input')
        need(d['firmware_sha256']==DIGESTS['test' if variant=='spatial-neutral-lab' else 'modified2'],'Wrong QEMU firmware')
        counts=collections.Counter(o['label'] for o in d['observations'] if o['phase']!='isolated_nonzero_spatial')
        need(not any('read_error' in o for o in d['observations']),'Observation incomplete')
        if profile=='shooting':
            need(len(d['cross_checks'])==8 and all(x['exact_unicorn_state_match'] and x['inputs_canaries_preserved'] for x in d['cross_checks']),'Cross-engine mismatch')
            need(d['dial']['returned_to_baseline'] and counts['shared_main_wrapper']>=1 and counts['main_after_generator']>=1,'Shared caller/dial not observed')
            # Default no-lens state may be inhibited or neutral. Record exactly;
            # do not claim this exercised an active optical correction.
            states[variant]=[o['state_after'] for o in d['observations'] if o['phase']!='isolated_nonzero_spatial' and 'state_after' in o]
        for filename in ('boot.png','after.png'):
            img=Image.open(ROUND/name/filename).convert('RGB');extrema=img.getextrema()
            need(any(lo!=hi for lo,hi in extrema),'Blank QEMU screenshot '+name+'/'+filename)
            images[name,filename]=sha(img.tobytes())
        need(d['final_state']['error'] is None,'QEMU final error')
        rows.append(dict(path=path.relative_to(ROOT).as_posix(),sha256=sha(path.read_bytes()),variant=variant,
            profile=profile,native_observed_counts=dict(counts),cross_checks=len(d['cross_checks']),screens_nonblank=True,
            build_sources=d['model_sources'],controller_sources=d['controller_sources']))
    need(all(r['build_sources']==rows[0]['build_sources'] and r['controller_sources']==rows[0]['controller_sources'] for r in rows),'Model/controller changed across comparisons')
    need(set(states['modified2'])==set(states['spatial-neutral-lab']),'Observed default no-lens spatial states differ')
    need(images['qemu-menu-modified2-final','after.png']==images['qemu-menu-modified3-final','after.png'],'Menu selection differs')
    prior=ROOT/'analysis/raw-spatial-neutral-2026-11-09/verification.json'
    need(json.loads(prior.read_text())['ok'],'Prior native verification missing')
    verdict=dict(ok=True,verdict='Exact bytes passed offline preflash review for controlled physical test, not production reliability or ring-removal certification.',
        candidate_sha256=DIGESTS['test'],new_firmware_edits_this_round=False,shared_scope=True,
        input_source_pins=DIGESTS,native_updater_file_cases=9,native_scheduler_cases=6,qemu_runs=rows,
        qemu_native_nonzero_cases=16,observed_default_spatial_states_identical=True,menu_after_pixels_identical=True,
        prior_native_evidence=dict(path=prior.relative_to(ROOT).as_posix(),sha256=sha(prior.read_bytes())),
        physical_modified3_boot=False,physical_modified3_nef=False,physical_recovery=False,ring_removal_verified=False,
        excluded_runs={'qemu-modified2':'Input layout overlapped native interpolation workspace; failed before acceptance.',
                      'qemu-modified2-diagnostic':'Captured overlapping writes, same invalid fixture; no firmware change.',
                      'qemu-menu-modified2':'No initial menu settle; black scanout not accepted as visible-menu evidence.',
                      'qemu-menu-modified3':'Same insufficient settle; replaced by visually checked final runs.'})
    with (ROUND/'assessment.json').open('x',encoding='utf8') as f:json.dump(verdict,f,indent=2)
    print(json.dumps(dict(ok=True,qemu_runs=4,cross_engine_cases=16,updater_cases=9,scheduler_cases=6,candidate_sha256=DIGESTS['test'])))
if __name__=='__main__':main()

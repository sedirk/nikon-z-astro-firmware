"""Check consistency and freeze the small review sources; never copy/change firmware."""
from pathlib import Path
import datetime, hashlib, json, math, shutil
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/modified11-independent-review-2026-11-14'
def read(p):return json.loads(p.read_text(encoding='utf8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False),encoding='utf8')
def need(v,msg):
    if not v:raise ValueError(msg)

a=read(OUT/'samples-v2/assessment.json');d=read(OUT/'independent-lossless/result.json')
f=read(OUT/'firmware/assessment.json');n=read(OUT/'nefinfo/result.json')
g=read(ROOT/'analysis/modified11-real-2026-11-14/assessment.json')
need(a['computation_completed'] and d['ok'] and f['ok'] and n['ok'],'incomplete computation')
need(len(d['files'])==9 and d['total_pixels']==220487040,'wrong decode coverage')
need(all(x['mismatches']==0 for x in d['files']),'decoder disagreement')
checks=[]
for x in a['files']:
    need(sha(Path(x['path']))==x['sha256'],'source NEF changed')
    if 4964<=x['id']<=4966:
        old=g['comb_analysis'][x['name']]['R'];new=x['flat']['spectra']['R']['legacy']
        need(math.isclose(old['peak_f'],new['peak_frequency'],abs_tol=1e-12),'FFT frequency reproduction failed')
        need(math.isclose(old['snr'],new['peak_over_band_median'],rel_tol=1e-7),'FFT ratio reproduction failed')
        checks.append(dict(name=x['name'],legacy_fft_reproduced=True,dominant_peak_above_10x_band_median=new['peak_over_band_median']>10))
for group in ('Modified10','Modified11'):
    for key,oldkeys in [('broad_ptp_pp',['broad_rg_ptp','broad_bg_ptp','broad_gg_ptp']),('hp6_ptp_pp',['hp6_rg_ptp','hp6_bg_ptp','hp6_gg_ptp'])]:
        for val,oldkey in zip(a['flat_groups'][group][key],oldkeys):
            need(math.isclose(val,g['flat_metrics'][group][oldkey],abs_tol=1e-12),'radial reproduction failed')
for label,row in f['files'].items():need(sha(Path(row['path']))==row['sha256'],'firmware changed')
need(sha(Path(f['original_container']['path']))==f['original_container']['sha256'],'original container changed')
frozen=OUT/'reviewed-source-snapshots';frozen.mkdir(exist_ok=False)
source_paths=[
 'docs/MODIFIED11_REAL_NEF_2026-11-14.md','docs/MODIFIED11_PRODUCTION_CONVERGENCE_2026-11-14.md',
 'analysis/modified11-real-2026-11-14/assessment.json','tools/fw/audit_modified11_all.py',
 'tools/fw/probe_modified11_native.py','tools/fw/probe_modified11_updater.py',
 'tools/fw/verify_modified11_kit.py','patches/z6-c380-modified11-production-convergence.json',
 'outputs/Z6-C380-modified11-reviewed-2026-11-14/FLAT_COMPARE.txt',
 'tools/fw/audit_nef.py','tools/fw/verify_modified1_decode.py','tools/fw/extract_flat_correction_fields.py',
 'tools/fw/review_modified11_samples.py','tools/fw/review_modified11_firmware.py',
 'tools/fw/finalize_modified11_review.py','docs/MODIFIED11_INDEPENDENT_REVIEW_2026-11-14.md']
sources=[]
for rel in source_paths:
    p=ROOT/rel;dest=frozen/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
    need(sha(p)==sha(dest),'snapshot differs');sources.append(dict(path=str(p),snapshot=str(dest.relative_to(OUT)),sha256=sha(p)))
summ=dict(completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
          review_computation_passed=True,production_certified=False,firmware_modified_by_this_review=False,
          decode=dict(files=9,pixels=d['total_pixels'],differences=0),original_numerical_results_reproduced=checks,
          findings=[dict(id='R1',severity='high',claim='all comb/rings gone',verdict='not supported; repeatable new peaks and mixed radial changes'),
                    dict(id='R2',severity='high',claim='unity gain only',verdict='NULL publish guard also removed, changing control-byte update semantics'),
                    dict(id='R3',severity='high',claim='all raw correction off / production safe / arbitrary rollback',verdict='evidence covers bounded paths and synthetic updater tests'),
                    dict(id='R4',severity='medium',claim='preview colour proves pure sensor response',verdict='RAW ratios and automatic white balance both change'),
                    dict(id='R5',severity='medium',claim='automated three-goal verification',verdict='completion flags are literal True constants')],
          dark_old_rule_matches=[a['dark'][str(i)]['matches_0_8_to_56'] for i in (4961,4962,4963)],
          frozen_sources=sources)
dump(OUT/'review-summary.json',summ)
manifest=[]
for p in sorted(OUT.rglob('*')):
    if p.is_file() and 'commands' not in p.relative_to(OUT).parts and p.name!='evidence-sha256.json':
        manifest.append(dict(path=str(p.relative_to(OUT)),bytes=p.stat().st_size,sha256=sha(p)))
dump(OUT/'evidence-sha256.json',dict(scope='All completed evidence except live command logs and this manifest',files=manifest))
print(json.dumps(dict(ok=True,source_snapshots=len(sources),evidence_files=len(manifest),decode_pixels=d['total_pixels'],production_certified=False)))

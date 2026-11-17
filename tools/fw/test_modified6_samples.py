"""Analyze six supplied samples only; no firmware research or modification."""
from pathlib import Path
import hashlib, json, sys
import numpy as np
import rawpy
from audit_nef import audit, file_sha
from analyze_modified1_nef import maximum, KR, KG

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/modified6-real-2026-11-10'

def read(p): return json.loads(p.read_text(encoding='utf8'))
def write(p, v):
    assert not p.exists(), p
    p.write_text(json.dumps(v, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf8')

def prepare():
    md = read(OUT / 'metadata/metadata.json')
    rows = []
    for m in md:
        path = (ROOT / m['SourceFile']).resolve()
        ident = int(path.stem.split('_')[-1])
        row = audit(path, 'dark' if ident in (4913,4914) else 'flat')
        row.update(id=ident, metadata=m)
        rows.append(row)
    assert {r['id'] for r in rows} == {4910,4911,4913,4914,4917,4921}
    write(OUT / 'raw-audit.json', dict(ok=True, files=rows))
    flats = []
    for ident in (4910,4911,4917,4921):
        r = next(r for r in rows if r['id'] == ident)
        m = r['metadata']
        assert m['ExifIFD:ExposureTime'] == '1/8000' and m['ExifIFD:ISO'] == 1600 and m['ExifIFD:FNumber'] == 1.8
        assert all(m['Nikon:' + n] == 'Off' for n in ('VignetteControl','AutoDistortionControl','DiffractionCompensation'))
        flats.append(dict(id=ident, group='modified4' if ident<4915 else 'modified6',
            path=r['path'], sha256=r['sha256'], capture_time=m['ExifIFD:DateTimeOriginal']))
    write(OUT / 'inputs.json', dict(files=flats,
        design='Two new modified4 and two modified6 1/8000 tablet flats; correction menusOFF. Actual placement/focus stability not newly confirmed.',
        user_confirmation='User labels supplied folders modified4/modified6 and requests tests/results only; no further firmware correction.'))
    # Fork exact established flat method; remove only the unrelated historical-A binding.
    source = ROOT / 'tools/fw/analyze_modified2_flats.py'
    text = source.read_text(encoding='utf8')
    old = "    oldmaps=np.load(ROOT/'analysis/modified1-flat-2026-11-09/spatial/maps.npz')\n    need(np.array_equal(codes[:2],oldmaps['codes']),'Frozen A block means not reproduced')\n    need(np.array_equal(rats[:2],oldmaps['ratios']),'Frozen A ratios not reproduced')\n    report['frozen_A_arrays_exactly_reproduced']=True"
    assert text.count(old) == 1
    text = text.replace(old, "    report['new_A_and_B_sources']=True")
    text = text.replace("ROUND=ROOT/'analysis/modified2-flat-2026-11-09'", "ROUND=ROOT/'analysis/modified6-real-2026-11-10'")
    text = text.replace('A_modified1', 'A_modified4').replace('B_modified2', 'B_modified6')
    target = ROOT / 'tools/fw/analyze_modified6_flats.py'
    assert not target.exists()
    target.write_text(text, encoding='utf8')
    write(OUT / 'flat-method-provenance.json', dict(source=str(source), source_sha256=file_sha(source),
        derived=str(target), derived_sha256=file_sha(target),
        changes='Round paths and group labels; remove old unrelated two-frame frozen-A equality check. Numerical method unchanged.'))
    print(json.dumps(dict(ok=True, samples=len(rows), flats=4, darks_modified4=2, darks_modified6=0)))

def darks():
    lockpath = ROOT / 'outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json'
    lock = read(lockpath)
    assert lock['kernel_R_B'] == [list(v) for v in KR] and lock['kernel_G1_G2'] == [list(v) for v in KG]
    y = np.array([r['y'] for r in lock['targets']]); x = np.array([r['x'] for r in lock['targets']])
    oldc = np.array([r['dark_centres'] for r in lock['targets']]).T
    oldm = np.array([r['nearest_color_max'] for r in lock['targets']]).T
    oldd = oldc-oldm
    exact_subset = (oldd == 0).all(axis=0)
    assert int(exact_subset.sum()) == lock['discovery112']['both_exact_max'] == 62
    result = dict(ok=False, frozen_targets_sha256=file_sha(lockpath), files=[],
        formula='centre-max8 in {0,8,...,56}', prior_both_exact_max_subset=62,
        modified6_dark_frames=0, full_dark_current_rate_measured=False)
    for row in read(OUT / 'raw-audit.json')['files']:
        if row['id'] not in (4913,4914): continue
        m = row['metadata']
        assert m['ExifIFD:ISO'] == 1600 and m['ExifIFD:ExposureTime'] == 5
        with rawpy.imread(row['path']) as raw:
            v = raw.raw_image
            assert hashlib.sha256(v.astype('<u2',copy=False).tobytes()).hexdigest() == row['stored_pixels_sha256']
            cc = v[y,x].astype(np.int32); mm = maximum(v,y,x); d = cc-mm
            fit = (d>=0)&(d<=56)&(d%8==0)
            shifted = []
            for shift in (-32,32):
                dd = v[y,x+shift].astype(np.int32)-maximum(v,y,x+shift)
                shifted.append(dict(shift_x=shift, fits=int(((dd>=0)&(dd<=56)&(dd%8==0)).sum())))
            result['files'].append(dict(id=row['id'], sha256=row['sha256'], old_fingerprint_fit=int(fit.sum()),
                exact_max=int((d==0).sum()), above_max56=int((d>56).sum()),
                prior_exact_subset_still_exact=int((d[exact_subset]==0).sum()), prior_exact_subset_above_max56=int((d[exact_subset]>56).sum()),
                above_stock_mean50=int((cc-oldc.mean(axis=0)>50).sum()), saturated=int((cc>=16383).sum()),
                centre_mean=float(cc.mean()), delta_median=float(np.median(d)),
                centres=cc.tolist(), maxima=mm.tolist(), deltas=d.tolist(), shifted_controls=shifted))
    assert len(result['files']) == 2
    result['ok'] = True
    write(OUT / 'dark-regression.json', result)
    print(json.dumps({**result,'files':[{k:v for k,v in r.items() if k not in ('centres','maxima','deltas')} for r in result['files']]}, indent=2))

if __name__ == '__main__':
    assert len(sys.argv)==2 and sys.argv[1] in ('prepare','darks')
    globals()[sys.argv[1]]()

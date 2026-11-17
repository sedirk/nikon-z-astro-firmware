"""Audit 11.12_modified7 NEF samples and run BIAS + DARK regression checks.

All source NEFs are read-only. No demosaic, display stretch, or software lens
correction is applied.
"""
from pathlib import Path
import hashlib, json, sys
import numpy as np
import rawpy
from audit_nef import audit, file_sha, stats
from analyze_modified1_nef import PHASES, KR, KG, maximum, simple, pair_noise

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/modified7-real-2026-11-12'
OLD6 = ROOT / 'analysis/modified6-real-2026-11-10'

BIAS_IDS = (4922, 4923, 4924)
DARK_IDS = (4925, 4926, 4927)
FLAT_IDS = (4928, 4930, 4931)


def read(p):
    return json.loads(Path(p).read_text(encoding='utf8'))


def write(p, v):
    p = Path(p)
    assert not p.exists(), p
    p.write_text(json.dumps(v, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf8')


def prepare():
    md = read(OUT / 'metadata/metadata.json')
    rows = []
    for m in md:
        path = (ROOT / m['SourceFile']).resolve()
        ident = int(path.stem.split('_')[-1])
        kind = 'bias' if ident in BIAS_IDS else ('dark' if ident in DARK_IDS else 'flat')
        row = audit(path, kind)
        row.update(id=ident, kind=kind, metadata=m)
        rows.append(row)
    assert {r['id'] for r in rows} == set(BIAS_IDS + DARK_IDS + FLAT_IDS)
    for r in rows:
        m = r['metadata']
        assert str(m['Nikon:SerialNumber']) == '8006677'
        assert m['ExifIFD:ISO'] == 1600 and m['ExifIFD:FNumber'] == 1.8
        assert m['Nikon:ShutterMode'] == 'Mechanical' and m['Nikon:NEFCompression'] == 'Lossless'
        assert m['Nikon:NoiseReduction'] == 'Off' and m['Nikon:HighISONoiseReduction'] == 'Off'
        assert all(m['Nikon:' + n] == 'Off' for n in ('VignetteControl', 'AutoDistortionControl', 'DiffractionCompensation'))
        if r['id'] in DARK_IDS:
            assert m['ExifIFD:ExposureTime'] == 5
        else:
            assert m['ExifIFD:ExposureTime'] == '1/8000'
    write(OUT / 'raw-audit.json', dict(ok=True, files=rows))

    old_audit = {r['id']: r for r in read(OLD6 / 'raw-audit.json')['files']}
    flats = []
    for ident in (4910, 4911):
        r = old_audit[ident]
        assert file_sha(r['path']) == r['sha256']
        flats.append(dict(id=ident, group='A_modified4', path=r['path'], sha256=r['sha256'],
                          capture_time=r['metadata']['ExifIFD:DateTimeOriginal']))
    for ident in (4917, 4921):
        r = old_audit[ident]
        assert file_sha(r['path']) == r['sha256']
        flats.append(dict(id=ident, group='C_modified6', path=r['path'], sha256=r['sha256'],
                          capture_time=r['metadata']['ExifIFD:DateTimeOriginal']))
    for ident in FLAT_IDS:
        r = next(x for x in rows if x['id'] == ident)
        flats.append(dict(id=ident, group='B_modified7', path=r['path'], sha256=r['sha256'],
                          capture_time=r['metadata']['ExifIFD:DateTimeOriginal']))
    biases = [dict(id=r['id'], path=r['path'], sha256=r['sha256'],
                   capture_time=r['metadata']['ExifIFD:DateTimeOriginal'])
              for r in rows if r['id'] in BIAS_IDS]
    write(OUT / 'inputs.json', dict(
        ok=True,
        files=flats,
        bias_files=biases,
        design='Compare menu-Off 1/8000 ISO1600 f/1.8 mechanical-shutter flats across A_modified4 (4910,4911), C_modified6 (4917,4921), and B_modified7 (4928,4930,4931), with new modified7 BIAS (4922-4924) subtraction control.',
        user_confirmation='User captured DARK, BIAS, FLAT in samples/11.12_modified7 after flashing modified7.'
    ))
    print(json.dumps(dict(ok=True, audited=len(rows), bias=len(BIAS_IDS), dark=len(DARK_IDS), flat=len(FLAT_IDS))))


def bias_dark():
    out_dir = OUT / 'bias-dark'
    out_dir.mkdir(parents=True, exist_ok=False)
    lockpath = ROOT / 'outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json'
    lock = read(lockpath)
    assert len(lock['targets']) == 112
    assert lock['kernel_R_B'] == [list(v) for v in KR] and lock['kernel_G1_G2'] == [list(v) for v in KG]
    y = np.array([r['y'] for r in lock['targets']])
    x = np.array([r['x'] for r in lock['targets']])
    oldc = np.array([r['dark_centres'] for r in lock['targets']]).T
    oldm = np.array([r['nearest_color_max'] for r in lock['targets']]).T
    exact_subset = ((oldc - oldm) == 0).all(axis=0)
    assert int(exact_subset.sum()) == lock['discovery112']['both_exact_max'] == 62

    audit_rows = {r['id']: r for r in read(OUT / 'raw-audit.json')['files']}
    old4_rows = {r['id']: r for r in read(OLD6 / 'raw-audit.json')['files'] if r['id'] in (4913, 4914)}

    bias_imgs = {}
    bias_summary = []
    for ident in BIAS_IDS:
        row = audit_rows[ident]
        assert file_sha(row['path']) == row['sha256']
        with rawpy.imread(row['path']) as raw:
            v = raw.raw_image.copy()
        assert hashlib.sha256(v.astype('<u2', copy=False).tobytes()).hexdigest() == row['stored_pixels_sha256']
        bias_imgs[ident] = v
        phases = []
        for name, dy, dx in PHASES:
            plane = v[8 + dy:4032:2, 8 + dx:6056:2]
            q = stats(plane, 1008)
            q.update(name=name, mean_minus_1008=float(plane.mean(dtype=np.float64) - 1008.0))
            phases.append(q)
        bias_summary.append(dict(id=ident, sha256=row['sha256'], phases=phases,
                                 active_mean=float(v[8:4032, 8:6056].mean(dtype=np.float64))))

    # Reference stock & modified1 bias noise/pedestal
    ref_bias = {}
    for gname, folder, seq in (('stock_bias', 'samples/11.9', (4851, 4852, 4853)),
                               ('modified1_bias', 'samples/11.9_modified1', (4857, 4858, 4859))):
        arrs = []
        for i in seq:
            with rawpy.imread(str(ROOT / f'{folder}/Z61_{i}.NEF')) as raw:
                arrs.append(raw.raw_image[8:4032, 8:6056].copy())
        pn = pair_noise(arrs[0], arrs[1])
        mean_map = np.mean(arrs, axis=0, dtype=np.float64)
        ref_bias[gname] = dict(ids=list(seq), active_mean=float(mean_map.mean()),
                               pair_noise=pn, col_profile_std=float(mean_map.mean(axis=0).std()),
                               row_profile_std=float(mean_map.mean(axis=1).std()))
    mod7_active_b = [bias_imgs[i][8:4032, 8:6056] for i in BIAS_IDS]
    mod7_bmean = np.mean(mod7_active_b, axis=0, dtype=np.float64)
    ref_bias['modified7_bias'] = dict(
        ids=list(BIAS_IDS), active_mean=float(mod7_bmean.mean()),
        pair_noise=pair_noise(mod7_active_b[0], mod7_active_b[1]),
        col_profile_std=float(mod7_bmean.mean(axis=0).std()),
        row_profile_std=float(mod7_bmean.mean(axis=1).std()),
    )

    dark_imgs = {}
    dark_files = []
    for group_label, lookup in (('modified4_11.10_dark', old4_rows), ('modified7_11.12_dark', {i: audit_rows[i] for i in DARK_IDS})):
        for ident, row in sorted(lookup.items()):
            assert file_sha(row['path']) == row['sha256']
            with rawpy.imread(row['path']) as raw:
                v = raw.raw_image.copy()
            assert hashlib.sha256(v.astype('<u2', copy=False).tobytes()).hexdigest() == row['stored_pixels_sha256']
            if ident in DARK_IDS:
                dark_imgs[ident] = v
            cc = v[y, x].astype(np.int32)
            mm = maximum(v, y, x)
            d = cc - mm
            fit = (d >= 0) & (d <= 56) & (d % 8 == 0)
            shifted = []
            for shift in (-32, 32):
                dd = v[y, x + shift].astype(np.int32) - maximum(v, y, x + shift)
                shifted.append(dict(shift_x=shift, fits=int(((dd >= 0) & (dd <= 56) & (dd % 8 == 0)).sum())))
            dark_files.append(dict(
                id=ident, group=group_label, sha256=row['sha256'],
                old_fingerprint_fit=int(fit.sum()),
                exact_max=int((d == 0).sum()),
                above_max56=int((d > 56).sum()),
                prior_exact_subset_still_exact=int((d[exact_subset] == 0).sum()),
                prior_exact_subset_above_max56=int((d[exact_subset] > 56).sum()),
                above_stock_mean50=int((cc - oldc.mean(axis=0) > 50).sum()),
                saturated=int((cc >= 16383).sum()),
                centre_mean=float(cc.mean()),
                delta_median=float(np.median(d)),
                centres=cc.tolist(), maxima=mm.tolist(), deltas=d.tolist(),
                shifted_controls=shifted,
            ))

    # 31-site original selection rule & net (DARK - BIAS) signal by CFA phase for modified7
    phase_signals = []
    total_rule31 = 0
    for name, dy, dx in PHASES:
        bs = [bias_imgs[i][8 + dy:4032:2, 8 + dx:6056:2] for i in BIAS_IDS]
        ds = [dark_imgs[i][8 + dy:4032:2, 8 + dx:6056:2] for i in DARK_IDS]
        bsum = sum(v.astype(np.int32) for v in bs)
        dsum = sum(v.astype(np.int32) for v in ds)
        reduced = (np.minimum.reduce(bs) > 1108) & (np.maximum.reduce(ds) < 1080) & (
            np.maximum.reduce(ds).astype(np.int32) * 3 < bsum - 150
        )
        cnt = int(reduced.sum())
        total_rule31 += cnt
        b_mean = float(bsum.mean(dtype=np.float64) / 3.0)
        d_mean = float(dsum.mean(dtype=np.float64) / 3.0)
        phase_signals.append(dict(
            channel=name,
            bias_mean=b_mean,
            dark_mean=d_mean,
            dark_minus_bias=d_mean - b_mean,
            bias_pair_noise=pair_noise(bs[0], bs[1]),
            dark_pair_noise=pair_noise(ds[0], ds[1]),
            original_selection_rule_sites=cnt,
        ))

    mod7_dc = np.mean([r['centres'] for r in dark_files if r['id'] in DARK_IDS], axis=0)
    mod7_bc = np.mean([bias_imgs[i][y, x].astype(np.float64) for i in BIAS_IDS], axis=0)
    result = dict(
        ok=True,
        scope=__doc__,
        frozen_targets_sha256=file_sha(lockpath),
        formula='centre - same-colour max8 in {0, 8, ..., 56}',
        prior_both_exact_max_subset=62,
        bias_frames=bias_summary,
        bias_group_comparison=ref_bias,
        dark_files=dark_files,
        modified7_net_signal=dict(
            phases=phase_signals,
            overall_dark_minus_bias_dn=float(np.mean([p['dark_minus_bias'] for p in phase_signals])),
            original_selection_rule_sites=total_rule31,
            stock_reference_rule_sites=31,
        ),
        modified7_target112_vs_stock=dict(
            mean_dark_increase=simple(mod7_dc - oldc.mean(axis=0)),
            modified7_dark_minus_modified7_bias=simple(mod7_dc - mod7_bc),
            increased_over_50=int((mod7_dc - oldc.mean(axis=0) > 50).sum()),
        ),
    )
    assert all(r['old_fingerprint_fit'] == 0 and r['above_max56'] == 112 for r in dark_files if r['id'] in DARK_IDS)
    assert total_rule31 == 0
    write(out_dir / 'result.json', result)
    print(json.dumps(dict(
        ok=True,
        mod7_fits=[r['old_fingerprint_fit'] for r in dark_files if r['id'] in DARK_IDS],
        mod7_above56=[r['above_max56'] for r in dark_files if r['id'] in DARK_IDS],
        rule31_sites=total_rule31,
        overall_dark_minus_bias_dn=result['modified7_net_signal']['overall_dark_minus_bias_dn'],
        bias_active_mean=ref_bias['modified7_bias']['active_mean'],
    ), indent=2))


if __name__ == '__main__':
    assert len(sys.argv) == 2 and sys.argv[1] in ('prepare', 'bias_dark')
    globals()[sys.argv[1]]()

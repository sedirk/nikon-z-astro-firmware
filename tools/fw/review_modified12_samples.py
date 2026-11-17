"""Independent-grade, read-only measurement of Modified12 NEFs vs Modified10 and Modified11.

No firmware edits or camera operations. Separates observed code values from
claims about unobserved sensor charge. No hardcoded acceptance booleans or plot labels.
"""
from pathlib import Path
import argparse, datetime, hashlib, itertools, json, shutil
import numpy as np
import rawpy
from scipy.ndimage import shift, gaussian_filter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from audit_nef import tiff_inventory, file_sha

ROOT = Path(__file__).resolve().parents[2]
PHASES = [('R', 0, 0), ('G1', 0, 1), ('G2', 1, 0), ('B', 1, 1)]
BLACK = 1008

M10_IDS = [4955, 4956, 4957]
M11_BIAS = [4958, 4959, 4960]
M11_DARK = [4961, 4962, 4963]
M11_FLAT = [4964, 4965, 4966]
M12_BIAS = [4967, 4968, 4969]
M12_DARK = [4970, 4971, 4972]
M12_FLAT = [4975, 4976, 4978]


def dump(p: Path, v) -> None:
    p.write_text(json.dumps(v, indent=2, ensure_ascii=False, allow_nan=False), encoding='utf8')


def stats(a: np.ndarray) -> dict:
    h = np.bincount(a.ravel(), minlength=16384)
    n = int(h.sum())
    x = np.arange(len(h))
    mu = float(h @ x / n)
    return dict(
        n=n,
        mean=mu,
        std=float(np.sqrt(h @ ((x - mu) ** 2) / n)),
        minimum=int(a.min()),
        maximum=int(a.max()),
        zero=int(h[0]),
        below_black=int(h[:BLACK].sum()),
        below_black_pct=float(100.0 * h[:BLACK].sum() / n),
        saturated=int(h[16383:].sum()),
    )


def fft_summary(counts: np.ndarray):
    amps = np.abs(np.fft.rfft(counts - counts.mean()))
    freq = np.fft.rfftfreq(len(counts))
    idx = np.flatnonzero((freq >= 0.10) & (freq <= 0.49))
    peak = idx[np.argmax(amps[idx])]
    band_med = float(np.median(amps[idx]))
    return (
        dict(
            peak_frequency=float(freq[peak]),
            period_dn=float(1.0 / freq[peak]),
            peak_amplitude=float(amps[peak]),
            band_median=band_med,
            peak_over_band_median=float(amps[peak] / band_med),
            nearest_02276_amplitude=float(amps[np.argmin(np.abs(freq - 0.2276))]),
            nearest_01714_amplitude=float(amps[np.argmin(np.abs(freq - (6.0 / 35.0)))]),
        ),
        freq,
        amps,
    )


def spectrum(data: np.ndarray):
    h = np.bincount(data.ravel(), minlength=16384)
    legacy, _, _ = fft_summary(h[int(data.min()):int(data.max()) + 1])
    fixed, f, a = fft_summary(h)
    k = np.arange(len(h))
    fixed['amplitude_normalized_by_n'] = float(fixed['peak_amplitude'] / data.size)
    fixed['exact_02276_amplitude'] = float(np.abs(h @ np.exp(-2j * np.pi * 0.2276 * k)))
    fixed['exact_6_over_35_amplitude'] = float(np.abs(h @ np.exp(-2j * np.pi * (6.0 / 35.0) * k)))
    fixed['exact_3_over_35_amplitude'] = float(np.abs(h @ np.exp(-2j * np.pi * (3.0 / 35.0) * k)))
    return dict(n=int(data.size), mean=float(data.mean()), legacy=legacy, fixed_grid=fixed), f, a / data.size


def dip_periodicity(raw: np.ndarray) -> dict:
    """Measure local histogram trough spacing on central 2000x2000 active region (1M samples/phase)."""
    sub = raw[1020:3020, 2032:4032]
    out = {}
    for name, dy, dx in PHASES:
        vals = sub[dy::2, dx::2].ravel()
        h = np.bincount(vals, minlength=16384)
        q10, q90 = np.percentile(vals, [10, 90])
        lo, hi = max(10, int(q10)), min(16370, int(q90))
        dips = []
        for c in range(lo, hi):
            if h[c] > 20 and h[c] < 0.88 * 0.5 * (h[c - 1] + h[c + 1]):
                dips.append(c)
        gaps = np.diff(dips).tolist() if len(dips) >= 2 else []
        out[name] = dict(
            window=[lo, hi],
            dip_count=len(dips),
            sample_dips=dips[:18],
            sample_gaps=gaps[:17],
            mean_gap=float(np.mean(gaps)) if gaps else None,
        )
    return out


def flat_maps(raw: np.ndarray):
    a = raw[8:4032, 8:6056]
    ny, nx = a.shape[0] // 16, a.shape[1] // 16
    planes = []
    for _, dy, dx in PHASES:
        p = a[dy:ny * 16:2, dx:nx * 16:2].reshape(ny, 8, nx, 8).mean(axis=(1, 3)) - BLACK
        planes.append(shift(p, ((dy - 0.5) / 16.0, (dx - 0.5) / 16.0), order=1, mode='nearest', prefilter=False))
    r, g1, g2, b = planes
    g = 0.5 * (g1 + g2)
    maps = np.stack([r / g, b / g, g1 / g2])
    maps /= maps[:, ny // 3:2 * ny // 3, nx // 3:2 * nx // 3].mean(axis=(1, 2), keepdims=True)
    yy, xx = np.mgrid[:ny, :nx]
    radius = np.hypot(xx * 16 + 7.5 - 3023.5, yy * 16 + 7.5 - 2011.5) / 2012.0
    edges = np.arange(0.0, 1.821, 0.02)
    radii = 0.5 * (edges[:-1] + edges[1:])
    bins = np.searchsorted(edges, radius, side='right') - 1
    valid = (bins >= 0) & (bins < len(radii))
    count = np.bincount(bins[valid], minlength=len(radii))

    def profile(v):
        sums = np.bincount(bins[valid], weights=v[valid], minlength=len(radii))
        return np.divide(sums, count, out=np.zeros_like(sums), where=count > 0)

    broad = np.stack([profile(100.0 * (v - 1.0)) for v in maps])
    hp = np.stack([profile(100.0 * (v / gaussian_filter(v, 6, mode='reflect') - 1.0)) for v in maps])
    keep = (radii >= 0.15) & (radii <= 0.90)
    met = dict(
        broad_ptp_pp=np.ptp(broad[:, keep], axis=1).tolist(),
        hp6_ptp_pp=np.ptp(hp[:, keep], axis=1).tolist(),
    )
    return maps, broad, hp, radii, met


def target_check(a: np.ndarray, baseline: dict) -> dict:
    """Evaluate frozen 112 sites using the exact frozen nearest-same-color 8-neighbour kernel.

    Note: In baseline112.json, kernel_R_B uses same-phase (+/-2) offsets while
    kernel_G1_G2 includes (+/-1,+/-1) diagonal green neighbours (crossing G1/G2)
    plus (+/-2,0)/(0,+/-2) axial green neighbours.
    """
    deltas = []
    centers = []
    for p in baseline['targets']:
        y, x = p['y'], p['x']
        c = int(a[y, x])
        centers.append(c)
        kernel = baseline['kernel_R_B' if y % 2 == x % 2 else 'kernel_G1_G2']
        deltas.append(c - max(int(a[y + dy, x + dx]) for dy, dx in kernel))
    d = np.array(deltas)
    return dict(
        points=len(d),
        kernel_definition='nearest_same_color_8_neighbours_per_frozen_baseline112',
        matches_0_8_to_56=int(np.isin(d, np.arange(0, 57, 8)).sum()),
        exact_neighbor_max=int((d == 0).sum()),
        above56=int((d > 56).sum()),
        saturated=int((np.array(centers) >= 16383).sum()),
        min_delta=int(d.min()),
        median_delta=float(np.median(d)),
        max_delta=int(d.max()),
        deltas=deltas,
        centers=centers,
    )


def bias_pair_stats(cache: dict, ids: list, group: str) -> list:
    rows = []
    for i, j in itertools.combinations(ids, 2):
        d = cache[i][8:4032, 8:6056].astype(np.int32) - cache[j][8:4032, 8:6056].astype(np.int32)
        q25, q75 = np.percentile(d, [25, 75])
        v = d[(d >= -20) & (d <= 20)]
        rows.append(
            dict(
                group=group,
                ids=[i, j],
                iqr_sigma_dn=float((q75 - q25) / (2.0 * 0.67448975 * np.sqrt(2.0))),
                untrimmed_sigma_dn=float(d.std() / np.sqrt(2.0)),
                trimmed_abs20_sigma_dn=float(v.std() / np.sqrt(2.0)),
                trimmed_kept=int(v.size),
                total=int(d.size),
            )
        )
    return rows


def compute_bias_4969_tail(cache: dict) -> dict:
    """Separately compute active-area vs stored-array tail (>2000 DN) for Z61_4969.NEF."""
    im67, im68, im69, im70 = cache[4967], cache[4968], cache[4969], cache[4970]
    act67 = im67[8:4032, 8:6056]
    act68 = im68[8:4032, 8:6056]
    act69 = im69[8:4032, 8:6056]
    act70 = im70[8:4032, 8:6056]

    ay, ax = np.where(act69 > 2000)
    sy, sx = np.where(im69 > 2000)
    border_only = [
        [int(y), int(x), int(im69[y, x])]
        for y, x in zip(sy, sx)
        if not (8 <= y < 4032 and 8 <= x < 6056)
    ]
    return dict(
        threshold_dn=2000,
        active_area=dict(
            bounds=[8, 4032, 8, 6056],
            count_gt_2000=int(len(ay)),
            saturated_16383_in_frame=int(np.count_nonzero(act69 >= 16383)),
            frame_std_dn=float(act69.std()),
            means_at_sites_dn={
                '4967': float(act67[ay, ax].mean()),
                '4968': float(act68[ay, ax].mean()),
                '4969': float(act69[ay, ax].mean()),
                '4970': float(act70[ay, ax].mean()),
            },
        ),
        stored_array=dict(
            shape=list(im69.shape),
            count_gt_2000=int(len(sy)),
            saturated_16383_in_frame=int(np.count_nonzero(im69 >= 16383)),
            frame_std_dn=float(im69.std()),
            means_at_sites_dn={
                '4967': float(im67[sy, sx].mean()),
                '4968': float(im68[sy, sx].mean()),
                '4969': float(im69[sy, sx].mean()),
                '4970': float(im70[sy, sx].mean()),
            },
            border_only_sites=border_only,
        ),
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    shutil.copy2(__file__, out / Path(__file__).name)

    frozen = ROOT / 'outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json'
    baseline = json.loads(frozen.read_text(encoding='utf8'))
    assert file_sha(frozen) == '4c3979cccf400b341e1859c31903e73e0d050f74dd96b3250eaf8d581cef11fb'

    report = dict(
        computation_completed=False,
        scope=__doc__,
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=file_sha(__file__),
        versions=dict(rawpy=rawpy.__version__, libraw=list(rawpy.libraw_version), numpy=np.__version__),
        baseline_sha256=file_sha(frozen),
        files=[],
        dark={},
        bias_pairs=[],
        bias_4969_tail={},
        active_dark_minus_mean_bias_dn={},
        flat_groups={},
        flat_group_correlations={},
        cautions=[
            'Peak/band-median is descriptive, not a multiple-testing-calibrated significance metric.',
            'Annular colour residuals combine optics, flat-panel illumination, PWM/flicker, framing, and camera processing.',
            'Zero C++/LibRaw decode mismatches verify lossless decompression of stored codes, not untouched sensor charge.',
            'Frame numbers in 11.14_modified12 lack 4973, 4974, and 4977 (reason unrecorded); kept files are not a camera event log.',
        ],
    )

    groups = [
        ('Modified10', '11.13_modified10', M10_IDS),
        ('Modified11', '11.14_modified11', M11_BIAS + M11_DARK + M11_FLAT),
        ('Modified12', '11.14_modified12', M12_BIAS + M12_DARK + M12_FLAT),
    ]
    cache = {}
    maps = {}
    broad = {}
    high = {}
    curves = {}
    flatrows = {}

    for group, folder, ids in groups:
        maps[group] = []
        broad[group] = []
        high[group] = []
        flatrows[group] = []
        for number in ids:
            path = ROOT / 'samples' / folder / f'Z61_{number}.NEF'
            before = file_sha(path)
            inv = tiff_inventory(path)
            with rawpy.imread(str(path)) as r:
                a = r.raw_image.copy()
                wb = [float(x) for x in r.camera_whitebalance]
                assert a.shape == (4040, 6064) and r.raw_pattern.tolist() == [[0, 1], [3, 2]]
                assert r.black_level_per_channel == [1008] * 4 and r.white_level == 16383
                sizes = r.sizes._asdict()
            active = a[8:4032, 8:6056]
            phase_active = {name: stats(active[dy::2, dx::2]) for name, dy, dx in PHASES}
            kind = (
                'BIAS' if number in (M11_BIAS + M12_BIAS)
                else 'DARK' if number in (M11_DARK + M12_DARK)
                else 'FLAT'
            )
            row = dict(
                id=number,
                name=path.name,
                path=str(path),
                group=group,
                kind=kind,
                sha256=before,
                tiff=inv,
                stored_pixels_sha256=hashlib.sha256(a.astype('<u2').tobytes()).hexdigest(),
                stored=stats(a),
                active=stats(active),
                active_phases=phase_active,
                sizes=sizes,
                black=[1008] * 4,
                white=16383,
                camera_whitebalance=wb,
            )
            if kind in ('BIAS', 'DARK'):
                cache[number] = a
            if kind == 'DARK':
                report['dark'][str(number)] = target_check(a, baseline)
            if kind == 'FLAT':
                central = a[1820:2220, 2832:3232]
                spectra = {}
                for name, dy, dx in PHASES:
                    val, f, amp = spectrum(central[dy::2, dx::2])
                    spectra[name] = val
                    curves[f'{number}_{name}'] = amp
                m, p, h, radii, metrics = flat_maps(a)
                means = {name: spectra[name]['mean'] - BLACK for name, _, _ in PHASES}
                metrics.update(
                    center_net=means,
                    rg1=float(means['R'] / means['G1']),
                    bg1=float(means['B'] / means['G1']),
                    g1_over_g2=float(means['G1'] / means['G2']),
                    spectra=spectra,
                    dip_periodicity_2000x2000=dip_periodicity(a),
                )
                row['flat'] = metrics
                maps[group].append(m)
                broad[group].append(p)
                high[group].append(h)
                flatrows[group].append(row)
            assert file_sha(path) == before
            report['files'].append(row)
            print(json.dumps(dict(file=path.name, group=group, kind=kind, active_mean=round(row['active']['mean'], 4))), flush=True)

    for number in (4854, 4855):
        path = ROOT / 'samples/11.9' / f'Z61_{number}.NEF'
        assert file_sha(path) == baseline['source_sha256'][str(path.relative_to(ROOT))]
        with rawpy.imread(str(path)) as r:
            report['dark'][str(number)] = target_check(r.raw_image, baseline)

    report['bias_pairs'].extend(bias_pair_stats(cache, M11_BIAS, 'Modified11'))
    report['bias_pairs'].extend(bias_pair_stats(cache, M12_BIAS, 'Modified12'))
    report['bias_4969_tail'] = compute_bias_4969_tail(cache)

    for grp, b_ids, d_ids in [('Modified11', M11_BIAS, M11_DARK), ('Modified12', M12_BIAS, M12_DARK)]:
        b_mu = float(np.mean([r['active']['mean'] for r in report['files'] if r['id'] in b_ids]))
        report['active_dark_minus_mean_bias_dn'][grp] = {
            str(r['id']): float(r['active']['mean'] - b_mu) for r in report['files'] if r['id'] in d_ids
        }
    b_mu_67_68 = float(np.mean([r['active']['mean'] for r in report['files'] if r['id'] in (4967, 4968)]))
    report['active_dark_minus_mean_bias_dn']['Modified12_vs_4967_4968'] = {
        str(r['id']): float(r['active']['mean'] - b_mu_67_68) for r in report['files'] if r['id'] in M12_DARK
    }

    keep = (radii >= 0.15) & (radii <= 0.90)
    mean_broad = {}
    mean_hp6 = {}
    for group in ('Modified10', 'Modified11', 'Modified12'):
        p = np.mean(broad[group], axis=0)
        h = np.mean(high[group], axis=0)
        mean_broad[group] = p
        mean_hp6[group] = h
        r_old_amps = [v['flat']['spectra']['R']['fixed_grid']['exact_02276_amplitude'] for v in flatrows[group]]
        r_new_amps = [v['flat']['spectra']['R']['fixed_grid']['exact_6_over_35_amplitude'] for v in flatrows[group]]
        b_old_amps = [v['flat']['spectra']['B']['fixed_grid']['peak_amplitude'] for v in flatrows[group]]
        report['flat_groups'][group] = dict(
            ids=[v['id'] for v in flatrows[group]],
            broad_ptp_pp=np.ptp(p[:, keep], axis=1).tolist(),
            hp6_ptp_pp=np.ptp(h[:, keep], axis=1).tolist(),
            means_of_individual_broad_ptp_pp=np.mean([v['flat']['broad_ptp_pp'] for v in flatrows[group]], axis=0).tolist(),
            means_of_individual_hp6_ptp_pp=np.mean([v['flat']['hp6_ptp_pp'] for v in flatrows[group]], axis=0).tolist(),
            mean_center_rg1=float(np.mean([v['flat']['rg1'] for v in flatrows[group]])),
            mean_center_bg1=float(np.mean([v['flat']['bg1'] for v in flatrows[group]])),
            mean_exact_02276_R_amp=float(np.mean(r_old_amps)),
            mean_exact_6_over_35_R_amp=float(np.mean(r_new_amps)),
            mean_dominant_B_amp=float(np.mean(b_old_amps)),
        )

    for a_g, b_g in [('Modified10', 'Modified12'), ('Modified11', 'Modified12'), ('Modified10', 'Modified11')]:
        report['flat_group_correlations'][f'{a_g}_vs_{b_g}'] = dict(
            broad_rg_r=float(np.corrcoef(mean_broad[a_g][0, keep], mean_broad[b_g][0, keep])[0, 1]),
            broad_bg_r=float(np.corrcoef(mean_broad[a_g][1, keep], mean_broad[b_g][1, keep])[0, 1]),
            hp6_rg_r=float(np.corrcoef(mean_hp6[a_g][0, keep], mean_hp6[b_g][0, keep])[0, 1]),
            hp6_bg_r=float(np.corrcoef(mean_hp6[a_g][1, keep], mean_hp6[b_g][1, keep])[0, 1]),
        )

    np.savez_compressed(
        out / 'measurements.npz',
        frequency=f,
        radii=radii,
        **curves,
        **{f'{g}_ratio_maps': np.array(v) for g, v in maps.items()},
        **{f'{g}_broad': np.array(v) for g, v in broad.items()},
        **{f'{g}_hp6': np.array(v) for g, v in high.items()},
    )

    # Figure 1: 4-panel M10 vs M11 vs M12 quantitative comparison (all labels dynamically interpolated)
    fig, ax = plt.subplots(2, 2, figsize=(13.5, 9.2), layout='constrained')
    colors = {'Modified10': '#c44939', 'Modified11': '#226cb8', 'Modified12': '#1b8a5a'}
    group_flat_ids = {'Modified10': M10_IDS, 'Modified11': M11_FLAT, 'Modified12': M12_FLAT}
    sel = (f >= 0.10) & (f <= 0.49)
    for group, ids in group_flat_ids.items():
        amps = np.array([curves[f'{i}_R'] for i in ids])
        ax[0, 0].plot(f[sel], amps.mean(axis=0)[sel], color=colors[group], label=group, lw=1.3)
        ax[0, 0].fill_between(f[sel], amps.min(axis=0)[sel], amps.max(axis=0)[sel], color=colors[group], alpha=0.14)
        for k, target in enumerate([ax[0, 1], ax[1, 0]]):
            for individual in broad[group]:
                target.plot(radii[keep], individual[k, keep], color=colors[group], alpha=0.22, lw=0.9)
            target.plot(radii[keep], mean_broad[group][k, keep], color=colors[group], label=group, lw=1.8)
    ax[0, 0].axvline(0.2276, color='#c44939', ls=':', alpha=0.7, label='0.2276 cyc/DN (old gain comb)')
    ax[0, 0].axvline(6.0 / 35.0, color='#555555', ls='--', alpha=0.7, label='6/35=0.1714 cyc/DN (residual peak)')
    ax[0, 0].set(
        title='Red central 400x400 histogram FFT (uniform 16384-bin grid)',
        xlabel='Frequency (cycles / DN)',
        ylabel='DFT amplitude / 40000 pixels',
    )
    ax[0, 1].set(
        title='Unfiltered R/G annular profile (r in [0.15, 0.90])',
        xlabel='Radius / 2012 px',
        ylabel='Relative to own centre 1/3 (%)',
    )
    ax[1, 0].set(
        title='Unfiltered B/G annular profile (r in [0.15, 0.90])',
        xlabel='Radius / 2012 px',
        ylabel='Relative to own centre 1/3 (%)',
    )
    dk4854 = report['dark']['4854']
    dk4961 = report['dark']['4961']
    ax[1, 1].scatter(
        range(dk4854['points']),
        dk4854['deltas'],
        s=14,
        label=f"Stock 4854 ({dk4854['matches_0_8_to_56']}/{dk4854['points']} in {{0..56}})",
        color='#c44939',
    )
    ax[1, 1].scatter(
        range(dk4961['points']),
        dk4961['deltas'],
        s=12,
        alpha=0.55,
        label=f"M11 4961 ({dk4961['matches_0_8_to_56']}/{dk4961['points']} in {{0..56}})",
        color='#226cb8',
    )
    for n in M12_DARK:
        dkn = report['dark'][str(n)]
        ax[1, 1].scatter(
            range(dkn['points']),
            dkn['deltas'],
            s=10,
            alpha=0.55,
            label=f"M12 {n} ({dkn['matches_0_8_to_56']}/{dkn['points']} in {{0..56}})",
            color='#1b8a5a',
        )
    ax[1, 1].axhline(56, ls=':', color='gray', label='Old clamp ceiling (+56 DN)')
    ax[1, 1].set(
        title='Frozen 112 sites: centre - max(8 nearest same-colour neighbours)',
        xlabel='Frozen site index (0..111)',
        ylabel='Centre - max8 neighbour (DN)',
    )
    for panel in ax.flat:
        panel.grid(alpha=0.22)
        panel.legend(fontsize=7.6)
    fig.suptitle('Modified12 Real-NEF Measurements vs Modified10 & Modified11')
    fig.savefig(out / 'modified12-comparison.png', dpi=170)
    plt.close(fig)

    # Figure 2: 2x3 unfiltered 2D colour-ratio maps across M10, M11, M12
    fig, ax = plt.subplots(2, 3, figsize=(14.5, 8.2), layout='constrained')
    for j, group in enumerate(['Modified10', 'Modified11', 'Modified12']):
        mean_map = np.mean(maps[group], axis=0)
        for k, ch in enumerate(['R/G', 'B/G']):
            im = ax[k, j].imshow(100.0 * (mean_map[k] - 1.0), vmin=-2.5, vmax=2.5, cmap='RdBu_r', interpolation='nearest')
            ax[k, j].set(title=f'{group} {ch} (3-flat mean)', xlabel='16-px block X', ylabel='16-px block Y')
            fig.colorbar(im, ax=ax[k, j], label='% vs own centre', shrink=0.82)
    fig.suptitle('Unfiltered 2D Colour-Ratio Maps (Optics + Flat Panel + Sensor/ISP Combined)')
    fig.savefig(out / 'modified12-ratio-maps.png', dpi=160)
    plt.close(fig)

    m12_only = [v for v in report['files'] if v['group'] == 'Modified12']
    m12_flats_only = [v for v in m12_only if v['kind'] == 'FLAT']
    report['computation_completed'] = True
    dump(out / 'assessment.json', report)
    dump(out / 'decode-input.json', dict(files=m12_only))
    dump(out / 'nefinfo-all-m12-input.json', dict(files=m12_only))
    dump(out / 'nefinfo-flats-input.json', dict(files=m12_flats_only))
    print(
        json.dumps(
            dict(
                computation_completed=True,
                m12_files=len(m12_only),
                flat_groups=report['flat_groups'],
                correlations=report['flat_group_correlations'],
            )
        ),
        flush=True,
    )


if __name__ == '__main__':
    main()

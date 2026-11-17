"""Compare raw CFA flat-field chromatic structures across modified4, modified6, and modified7.

Uses the exact established floating-point 16x16 CFA block-mean method without
demosaicing or lens correction, plus a real Master-BIAS subtraction control
using the newly captured 11.12_modified7 BIAS frames (4922, 4923, 4924).
"""
from pathlib import Path
import argparse, datetime, json
import numpy as np
import rawpy
import scipy
from scipy.ndimage import gaussian_filter, uniform_filter1d
from audit_nef import file_sha
from analyze_modified1_flats import PHASES, bin_raw, register, ratios, normalize, centre, radial, stats

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / 'analysis/modified7-real-2026-11-12'
GROUPS = ('A_modified4', 'C_modified6', 'B_modified7')


def need(v, msg):
    if not v:
        raise ValueError(msg)


def read(p):
    return json.loads(Path(p).read_text(encoding='utf8'))


def finite_stats(v):
    return stats(np.asarray(v)[np.isfinite(v)])


def profile_stats(v, r):
    values = v[(r >= 0.15) & (r <= 0.90)]
    return dict(
        min=float(values.min()),
        max=float(values.max()),
        peak_to_peak=float(np.ptp(values)),
        rms=float(np.sqrt(np.mean(values ** 2))),
    )


def coordinates(size, shape):
    yy, xx = np.mgrid[:shape[0], :shape[1]]
    x = xx * size + (size - 1) / 2
    y = yy * size + (size - 1) / 2
    rr = np.hypot(x - (6048 - 1) / 2, y - (4024 - 1) / 2) / 2012
    theta = (np.arctan2(y - (4024 - 1) / 2, x - (6048 - 1) / 2) + 2 * np.pi) % (2 * np.pi)
    return rr, theta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)

    inputs = read(ROUND / 'inputs.json')
    files = inputs['files']
    bias_files = inputs['bias_files']
    need(len(files) == 7 and len(bias_files) == 3, 'Expected 7 flats and 3 bias frames')

    # Build master bias block map (bin=16) from 4922, 4923, 4924
    bias_maps16 = []
    for brow in bias_files:
        bpath = Path(brow['path'])
        need(file_sha(bpath) == brow['sha256'], 'Bias file changed')
        with rawpy.imread(str(bpath)) as r:
            bias_maps16.append(bin_raw(r.raw_image, 16))
    master_bias16 = np.mean(bias_maps16, axis=0, dtype=np.float64)

    report = dict(
        ok=False,
        scope=__doc__,
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        input_contract_sha256=file_sha(ROUND / 'inputs.json'),
        conditions=inputs['design'],
        user_confirmation=inputs['user_confirmation'],
        versions=dict(rawpy=rawpy.__version__, libraw=list(rawpy.libraw_version),
                      numpy=np.__version__, scipy=scipy.__version__),
        method=dict(
            bin=16, float_mean=True,
            phase_alignment='bilinear +/-0.5 sensor pixel to common block centre',
            normalization='each frame/ratio divided by its central-third rectangular mean',
            radius_unit='2012 sensor pixels; geometric centre only',
            radial_bin=0.02, descriptive_radius_interval=[0.15, 0.90],
            signal_unit='saved DN minus metadata black (1008), plus Master-BIAS control',
            no_postprocess=True, no_warp_or_image_registration=True,
        ),
        files=[], scalar_block_checks=0, scale_controls=[], black_controls=[],
        within_group=[], pwm_row_controls=[],
    )

    maps = {size: [] for size in (16, 32, 64)}
    for row in files:
        path = Path(row['path'])
        need(file_sha(path) == row['sha256'], 'Input changed')
        with rawpy.imread(str(path)) as r:
            raw = r.raw_image
            need(raw.shape == (4040, 6064) and r.raw_pattern.tolist() == [[0, 1], [3, 2]], 'Geometry/CFA changed')
            need(r.black_level_per_channel == [1008] * 4 and r.white_level == 16383, 'Black/white level changed')
            for size in maps:
                maps[size].append(bin_raw(raw, size))
            active = raw[8:4032, 8:6056]
            phase = []
            for k, (name, dy, dx) in enumerate(PHASES):
                plane = active[dy::2, dx::2]
                phase.append(dict(
                    name=name, pixels=int(plane.size), min=int(plane.min()), max=int(plane.max()),
                    zero=int(np.count_nonzero(plane == 0)), saturated=int(np.count_nonzero(plane >= 16383)),
                    mean_signal=float(plane.mean(dtype=np.float64) - 1008),
                    centre_mean_signal=float(centre(maps[16][-1][k]).mean() - 1008),
                    percentiles_signal=(np.percentile(plane, [1, 50, 99, 99.9]) - 1008).tolist(),
                ))
            # PWM high-pass row banding check on raw green rows
            g_plane = 0.5 * (active[0::2, 1::2].astype(np.float64) + active[1::2, 0::2].astype(np.float64)) - 1008.0
            row_prof = g_plane.mean(axis=1)
            row_hp = 100.0 * (row_prof / uniform_filter1d(row_prof, size=25, mode='reflect') - 1.0)
            report['pwm_row_controls'].append(dict(
                id=row['id'], group=row['group'],
                row_hp_rms_percent=float(np.sqrt(np.mean(row_hp ** 2))),
                row_hp_ptp_percent=float(np.ptp(row_hp)),
            ))
            for by, bx in ((0, 0), (1, 1), (50, 70), (120, 180), (200, 300), (250, 377)):
                for k, (_, dy, dx) in enumerate(PHASES):
                    s = sum(int(raw[8 + by * 16 + y, 8 + bx * 16 + x]) for y in range(dy, 16, 2) for x in range(dx, 16, 2))
                    need(maps[16][-1][k, by, bx] == s / 64, 'Block sum mismatch')
                    report['scalar_block_checks'] += 1
        report['files'].append(dict(id=row['id'], group=row['group'], path=str(path), sha256=row['sha256'],
                                    capture_time=row['capture_time'], phases=phase))

    codes = np.stack(maps[16])
    signals = codes - 1008.0
    aligned = np.stack([register(v) for v in signals])
    rats = np.stack([ratios(v) for v in aligned])
    unreg = np.stack([ratios(v) for v in signals])
    green = aligned[:, 1:3].mean(axis=1)
    gn = normalize(green)
    rr, theta = coordinates(16, green.shape[1:])
    core = (rr >= 0.15) & (rr <= 0.90)
    edges = np.arange(0, 1.821, 0.02)
    radii = (edges[:-1] + edges[1:]) / 2
    keep = (radii >= 0.15) & (radii <= 0.90)

    profiles = np.stack([[radial(100 * (v - 1), rr, edges)[0] for v in frame] for frame in rats])
    sectors = np.stack([[[radial(100 * (v - 1), rr, edges, (theta >= s * np.pi / 4) & (theta < (s + 1) * np.pi / 4))[0]
                          for s in range(8)] for v in frame] for frame in rats])
    gprofiles = np.stack([radial(v, rr, edges)[0] for v in gn])

    g_idx = {g: [j for j, r in enumerate(files) if r['group'] == g] for g in GROUPS}
    groups_r = np.stack([rats[g_idx[g]].mean(axis=0) for g in GROUPS])
    groups_g = np.stack([gn[g_idx[g]].mean(axis=0) for g in GROUPS])
    g_profiles = np.stack([profiles[g_idx[g]].mean(axis=0) for g in GROUPS])

    # High-pass local residual maps & radial high-pass ripple checks (sigma = 3, 6, 12)
    hp = np.stack([[[100 * (v / gaussian_filter(v, sigma=s, mode='reflect') - 1) for v in frame]
                    for frame in rats] for s in (3, 6, 12)])
    hp6_profiles = np.stack([[radial(v, rr, edges)[0] for v in frame] for frame in hp[1]])
    g_hp6_profiles = np.stack([hp6_profiles[g_idx[g]].mean(axis=0) for g in GROUPS])

    report['centre_green_signals'] = [float(centre(v).mean()) for v in green]
    report['radial_profiles'] = {
        str(files[j]['id']): {name: profile_stats(profiles[j, k], radii) for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))}
        for j in range(len(files))
    }
    report['group_radial_metrics'] = [
        dict(
            group=g,
            ids=[files[j]['id'] for j in g_idx[g]],
            metrics={name: profile_stats(g_profiles[gi, k], radii) for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))},
            highpass_sigma6_radial={name: profile_stats(g_hp6_profiles[gi, k], radii) for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))},
        )
        for gi, g in enumerate(GROUPS)
    ]

    # Master-BIAS calibrated flat control on B_modified7 (4928, 4930, 4931)
    b7_codes = codes[g_idx['B_modified7']]
    b7_bias_aligned = np.stack([register(v - master_bias16) for v in b7_codes])
    b7_bias_rats = np.stack([ratios(v) for v in b7_bias_aligned])
    b7_bias_prof = np.stack([[radial(100 * (v - 1), rr, edges)[0] for v in frame] for frame in b7_bias_rats]).mean(axis=0)
    b7_bias_hp6 = np.stack([[radial(100 * (v / gaussian_filter(v, sigma=6, mode='reflect') - 1), rr, edges)[0]
                             for v in frame] for frame in b7_bias_rats]).mean(axis=0)
    report['master_bias_control_modified7'] = dict(
        bias_ids=[r['id'] for r in bias_files],
        master_bias_phase_means=[float(master_bias16[k].mean()) for k in range(4)],
        broad_radial_metrics={name: profile_stats(b7_bias_prof[k], radii) for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))},
        highpass_sigma6_radial={name: profile_stats(b7_bias_hp6[k], radii) for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))},
        max_abs_profile_diff_from_1008_percent={
            name: float(np.max(np.abs(b7_bias_prof[k, keep] - g_profiles[2, k, keep])))
            for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))
        },
    )

    # Cross-group correlations (B_modified7 vs A_modified4 and C_modified6)
    report['radial_correlations_vs_modified7'] = {
        other: {
            name: dict(
                broad_radial_corr=float(np.corrcoef(g_profiles[2, k, keep], g_profiles[gi, k, keep])[0, 1]),
                hp6_radial_corr=float(np.corrcoef(g_hp6_profiles[2, k, keep], g_hp6_profiles[gi, k, keep])[0, 1]),
            )
            for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))
        }
        for gi, other in ((0, 'A_modified4'), (1, 'C_modified6'))
    }

    # Within-group repeatability
    for g in GROUPS:
        idxs = g_idx[g]
        for a_i in range(len(idxs)):
            for b_i in range(a_i + 1, len(idxs)):
                f1, f2 = idxs[a_i], idxs[b_i]
                report['within_group'].append(dict(
                    group=g, ids=[files[f1]['id'], files[f2]['id']],
                    normalized_green_difference_percent=finite_stats(100 * (gn[f2][core] / gn[f1][core] - 1)),
                    ratios={name: finite_stats(100 * (rats[f2, k][core] / rats[f1, k][core] - 1))
                            for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))},
                    radial_correlation={name: float(np.corrcoef(profiles[f1, k, keep], profiles[f2, k, keep])[0, 1])
                                        for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))},
                ))

    difference_m7_vs_m4 = 100 * (groups_r[2] / groups_r[0] - 1)
    gdiff_m7_vs_m4 = 100 * (groups_g[2] / groups_g[0] - 1)
    report['green_group_difference_m7_vs_m4_percent'] = finite_stats(gdiff_m7_vs_m4[core])
    report['ratio_group_difference_m7_vs_m4_percent'] = {
        name: finite_stats(difference_m7_vs_m4[k][core]) for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))
    }

    for size in (32, 64):
        arr = np.stack([ratios(register(v - 1008.0, size)) for v in maps[size]])
        radius, _ = coordinates(size, arr.shape[-2:])
        p = np.stack([[radial(100 * (v - 1), radius, edges)[0] for v in frame] for frame in arr])
        report['scale_controls'].append(dict(
            bin=size,
            group_radial_peak_to_peak={
                g: {
                    name: float(np.ptp(p[g_idx[g], k].mean(axis=0)[keep]))
                    for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))
                }
                for g in GROUPS
            },
        ))

    for black in (1004, 1012):
        other = np.stack([ratios(register(v - black)) for v in codes])
        report['black_controls'].append(dict(
            black=black,
            delta_from_1008_percent={
                str(files[j]['id']): {
                    name: finite_stats(100 * (other[j, k][core] / rats[j, k][core] - 1))
                    for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))
                }
                for j in range(len(files))
            },
        ))

    report['phase_alignment_control'] = {
        str(files[j]['id']): {
            name: finite_stats(100 * (rats[j, k][core] / unreg[j, k][core] - 1))
            for k, name in enumerate(('R/G', 'B/G', 'G1/G2'))
        }
        for j in range(len(files))
    }

    np.savez_compressed(
        a.output / 'maps.npz',
        ids=np.array([r['id'] for r in files]),
        groups=np.array(GROUPS),
        codes=codes, signals=signals, aligned=aligned, ratios=rats,
        unregistered_ratios=unreg, green=green, green_normalized=gn,
        master_bias16=master_bias16, b7_bias_profiles=b7_bias_prof, b7_bias_hp6=b7_bias_hp6,
        radius=rr, radial_edges=edges, radial_centres=radii,
        profiles=profiles, hp6_profiles=hp6_profiles, sectors=sectors, green_profiles=gprofiles,
        group_ratios=groups_r, group_green=groups_g, group_profiles=g_profiles, group_hp6_profiles=g_hp6_profiles,
        ratio_group_difference_m7_vs_m4_percent=difference_m7_vs_m4,
        green_group_difference_m7_vs_m4_percent=gdiff_m7_vs_m4,
        highpass_percent=hp,
    )
    need(all(file_sha(r['path']) == r['sha256'] for r in files), 'Source changed after analysis')
    report['ok'] = True
    (a.output / 'result.json').write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False), encoding='utf8')
    for name in (Path(__file__).name, 'analyze_modified1_flats.py', 'audit_nef.py'):
        (a.output / name).write_bytes((ROOT / 'tools/fw' / name).read_bytes())
    print(json.dumps(dict(
        ok=True,
        group_radial_metrics=report['group_radial_metrics'],
        master_bias_diff=report['master_bias_control_modified7']['max_abs_profile_diff_from_1008_percent'],
        correlations=report['radial_correlations_vs_modified7'],
        scalar_block_checks=report['scalar_block_checks'],
    ), indent=2))


if __name__ == '__main__':
    main()

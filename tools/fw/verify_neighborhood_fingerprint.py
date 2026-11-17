"""Recheck an exploratory saved-NEF fingerprint and explicit controls.

The nearest-color kernel and 8-DN residual were chosen after inspecting these
same files. Extended bias-only sites are an internal comparison, not new
independent captures. No firmware algorithm is implemented by this script.
"""
from pathlib import Path
import argparse, json
import numpy as np
import rawpy
from audit_nef import file_sha

ROOT = Path(__file__).resolve().parents[2]
K_RB = [(dy, dx) for dy in (-2, 0, 2) for dx in (-2, 0, 2) if dy or dx]
K_G = [(-2, 0), (2, 0), (0, -2), (0, 2), (-1, -1), (-1, 1), (1, -1), (1, 1)]


def maxima(im, ys, xs):
    same = np.maximum.reduce([im[ys + dy, xs + dx] for dy, dx in K_RB])
    green = np.maximum.reduce([im[ys + dy, xs + dx] for dy, dx in K_G])
    return np.where((ys + xs) % 2, green, same).astype(np.int32)


def histogram(v):
    keys, counts = np.unique(v, return_counts=True)
    return {str(int(k)): int(c) for k, c in zip(keys, counts)}


def evaluate(images, ys, xs, maximum_from=None):
    centre = np.array([im[ys, xs] for im in images], dtype=np.int32).T
    mx = np.array([maxima(im, ys, xs) for im in (maximum_from or images)]).T
    delta = centre - mx
    fit = (delta >= 0) & (delta <= 56) & (delta % 8 == 0)
    return dict(n=len(ys), both_fit=int(fit.all(axis=1).sum()),
        either_fit=int(fit.any(axis=1).sum()), per_frame_fit=fit.sum(axis=0).tolist(),
        both_exact_max=int((delta == 0).all(axis=1).sum()),
        delta_histogram=histogram(delta), remainder_mod8_histogram=histogram(delta % 8)), centre, mx, delta, fit


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); a.output.mkdir(parents=True, exist_ok=False)
    discovery = ROOT / 'analysis/raw-neighborhood-2026-11-09/targets/result.json'
    previous = json.loads(discovery.read_text(encoding='utf8'))
    paths = [ROOT / 'samples/11.9' / f'Z61_{i}.NEF' for i in range(4851, 4856)]
    hashes = {str(q.relative_to(ROOT)): file_sha(q) for q in paths}
    images = []
    for q in paths:
        with rawpy.imread(str(q)) as r:
            assert r.raw_image.shape == (4040, 6064)
            images.append(r.raw_image.copy())
    ys = np.array([r['raw_y'] for r in previous['targets']])
    xs = np.array([r['raw_x'] for r in previous['targets']])
    result, centre, mx, delta, fit = evaluate(images[3:], ys, xs)
    assert len(ys) == 112 and fit.all()
    rows = []
    # A second, scalar calculation uses the previously exported 17x17 patches.
    # This catches shifted coordinates and a mistaken vectorized CFA mask.
    for i, old in enumerate(previous['targets']):
        offsets = K_G if old['phase'].startswith('G') else K_RB
        scalar = [max(old['raw_17x17_patches'][j][8+dy][8+dx] for dy, dx in offsets) for j in (3, 4)]
        assert scalar == mx[i].tolist()
        assert old['centres'][3:5] == centre[i].tolist()
        rows.append(dict(x=int(xs[i]), y=int(ys[i]), phase=old['phase'],
            dark_centres=centre[i].tolist(), nearest_color_max=scalar,
            delta=delta[i].tolist(), k=(delta[i] // 8).tolist()))
    phase_summaries = {}
    for phase in ('R', 'G1', 'G2', 'B'):
        m = np.array([r['phase'] == phase for r in previous['targets']])
        phase_summaries[phase] = evaluate(images[3:], ys[m], xs[m])[0]
    controls = []
    for shift in (-32, 32):
        q = evaluate(images[3:], ys, xs + shift)[0]
        controls.append(dict(kind='same-phase nearby positions', shift_x=shift, **q))
    controls.append(dict(kind='swap the two dark neighbour fields at the same positions',
        **evaluate(images[3:], ys, xs, maximum_from=images[3:][::-1])[0]))
    # Broaden selection using only the three bias frames. No dark test or
    # nearest-max equality participates in this selection.
    sel = np.minimum.reduce(images[:3]) > 1108
    sel[:10, :] = False; sel[4030:, :] = False
    sel[:, :10] = False; sel[:, 6054:] = False
    sel[ys, xs] = False
    ey, ex = np.nonzero(sel)
    local_peak = np.logical_and.reduce([im[ey, ex] > maxima(im, ey, ex) for im in images[:3]])
    ey, ex = ey[local_peak], ex[local_peak]
    expanded, ec, em, ed, ef = evaluate(images[3:], ey, ex)
    expanded['selection'] = 'all three bias >1108 and strict nearest-color local maximum; excluding discovery112; no dark-value selection'
    expanded['fit_coordinates'] = [dict(x=int(ex[i]), y=int(ey[i]), dark=ec[i].tolist(), maximum=em[i].tolist(), delta=ed[i].tolist()) for i in np.flatnonzero(ef.all(axis=1))]
    expanded['nonfit_count'] = int((~ef.all(axis=1)).sum())
    assert all(file_sha(ROOT / q) == h == previous['source_sha256'][q] for q, h in hashes.items())
    report = dict(ok=True, scope=__doc__, source_sha256=hashes,
        exported_patch_evidence_sha256=file_sha(discovery),
        coordinates='zero-based full stored CFA; no demosaic/black subtraction/postprocess',
        kernel_R_B=K_RB, kernel_G1_G2=K_G, formula='centre = nearest_same_color_max8 + 8*k, integer k in 0..7',
        discovery112=result, phases=phase_summaries, controls=controls,
        bias_only_additional_sites=expanded, targets=rows, sources_unchanged=True,
        inference='A repeatable stored-pixel fingerprint. Does not identify the processor, exposure threshold, random-number mechanism or candidate firmware effect.')
    (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    (a.output / 'source.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps({k: report[k] for k in ('discovery112', 'phases', 'controls')}, indent=2))
    print(json.dumps(dict(additional_bias_only_sites=expanded['n'], both_fit=expanded['both_fit'], nonfit=expanded['nonfit_count'])))


if __name__ == '__main__':
    main()

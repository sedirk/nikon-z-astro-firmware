"""Strict coverage/provenance validator and race-free manifest freezer for Modified12 real-NEF audit."""
from pathlib import Path
import argparse
import binascii
import datetime
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/modified12-real-2026-11-14'

EXPECTED_FW_REL = 'outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN'
EXPECTED_FW_SHA256 = '9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c'
EXPECTED_FW_CRC16_HEX = 'dded'

EXPECTED_M12_KINDS = {
    4967: 'BIAS',
    4968: 'BIAS',
    4969: 'BIAS',
    4970: 'DARK',
    4971: 'DARK',
    4972: 'DARK',
    4975: 'FLAT',
    4976: 'FLAT',
    4978: 'FLAT',
}
STORED_PIXELS_PER_FRAME = 6064 * 4040  # 24,498,560
ACTIVE_PIXELS_PER_FRAME = 6048 * 4024  # 24,337,152
TOTAL_M12_STORED_PIXELS = 9 * STORED_PIXELS_PER_FRAME  # 220,487,040


def read_json(p: Path):
    return json.loads(p.read_text(encoding='utf8'))


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def need(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def validate_audit(root: Path = ROOT, out: Path = OUT, write_outputs: bool = True) -> dict:
    fw_path = root / EXPECTED_FW_REL
    need(fw_path.is_file(), f'missing Modified12 firmware binary: {fw_path}')
    fw_bytes = fw_path.read_bytes()
    need(len(fw_bytes) > 2, 'firmware binary unexpectedly small')
    actual_fw_sha = hashlib.sha256(fw_bytes).hexdigest()
    actual_fw_crc_hex = fw_bytes[-2:].hex()
    need(actual_fw_sha == EXPECTED_FW_SHA256, f'firmware SHA-256 mismatch: {actual_fw_sha}')
    need(
        actual_fw_crc_hex == EXPECTED_FW_CRC16_HEX and binascii.crc_hqx(fw_bytes, 0) == 0,
        f'firmware CRC16 check failed: tail={actual_fw_crc_hex}',
    )

    assess_path = out / 'samples-v2/assessment.json'
    dec_in_path = out / 'samples-v2/decode-input.json'
    nef_in_path = out / 'samples-v2/nefinfo-all-m12-input.json'
    decode_path = out / 'independent-lossless/result.json'
    nefinfo_path = out / 'nefinfo/result.json'

    for req_p in (assess_path, dec_in_path, nef_in_path, decode_path, nefinfo_path):
        need(req_p.is_file(), f'missing required audit artifact: {req_p}')

    a = read_json(assess_path)
    dec_in = read_json(dec_in_path)
    nef_in = read_json(nef_in_path)
    d = read_json(decode_path)
    n = read_json(nefinfo_path)

    need(a.get('computation_completed') is True, 'sample assessment incomplete')

    m12_rows = [x for x in a.get('files', []) if x.get('group') == 'Modified12']
    need(len(m12_rows) == 9, f'expected 9 Modified12 rows, got {len(m12_rows)}')

    seen_ids = [x.get('id') for x in m12_rows]
    seen_names = [x.get('name') for x in m12_rows]
    seen_sha = [x.get('sha256') for x in m12_rows]
    seen_pix_sha = [x.get('stored_pixels_sha256') for x in m12_rows]

    need(
        len(set(seen_ids)) == 9 and set(seen_ids) == set(EXPECTED_M12_KINDS.keys()),
        f'Modified12 unique ID set mismatch: {seen_ids}',
    )
    need(len(set(seen_names)) == 9, 'duplicate Modified12 file names in assessment.json')
    need(len(set(seen_sha)) == 9, 'duplicate source file SHA-256 across 9 distinct NEFs')
    need(len(set(seen_pix_sha)) == 9, 'duplicate stored_pixels_sha256 across 9 distinct NEFs')

    m12_by_name = {}
    for row in m12_rows:
        fid = row['id']
        expected_name = f'Z61_{fid}.NEF'
        need(row['name'] == expected_name, f"id/name mismatch: {fid} vs {row['name']}")
        need(row.get('kind') == EXPECTED_M12_KINDS[fid], f"unexpected kind for {expected_name}: {row.get('kind')}")
        src_p = Path(row['path'])
        need(src_p.is_file(), f'missing source NEF on disk: {src_p}')
        need(sha256_file(src_p) == row['sha256'], f"source NEF SHA-256 mismatch: {row['name']}")
        need(
            isinstance(row.get('stored_pixels_sha256'), str) and len(row['stored_pixels_sha256']) == 64,
            f"invalid stored_pixels_sha256 in {row['name']}",
        )
        need(
            row['stored']['n'] == STORED_PIXELS_PER_FRAME and row['active']['n'] == ACTIVE_PIXELS_PER_FRAME,
            f"unexpected stored/active pixel counts in {row['name']}",
        )
        need(
            row['active']['zero'] == 0 and row['stored']['zero'] == 0,
            f"unexpected 0 ADU pixels in {row['name']}",
        )
        m12_by_name[row['name']] = row

    # Input manifest entry-by-entry provenance binding against assessment.json
    dec_in_sha = sha256_file(dec_in_path)
    nef_in_sha = sha256_file(nef_in_path)
    for manifest_label, manifest_obj in (
        ('decode-input.json', dec_in),
        ('nefinfo-all-m12-input.json', nef_in),
    ):
        m_files = manifest_obj.get('files', [])
        need([x.get('name') for x in m_files] == seen_names, f'{manifest_label} file list mismatch')
        for item, ref in zip(m_files, m12_rows):
            need(item.get('id') == ref['id'] and item.get('kind') == ref['kind'] and item.get('group') == 'Modified12', f'{manifest_label} id/kind/group mismatch for {ref["name"]}')
            need(Path(item.get('path', '')) == Path(ref['path']), f'{manifest_label} path mismatch for {ref["name"]}')
            need(item.get('sha256') == ref['sha256'], f'{manifest_label} sha256 mismatch for {ref["name"]}')
            need(item.get('stored_pixels_sha256') == ref['stored_pixels_sha256'], f'{manifest_label} stored_pixels_sha256 mismatch for {ref["name"]}')
        need(manifest_obj == dict(files=m12_rows), f'{manifest_label} payload diverges from assessment Modified12 rows')

    nef_flats_in_path = out / 'samples-v2/nefinfo-flats-input.json'
    if nef_flats_in_path.is_file():
        nef_flats_in = read_json(nef_flats_in_path)
        expected_flats = [r for r in m12_rows if r['kind'] == 'FLAT']
        need(nef_flats_in == dict(files=expected_flats), 'nefinfo-flats-input.json payload diverges from assessment Modified12 FLAT rows')
    # Cross-report checks: independent C++ vs LibRaw decode
    need(d.get('ok') is True, 'decode result ok != True')
    need(d.get('audit_sha256') == dec_in_sha, 'decode result audit_sha256 != sha256(decode-input.json)')
    dec_files = d.get('files', [])
    need(len(dec_files) == 9, f'expected 9 files in decode result, got {len(dec_files)}')
    dec_names = [x.get('name') for x in dec_files]
    need(len(set(dec_names)) == 9 and set(dec_names) == set(seen_names), 'decode result filenames duplicate or incomplete')

    sum_pixels = 0
    for df in dec_files:
        ref = m12_by_name[df['name']]
        need(df.get('source_sha256') == ref['sha256'], f"decode source_sha256 mismatch for {df['name']}")
        need(df.get('pixels_sha256') == ref['stored_pixels_sha256'], f"decode pixels_sha256 mismatch for {df['name']}")
        need(df.get('pixels') == STORED_PIXELS_PER_FRAME, f"decode per-file pixels != {STORED_PIXELS_PER_FRAME} for {df['name']}")
        need(df.get('mismatches') == 0 and df.get('returncode') == 0, f"decode mismatch/failure in {df['name']}")
        sum_pixels += int(df['pixels'])
    need(
        sum_pixels == TOTAL_M12_STORED_PIXELS and d.get('total_pixels') == TOTAL_M12_STORED_PIXELS,
        f'decode total_pixels mismatch: sum={sum_pixels}, header={d.get("total_pixels")}',
    )

    # Cross-report checks: NEFInfo 0x6 / 0x7
    need(n.get('ok') is True, 'nefinfo result ok != True')
    need(n.get('audit_sha256') == nef_in_sha, 'nefinfo result audit_sha256 != sha256(nefinfo-all-m12-input.json)')
    nef_files = n.get('files', [])
    need(len(nef_files) == 9, f'expected 9 files in nefinfo result, got {len(nef_files)}')
    nef_names = [x.get('name') for x in nef_files]
    need(len(set(nef_names)) == 9 and set(nef_names) == set(seen_names), 'nefinfo filenames duplicate or incomplete')

    for nf in nef_files:
        ref = m12_by_name[nf['name']]
        need(nf.get('sha256') == ref['sha256'], f"nefinfo sha256 mismatch for {nf['name']}")
        need(Path(nf.get('path', '')) == Path(ref['path']), f"nefinfo path mismatch for {nf['name']}")
        need(nf.get('source_unchanged') is True, f"nefinfo source_unchanged != True for {nf['name']}")
        vig = nf.get('vignette', {})
        sp7 = nf.get('two_table_spatial', {})
        need(
            vig.get('coefficients') == [0, 0, 0, 0] and vig.get('strength_L') == 0 and vig.get('status') == 2,
            f"unexpected NEFInfo 0x6 fields in {nf['name']}: {vig}",
        )
        need(
            sp7.get('flag_at_5a') == 0 and sp7.get('flag_at_4') == 1,
            f"unexpected NEFInfo 0x7 flags in {nf['name']}: {sp7}",
        )

    # Dark clamp & 4969 tail checks
    for stock_id in ('4854', '4855'):
        sk = a['dark'][stock_id]
        need(sk['matches_0_8_to_56'] == 112 and sk['points'] == 112, f'stock dark baseline mismatch in {stock_id}')
    for dark_id in ('4970', '4971', '4972'):
        dk = a['dark'][dark_id]
        need(
            dk['matches_0_8_to_56'] == 0
            and dk['above56'] == 111
            and dk.get('kernel_definition') == 'nearest_same_color_8_neighbours_per_frozen_baseline112',
            f'dark clamp check failed in {dark_id}',
        )

    tail = a.get('bias_4969_tail', {})
    ta = tail.get('active_area', {})
    ts = tail.get('stored_array', {})
    need(
        ta.get('count_gt_2000') == 189
        and ta.get('saturated_16383_in_frame') == 11
        and ts.get('count_gt_2000') == 190
        and ts.get('saturated_16383_in_frame') == 12,
        f'unexpected Z61_4969.NEF tail statistics: {tail}',
    )

    summary = dict(
        ok=True,
        verified_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        candidate='modified12',
        firmware_path=EXPECTED_FW_REL,
        firmware_sha256_verified=actual_fw_sha,
        firmware_crc16_verified=actual_fw_crc_hex,
        input_report_sha256=dict(
            assessment_v2=sha256_file(assess_path),
            decode_input_v2=dec_in_sha,
            nefinfo_input_v2=nef_in_sha,
            independent_lossless=sha256_file(decode_path),
            nefinfo=sha256_file(nefinfo_path),
        ),
        m12_files_checked=len(m12_rows),
        m12_unique_ids=sorted(seen_ids),
        m12_category_counts=dict(BIAS=3, DARK=3, FLAT=3),
        m12_total_pixels_decoded=sum_pixels,
        m12_cpp_vs_libraw_mismatches=0,
        dark_112_nearest_same_color_clamped={k: a['dark'][k]['matches_0_8_to_56'] for k in ('4970', '4971', '4972')},
        bias_4969_tail_summary=dict(
            active_gt_2000=ta['count_gt_2000'],
            active_saturated=ta['saturated_16383_in_frame'],
            stored_gt_2000=ts['count_gt_2000'],
            stored_saturated=ts['saturated_16383_in_frame'],
        ),
        flat_groups=a['flat_groups'],
        remaining_open_items=[
            'Residual ~35/3 DN candidate-family histogram peaks (0.17163 / 0.25732 cycles/DN; origin undetermined) remain above band median.',
            'Residual ~0.16-0.22 pp local annular ratio structure remains in flat frames.',
            (
                f"Frame numbers 4973, 4974, and 4977 are absent for unrecorded reasons; Z61_4969.NEF has "
                f"{ta['count_gt_2000']} active-area pixels >2000 DN ({ts['count_gt_2000']} in full stored array) "
                f"at dark-frame-correlated coordinates."
            ),
        ],
    )

    if write_outputs:
        snap = out / 'document-and-script-snapshots'
        snap.mkdir(exist_ok=True)
        for rel, dst in [
            ('tools/fw/review_modified12_samples.py', 'review_modified12_samples.py'),
            ('tools/fw/render_modified12_real_report.py', 'render_modified12_real_report.py'),
            ('tools/fw/finalize_modified12_real_audit.py', 'finalize_modified12_real_audit.py'),
            ('tools/fw/test_finalize_modified12_audit.py', 'test_finalize_modified12_audit.py'),
            ('docs/MODIFIED12_REAL_NEF_2026-11-14.md', 'MODIFIED12_REAL_NEF_2026-11-14.md'),
            ('docs/MODIFIED12_PREFLASH_REVIEW_2026-11-14.md', 'MODIFIED12_PREFLASH_REVIEW_2026-11-14.md'),
            ('docs/PROJECT_GOALS.md', 'PROJECT_GOALS.md'),
            ('docs/NEXT_STEPS.md', 'NEXT_STEPS.md'),
            ('README.md', 'README.md'),
        ]:
            src_doc = root / rel
            if src_doc.is_file():
                shutil.copy2(src_doc, snap / dst)
        (out / 'verification.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf8')

    return summary


SNAPSHOT_SPECS = [
    ('tools/fw/review_modified12_samples.py', 'review_modified12_samples.py'),
    ('tools/fw/render_modified12_real_report.py', 'render_modified12_real_report.py'),
    ('tools/fw/finalize_modified12_real_audit.py', 'finalize_modified12_real_audit.py'),
    ('tools/fw/test_finalize_modified12_audit.py', 'test_finalize_modified12_audit.py'),
    ('docs/MODIFIED12_REAL_NEF_2026-11-14.md', 'MODIFIED12_REAL_NEF_2026-11-14.md'),
    ('docs/MODIFIED12_PREFLASH_REVIEW_2026-11-14.md', 'MODIFIED12_PREFLASH_REVIEW_2026-11-14.md'),
    ('docs/PROJECT_GOALS.md', 'PROJECT_GOALS.md'),
    ('docs/NEXT_STEPS.md', 'NEXT_STEPS.md'),
    ('README.md', 'README.md'),
]


def assert_verification_summary_fresh(root: Path = ROOT, out: Path = OUT) -> dict:
    """Recompute validation summary and ensure on-disk verification.json & snapshots match."""
    expected = validate_audit(root=root, out=out, write_outputs=False)
    ver_path = out / 'verification.json'
    need(ver_path.is_file(), 'verification.json must exist before freezing/verifying manifest')
    actual = read_json(ver_path)
    need(isinstance(actual, dict) and isinstance(actual.get('verified_utc'), str) and len(actual['verified_utc']) >= 20, 'invalid verified_utc in verification.json')
    exp_cmp = {k: v for k, v in expected.items() if k != 'verified_utc'}
    act_cmp = {k: v for k, v in actual.items() if k != 'verified_utc'}
    need(act_cmp == exp_cmp, 'verification.json is stale or tampered relative to live audit recomputation')

    snap = out / 'document-and-script-snapshots'
    if snap.is_dir():
        for rel, dst in SNAPSHOT_SPECS:
            src_doc = root / rel
            if src_doc.is_file():
                snap_doc = snap / dst
                need(snap_doc.is_file() and sha256_file(snap_doc) == sha256_file(src_doc), f'snapshot out of date: {dst}')
    return expected


def freeze_manifest(root: Path = ROOT, out: Path = OUT) -> dict:
    """Build evidence-sha256.json after all recorded commands inside `out/commands` have exited."""
    assert_verification_summary_fresh(root=root, out=out)
    evidence = []
    for p in sorted(out.rglob('*'), key=lambda x: x.relative_to(out).as_posix()):
        if p.is_file() and p.name != 'evidence-sha256.json':
            evidence.append(
                dict(
                    path=p.relative_to(root).as_posix(),
                    bytes=p.stat().st_size,
                    sha256=sha256_file(p),
                )
            )
    manifest = dict(
        ok=True,
        frozen_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        count=len(evidence),
        files=evidence,
    )
    (out / 'evidence-sha256.json').write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding='utf8',
    )
    return verify_manifest(root=root, out=out)


def verify_manifest(root: Path = ROOT, out: Path = OUT) -> dict:
    assert_verification_summary_fresh(root=root, out=out)
    manifest_path = out / 'evidence-sha256.json'
    need(manifest_path.is_file(), f'missing {manifest_path}')
    manifest = read_json(manifest_path)
    entries = manifest.get('files', [])
    need(manifest.get('ok') is True and manifest.get('count') == len(entries) and len(entries) > 0, 'invalid manifest header')

    by_rel = {e['path']: e for e in entries}
    need(len(by_rel) == len(entries), 'duplicate paths in evidence-sha256.json')

    actual_files = [
        p.relative_to(root).as_posix()
        for p in sorted(out.rglob('*'), key=lambda x: x.relative_to(out).as_posix())
        if p.is_file() and p.name != 'evidence-sha256.json'
    ]
    need(set(actual_files) == set(by_rel.keys()), 'manifest file set differs from on-disk files under output dir')

    for rel, rec in by_rel.items():
        fp = root / rel
        sz = fp.stat().st_size
        sh = sha256_file(fp)
        need(sz == rec['bytes'] and sh == rec['sha256'], f'manifest mismatch for {rel}: expected {rec["bytes"]}/{rec["sha256"]}, got {sz}/{sh}')

    return dict(ok=True, verified_files=len(entries), mismatches=0)

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--mode', choices=['validate', 'freeze', 'verify'], default='validate')
    args = ap.parse_args()

    if args.mode == 'validate':
        res = validate_audit(ROOT, OUT, write_outputs=True)
        print(json.dumps(dict(ok=res['ok'], mode='validate', total_pixels=res['m12_total_pixels_decoded'])))
    elif args.mode == 'freeze':
        res = freeze_manifest(ROOT, OUT)
        print(json.dumps(dict(ok=res['ok'], mode='freeze', verified_files=res['verified_files'], mismatches=res['mismatches'])))
    elif args.mode == 'verify':
        res = verify_manifest(ROOT, OUT)
        print(json.dumps(dict(ok=res['ok'], mode='verify', verified_files=res['verified_files'], mismatches=res['mismatches'])))


if __name__ == '__main__':
    main()

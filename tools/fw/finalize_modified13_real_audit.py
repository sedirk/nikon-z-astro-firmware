"""Strict coverage/provenance validator and manifest freezer for Modified13 real-NEF audit."""
from pathlib import Path
import argparse
import binascii
import datetime
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/modified13-real-2026-11-14'

EXPECTED_FW_REL = 'outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN'
EXPECTED_FW_SHA256 = '3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749'
EXPECTED_FW_CRC16_HEX = '6b10'

EXPECTED_M13_KINDS = {
    4991: 'BIAS',
    4992: 'BIAS',
    4993: 'BIAS',
    4994: 'FLAT',
    5000: 'FLAT',
    5006: 'FLAT',
    5007: 'DARK',
    5008: 'DARK',
    5009: 'DARK',
}
STORED_PIXELS_PER_FRAME = 6064 * 4040  # 24,498,560
ACTIVE_PIXELS_PER_FRAME = 6048 * 4024  # 24,337,152
TOTAL_M13_STORED_PIXELS = 9 * STORED_PIXELS_PER_FRAME  # 220,487,040


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
    need(fw_path.is_file(), f'missing Modified13 firmware binary: {fw_path}')
    fw_bytes = fw_path.read_bytes()
    need(len(fw_bytes) > 2, 'firmware binary unexpectedly small')
    actual_fw_sha = hashlib.sha256(fw_bytes).hexdigest()
    actual_fw_crc_hex = fw_bytes[-2:].hex()
    need(actual_fw_sha == EXPECTED_FW_SHA256, f'firmware SHA-256 mismatch: {actual_fw_sha}')
    need(
        actual_fw_crc_hex == EXPECTED_FW_CRC16_HEX and binascii.crc_hqx(fw_bytes, 0) == 0,
        f'firmware CRC16 check failed: tail={actual_fw_crc_hex}',
    )

    assess_path = out / 'samples/assessment.json'
    dec_in_path = out / 'samples/decode-input.json'
    nef_in_path = out / 'samples/nefinfo-all-m13-input.json'
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

    m13_rows = [x for x in a.get('files', []) if x.get('group') == 'Modified13']
    need(len(m13_rows) == 9, f'expected 9 Modified13 rows, got {len(m13_rows)}')

    seen_ids = [x.get('id') for x in m13_rows]
    seen_names = [x.get('name') for x in m13_rows]
    seen_sha = [x.get('sha256') for x in m13_rows]
    seen_pix_sha = [x.get('stored_pixels_sha256') for x in m13_rows]

    need(
        len(set(seen_ids)) == 9 and set(seen_ids) == set(EXPECTED_M13_KINDS.keys()),
        f'Modified13 unique ID set mismatch: {seen_ids}',
    )
    need(len(set(seen_names)) == 9, 'duplicate Modified13 file names in assessment.json')
    need(len(set(seen_sha)) == 9, 'duplicate source file SHA-256 across 9 distinct NEFs')
    need(len(set(seen_pix_sha)) == 9, 'duplicate stored_pixels_sha256 across 9 distinct NEFs')

    m13_by_name = {}
    for row in m13_rows:
        fid = row['id']
        expected_name = f'Z61_{fid}.NEF'
        need(row['name'] == expected_name, f"id/name mismatch: {fid} vs {row['name']}")
        need(row.get('kind') == EXPECTED_M13_KINDS[fid], f"unexpected kind for {expected_name}: {row.get('kind')}")
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
        m13_by_name[row['name']] = row

    # Input manifest provenance binding against assessment.json
    dec_in_sha = sha256_file(dec_in_path)
    nef_in_sha = sha256_file(nef_in_path)
    for manifest_label, manifest_obj in (
        ('decode-input.json', dec_in),
        ('nefinfo-all-m13-input.json', nef_in),
    ):
        m_files = manifest_obj.get('files', [])
        need([x.get('name') for x in m_files] == seen_names, f'{manifest_label} file list mismatch')
        for item, ref in zip(m_files, m13_rows):
            need(item.get('id') == ref['id'] and item.get('kind') == ref['kind'] and item.get('group') == 'Modified13', f'{manifest_label} id/kind/group mismatch for {ref["name"]}')
            need(Path(item.get('path', '')) == Path(ref['path']), f'{manifest_label} path mismatch for {ref["name"]}')
            need(item.get('sha256') == ref['sha256'], f'{manifest_label} sha256 mismatch for {ref["name"]}')
            need(item.get('stored_pixels_sha256') == ref['stored_pixels_sha256'], f'{manifest_label} stored_pixels_sha256 mismatch for {ref["name"]}')
        need(manifest_obj == dict(files=m13_rows), f'{manifest_label} payload diverges from assessment Modified13 rows')

    # Cross-report checks: independent C++ vs LibRaw decode
    need(d.get('ok') is True, 'decode result ok != True')
    need(d.get('audit_sha256') == dec_in_sha, 'decode result audit_sha256 != sha256(decode-input.json)')
    dec_files = d.get('files', [])
    need(len(dec_files) == 9, f'expected 9 files in decode result, got {len(dec_files)}')
    dec_names = [x.get('name') for x in dec_files]
    need(len(set(dec_names)) == 9 and set(dec_names) == set(seen_names), 'decode result filenames duplicate or incomplete')

    sum_pixels = 0
    for df in dec_files:
        ref = m13_by_name[df['name']]
        need(df.get('source_sha256') == ref['sha256'], f"decode source_sha256 mismatch for {df['name']}")
        need(df.get('pixels_sha256') == ref['stored_pixels_sha256'], f"decode pixels_sha256 mismatch for {df['name']}")
        need(df.get('pixels') == STORED_PIXELS_PER_FRAME, f"decode per-file pixels != {STORED_PIXELS_PER_FRAME} for {df['name']}")
        need(df.get('mismatches') == 0 and df.get('returncode') == 0, f"decode mismatch/failure in {df['name']}")
        sum_pixels += int(df['pixels'])
    need(
        sum_pixels == TOTAL_M13_STORED_PIXELS and d.get('total_pixels') == TOTAL_M13_STORED_PIXELS,
        f'decode total_pixels mismatch: sum={sum_pixels}, header={d.get("total_pixels")}',
    )

    # Cross-report checks: NEFInfo 0x6 / 0x7
    need(n.get('ok') is True, 'nefinfo result ok != True')
    need(n.get('audit_sha256') == nef_in_sha, 'nefinfo result audit_sha256 != sha256(nefinfo-all-m13-input.json)')
    nef_files = n.get('files', [])
    need(len(nef_files) == 9, f'expected 9 files in nefinfo result, got {len(nef_files)}')
    nef_names = [x.get('name') for x in nef_files]
    need(len(set(nef_names)) == 9 and set(nef_names) == set(seen_names), 'nefinfo filenames duplicate or incomplete')

    for nf in nef_files:
        ref = m13_by_name[nf['name']]
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

    # Dark clamp checks (112 points on Modified13)
    for dark_id in ('5007', '5008', '5009'):
        dk = a['dark'][dark_id]
        need(
            dk['matches_0_8_to_56'] == 0 and dk['exact_neighbor_max'] == 0 and dk['above56'] == 112,
            f"hot-pixel suppression detected in Modified13 {dark_id}: {dk}",
        )

    # Flat group metrics
    fg_m13 = a['flat_groups']['Modified13']
    need(fg_m13['broad_ptp_pp'][0] < 1.30, f"Modified13 broad R ptp not reduced: {fg_m13['broad_ptp_pp'][0]}")
    need(fg_m13['hp6_ptp_pp'][0] < 0.20, f"Modified13 hp6 R ptp not reduced: {fg_m13['hp6_ptp_pp'][0]}")

    manifest_payload = {
        'ok': True,
        'scope': 'Modified13 Real-NEF Final Production Convergence Audit',
        'audit_timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'firmware': {
            'relative_path': EXPECTED_FW_REL,
            'sha256': EXPECTED_FW_SHA256,
            'crc16_hqx': EXPECTED_FW_CRC16_HEX,
        },
        'files': m13_rows,
        'summary': {
            'stored_pixels_verified': TOTAL_M13_STORED_PIXELS,
            'cpp_libraw_mismatches': 0,
            'hot_pixel_clamp_hits': 0,
            'broad_r_ptp_pp': fg_m13['broad_ptp_pp'][0],
            'hp6_r_ptp_pp': fg_m13['hp6_ptp_pp'][0],
            'mean_center_rg1': fg_m13['mean_center_rg1'],
            'mean_center_bg1': fg_m13['mean_center_bg1'],
        }
    }

    if write_outputs:
        (out / 'manifest.json').write_text(json.dumps(manifest_payload, indent=2), encoding='utf8')
        (out / 'verification.json').write_text(json.dumps({'status': 'PASS', 'timestamp': manifest_payload['audit_timestamp_utc']}, indent=2), encoding='utf8')

        # Freeze SHA-256 for all artifacts in out
        ev_manifest = {}
        for p in sorted(out.rglob('*')):
            if p.is_file() and p.name != 'evidence-sha256.json':
                ev_manifest[str(p.relative_to(out)).replace('\\', '/')] = sha256_file(p)
        (out / 'evidence-sha256.json').write_text(json.dumps(ev_manifest, indent=2), encoding='utf8')

    print(f"PASS: Modified13 real audit verified successfully! 9 NEFs, {TOTAL_M13_STORED_PIXELS} pixels, 0 mismatches, 0/112 dark clamp hits.")
    return manifest_payload


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, default=OUT)
    args = ap.parse_args()
    validate_audit(ROOT, args.output)


if __name__ == '__main__':
    main()

"""Adversarial negative self-tests for finalize_modified12_real_audit.py."""
from pathlib import Path
import copy
import json
import os
import shutil
import tempfile

from finalize_modified12_real_audit import (
    EXPECTED_FW_REL,
    OUT,
    ROOT,
    freeze_manifest,
    validate_audit,
    verify_manifest,
)


def make_fixture(tmp: Path) -> tuple[Path, Path]:
    """Create a lightweight isolated fixture mirroring required audit JSONs and firmware BIN."""
    test_root = tmp / 'root'
    test_out = test_root / 'analysis/modified12-real-2026-11-14'
    (test_out / 'samples-v2').mkdir(parents=True)
    (test_out / 'independent-lossless').mkdir(parents=True)
    (test_out / 'nefinfo').mkdir(parents=True)

    fw_dst = test_root / EXPECTED_FW_REL
    fw_dst.parent.mkdir(parents=True)
    shutil.copy2(ROOT / EXPECTED_FW_REL, fw_dst)

    for rel in (
        'samples-v2/assessment.json',
        'samples-v2/decode-input.json',
        'samples-v2/nefinfo-all-m12-input.json',
        'independent-lossless/result.json',
        'nefinfo/result.json',
    ):
        shutil.copy2(OUT / rel, test_out / rel)

    return test_root, test_out


def expect_reject(label: str, fn) -> str:
    try:
        fn()
    except ValueError as exc:
        return str(exc)
    raise AssertionError(f'Negative case was NOT rejected: {label}')


def main() -> None:
    scratch_base = Path(os.environ.get('PI_SCRATCH_DIR', tempfile.gettempdir()))
    results = []

    with tempfile.TemporaryDirectory(dir=scratch_base, prefix='m12_val_test_') as td:
        tmp = Path(td)

        # Positive baseline
        r0, o0 = make_fixture(tmp / 'case0_positive')
        s0 = validate_audit(r0, o0, write_outputs=True)
        assert s0['ok'] is True
        f0 = freeze_manifest(r0, o0)
        assert f0['ok'] is True and f0['mismatches'] == 0
        results.append(dict(case='positive_baseline_and_freeze', rejected=False, verified_files=f0['verified_files']))

        # Negative 1: 9 Modified12 entries in assessment.json all repeat the first entry
        r1, o1 = make_fixture(tmp / 'case1_dup_assessment')
        a1 = json.loads((o1 / 'samples-v2/assessment.json').read_text(encoding='utf8'))
        first_m12 = next(x for x in a1['files'] if x['group'] == 'Modified12')
        a1['files'] = [x for x in a1['files'] if x['group'] != 'Modified12'] + [copy.deepcopy(first_m12) for _ in range(9)]
        (o1 / 'samples-v2/assessment.json').write_text(json.dumps(a1), encoding='utf8')
        msg1 = expect_reject('case1_dup_assessment', lambda: validate_audit(r1, o1, write_outputs=False))
        results.append(dict(case='case1_dup_assessment_9x_first', rejected=True, error=msg1))

        # Negative 2a..2d: decode report wrong audit_sha256, filename, source_sha256, pixels_sha256
        for sub, mut in [
            ('audit_sha256', lambda d: d.update(audit_sha256='0' * 64)),
            ('filename', lambda d: d['files'][0].update(name='Z61_9999.NEF')),
            ('source_sha256', lambda d: d['files'][0].update(source_sha256='f' * 64)),
            ('pixels_sha256', lambda d: d['files'][0].update(pixels_sha256='a' * 64)),
        ]:
            rx, ox = make_fixture(tmp / f'case2_{sub}')
            dx = json.loads((ox / 'independent-lossless/result.json').read_text(encoding='utf8'))
            mut(dx)
            (ox / 'independent-lossless/result.json').write_text(json.dumps(dx), encoding='utf8')
            msgx = expect_reject(f'case2_{sub}', lambda: validate_audit(rx, ox, write_outputs=False))
            results.append(dict(case=f'case2_decode_wrong_{sub}', rejected=True, error=msgx))

        # Negative 3: NEFInfo report repeats first file 9 times
        r3, o3 = make_fixture(tmp / 'case3_dup_nefinfo')
        n3 = json.loads((o3 / 'nefinfo/result.json').read_text(encoding='utf8'))
        n3['files'] = [copy.deepcopy(n3['files'][0]) for _ in range(9)]
        (o3 / 'nefinfo/result.json').write_text(json.dumps(n3), encoding='utf8')
        msg3 = expect_reject('case3_dup_nefinfo', lambda: validate_audit(r3, o3, write_outputs=False))
        results.append(dict(case='case3_dup_nefinfo_9x_first', rejected=True, error=msg3))

        # Negative 4: per-file pixels = 1 while keeping top-level total_pixels = 220487040
        r4, o4 = make_fixture(tmp / 'case4_fake_per_file_pixels')
        d4 = json.loads((o4 / 'independent-lossless/result.json').read_text(encoding='utf8'))
        for item in d4['files']:
            item['pixels'] = 1
        d4['total_pixels'] = 220487040
        (o4 / 'independent-lossless/result.json').write_text(json.dumps(d4), encoding='utf8')
        msg4 = expect_reject('case4_fake_per_file_pixels', lambda: validate_audit(r4, o4, write_outputs=False))
        results.append(dict(case='case4_per_file_pixels_1_with_valid_header_total', rejected=True, error=msg4))

        # Negative 5: cases 1+2+3+4 combined simultaneously
        r5, o5 = make_fixture(tmp / 'case5_all_combined')
        (o5 / 'samples-v2/assessment.json').write_text(json.dumps(a1), encoding='utf8')
        d5 = copy.deepcopy(d4)
        d5['audit_sha256'] = '1' * 64
        d5['files'][0]['source_sha256'] = '2' * 64
        d5['files'][0]['pixels_sha256'] = '3' * 64
        (o5 / 'independent-lossless/result.json').write_text(json.dumps(d5), encoding='utf8')
        (o5 / 'nefinfo/result.json').write_text(json.dumps(n3), encoding='utf8')
        msg5 = expect_reject('case5_all_combined', lambda: validate_audit(r5, o5, write_outputs=False))
        results.append(dict(case='case5_all_four_corruptions_combined', rejected=True, error=msg5))

        # Negative 6: missing firmware binary in root
        r6, o6 = make_fixture(tmp / 'case6_missing_fw')
        (r6 / EXPECTED_FW_REL).unlink()
        msg6 = expect_reject('case6_missing_fw', lambda: validate_audit(r6, o6, write_outputs=False))
        results.append(dict(case='case6_missing_firmware_bin', rejected=True, error=msg6))

        # Negative 7: input manifest provenance mismatch (decode-input & nefinfo-all-m12-input with updated audit_sha256)
        import hashlib
        for m_rel, res_rel in [
            ('samples-v2/decode-input.json', 'independent-lossless/result.json'),
            ('samples-v2/nefinfo-all-m12-input.json', 'nefinfo/result.json'),
        ]:
            for field_name, bad_val in [
                ('path', r'D:\nonexistent\Z61_4967.NEF'),
                ('sha256', 'e' * 64),
                ('stored_pixels_sha256', 'd' * 64),
            ]:
                rm, om = make_fixture(tmp / f"case7_{Path(m_rel).stem}_{field_name}")
                m_obj = json.loads((om / m_rel).read_text(encoding='utf8'))
                m_obj['files'][0][field_name] = bad_val
                m_bytes = json.dumps(m_obj).encode('utf8')
                (om / m_rel).write_bytes(m_bytes)
                r_obj = json.loads((om / res_rel).read_text(encoding='utf8'))
                r_obj['audit_sha256'] = hashlib.sha256(m_bytes).hexdigest()
                (om / res_rel).write_text(json.dumps(r_obj), encoding='utf8')
                msgm = expect_reject(f'{m_rel}:{field_name}', lambda: validate_audit(rm, om, write_outputs=False))
                results.append(dict(case=f'case7_{Path(m_rel).stem}_wrong_{field_name}', rejected=True, error=msgm))

        # Negative 8: stale/tampered verification.json rejected by both freeze_manifest and verify_manifest
        r8, o8 = make_fixture(tmp / 'case8_stale_verification')
        validate_audit(r8, o8, write_outputs=True)
        freeze_manifest(r8, o8)
        v8 = json.loads((o8 / 'verification.json').read_text(encoding='utf8'))
        v8['m12_files_checked'] = 1
        v8['m12_total_pixels_decoded'] = 1
        v8['firmware_sha256_verified'] = '0' * 64
        (o8 / 'verification.json').write_text(json.dumps(v8), encoding='utf8')
        msg8a = expect_reject('case8_freeze_stale_ver', lambda: freeze_manifest(r8, o8))
        msg8b = expect_reject('case8_verify_stale_ver', lambda: verify_manifest(r8, o8))
        results.append(dict(case='case8_stale_verification_rejected_on_freeze', rejected=True, error=msg8a))
        results.append(dict(case='case8_stale_verification_rejected_on_verify', rejected=True, error=msg8b))

        # Negative 9: post-freeze byte change (e.g. extra whitespace in metadata or log) caught by verify_manifest
        (o0 / 'extra_log.txt').write_text('ok', encoding='utf8')
        freeze_manifest(r0, o0)
        (o0 / 'extra_log.txt').write_text('NO', encoding='utf8')  # same length (2 bytes) content tamper!
        msg9 = expect_reject('case9_manifest_same_len_tamper', lambda: verify_manifest(r0, o0))
        results.append(dict(case='case9_post_freeze_same_length_tamper_detected', rejected=True, error=msg9))

    print(json.dumps(dict(ok=True, cases_tested=len(results), results=results), indent=2))


if __name__ == '__main__':
    main()

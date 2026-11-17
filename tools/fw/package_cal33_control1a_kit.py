"""Gate and package exact modified7 bytes for a controlled physical experiment."""
from pathlib import Path
import argparse, datetime, json, os, re, shutil, struct
from verify_cal33_control1a_kit import DIGESTS, PATHS, BEFORE, AFTER, read_module, need, sha, check_kit
from probe_cal33_control1a_updater import ROOT, ROUND, FILES

def read(path):
    return json.loads(path.read_text(encoding='utf8'))

def record(path, root=ROOT):
    return dict(path=path.relative_to(root).as_posix(), bytes=path.stat().st_size, sha256=sha(path.read_bytes()))

def write(path, value):
    need(not path.exists(), 'Output already exists: ' + str(path))
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf8')

def assess():
    names = ['native-static-cal33-lab/result.json', 'native-cal33-abi/result.json',
        'independent-byte-review/result.json', 'native-updater/result.json',
        'qemu-m4-real-records/result.json', 'qemu-lab-real-records/result.json']
    results = [read(ROUND / name) for name in names]
    need(all(r['ok'] for r in results), 'An offline review failed')
    native, abi, audit, update, base, test = results
    need(native['lab_sha256'] == abi['lab_sha256'] == audit['sha256'] == test['firmware_sha256'] == DIGESTS['test'], 'Candidate review mismatch')
    need(len(native['rows']) == 80 and len(native['comparisons']) == 40, 'Native case count')
    need(len(native['restore_checks']) == 36 and len(native['error_checks']) == 26, 'Restoration or error case count')
    need(all(r['one_cache_byte_only'] and r['one_register_only'] and r['id35_and_packet_context_unchanged'] for r in native['comparisons']), 'Native control isolation')
    need(len(abi['rows']) == 64 and all(r['callee_saved'] and r['stack_preserved'] for r in abi['rows']), 'ABI cases')
    need(audit['changed_code_bytes'] == 72 and audit['changed_crc_bytes'] == 2 and audit['inherited_patch_count'] == 10, 'Byte audit')
    need(audit['exact_restore_to_modified4'] and audit['call_order_preserved'], 'Original flow audit')
    need(len(update['file_checks']) == 8 and len(update['scheduler']) == 5 and not update['physical_flash'], 'Updater scope')
    positive = update['file_checks'][:5]
    expected = [('modified4', 'test'), ('stock', 'test'), ('test', 'modified4'), ('test', 'modified1'), ('test', 'stock')]
    for row, pair in zip(positive, expected):
        need((row['running_rom'], row['target']) == pair, 'Update pair')
        need(row['loaded_buffer_sha256'] == DIGESTS[row['target']], 'Update bytes')
        need(row['discovery_return'] == row['integrity_return'] == row['component_precheck_return'] == 0, 'Native update rejection')
    need([r['completion'] for r in update['scheduler']] == [[0], [0], [0], [1], [1]], 'Scheduler outcome')
    need(all(r['prefix_preserved'] and r['tail_canary_preserved'] for r in update['scheduler']), 'Flash region guards')
    need(base['firmware_sha256'] == DIGESTS['modified4'], 'QEMU baseline identity')
    need(base['model_sources'] == test['model_sources'] and base['controller_sources'] == test['controller_sources'], 'QEMU model drift')
    need(base['overlays'] == test['overlays'], 'QEMU calibration differs')
    active = []
    for label, r, value in [('modified4', base, 1), ('modified7', test, 0)]:
        need(r['boot_reached_dispatch'] and r['original_id35_transfer_preserved'] and r['firmware_unchanged'], 'QEMU flow')
        need(not r['hardware_formula_added'] and not r['extra_completion_added'] and not r['real_nef'], 'QEMU claim boundary')
        need(r['final_state']['error'] is None and not r['final_state']['capture']['capture_failed'], 'QEMU final state')
        rows = [e for e in r['events'] if e['phase'].startswith('static')]
        uploads = [e for e in rows if e['event'] == 'table33_control_upload' and struct.unpack_from('<I', bytes.fromhex(e['context']), 0x84)[0] == 1]
        need(len(uploads) == 1 and bytes.fromhex(uploads[0]['uploaded_control'])[5] == value, 'Static upload value')
        for event in ('static_builder', 'id35_descriptor', 'raw_destination', 'temporary_exit'):
            need(any(e['event'] == event for e in rows), 'Missing event: ' + event)
        active.append(dict(variant=label, static_control=value, events=[e['event'] for e in rows],
            screenshot_sha256=sha((ROUND / ('qemu-m4-real-records' if label == 'modified4' else 'qemu-lab-real-records') / 'after.png').read_bytes())))
    return dict(ok=True, verdict='OFFLINE_REVIEW_PASSED_FOR_CONTROLLED_SINGLE_VARIABLE_TEST',
        candidate='modified7', candidate_sha256=DIGESTS['test'], native_pairs=40, native_executions=80,
        non_target_restore_cases=36, error_cases=26, abi_cases=64, update_file_cases=8, flash_model_cases=5,
        qemu_runs=active, qemu_real_resource_ranges=base['overlays'], qemu_model_sources=base['model_sources'],
        qemu_controller_sources=base['controller_sources'],
        visual_review='Both after.png inspected: same synthetic color bars and camera UI. Confirms visible VM output only.',
        limitations=['Hardware operation of control1a is unconfirmed.', 'QEMU overlays only three real resource ranges; other resources/OS/hardware remain fixtures.',
            'RAW-destination event is before this processing stage; it is not evidence of completed corrected RAW or saved NEF.',
            'Flash validation uses native code with RAM-only low-level adapters; physical power-loss or mechanical-shutter behavior is not reproduced.',
            'modified5 real Err cause is not fully resolved. Its ID35 override is absent from modified7.',
            'Latest real dark regression is modified3; modified4 and modified7 still need matched new dark samples.'],
        physical_modified7_test=False, ring_removal_verified=False,
        evidence=[record(ROUND / name) for name in names])

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    out = p.parse_args().output.resolve()
    need(out.is_relative_to(ROOT / 'outputs'), 'Output outside project outputs')
    review = assess()
    manifest = read(ROUND / 'static-cal33-lab/manifest.json')
    need(bytes.fromhex(manifest['before']) == BEFORE and bytes.fromhex(manifest['after']) == AFTER, 'Hard-coded function mismatch')
    out.mkdir(parents=True, exist_ok=False)
    for mode, (source, digest) in FILES.items():
        need(digest == DIGESTS[mode], 'Source identity mismatch')
        target = out / PATHS[mode]
        target.parent.mkdir()
        target.write_bytes(read_module(ROOT / source, mode))
    for source, dest in (
        ('docs/Z6_CAL33_INSTALL_2026-11-12.txt', 'START_HERE.txt'),
        ('docs/Z6_CAL33_FLAT_COMPARE_2026-11-12.txt', 'FLAT_COMPARE.txt'),
        ('docs/RAW_SPATIAL_CONTROLS_2026-11-12.md', 'REVIEW.md'),
        ('tools/fw/verify_cal33_control1a_kit.py', 'verify.py'),
        ('outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json', 'baseline112.json'),
        ('docs/Z6_CAL33_SHOT_LOG_2026-11-12.txt', 'SHOT_LOG_TEMPLATE.txt')):
        if dest == 'REVIEW.md':
            original = ROOT / source
            content = original.read_text(encoding='utf8')
            def relocate_link(match):
                link = match.group(1)
                if link.startswith(('https:', 'http:')):
                    return match.group(0)
                target = (original.parent / link).resolve()
                return '](' + Path(os.path.relpath(target, out)).as_posix() + ')'
            (out / dest).write_text(re.sub(r'\]\(([^)]+)\)', relocate_link, content), encoding='utf8')
        else:
            shutil.copyfile(ROOT / source, out / dest)
    recipe = dict(manifest, historical_status=manifest['status'], status=review['verdict'],
        delivered_as='modified7', physical_test=False, inherited_patch_count=10, evidence=review['evidence'])
    write(out / 'patch-recipe.json', recipe)
    write(out / 'manifest.json', dict(schema=6, created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        model='First-generation Nikon Z6', version='C3.80', candidate='modified7', verdict=review['verdict'],
        module_sha256=DIGESTS, physical_modified7_test=False, ring_removal_verified=False,
        scope='Static builder only, one CAL33 cached byte. Not NEF-exclusive. Existing modified1-4 patches inherited.',
        evidence=review['evidence'], files=[record(f, out) for f in sorted(out.rglob('*')) if f.is_file()]))
    checked = check_kit(out)
    write(ROUND / 'assessment.json', review)
    write(ROUND / 'package-result.json', dict(ok=True, output=out.relative_to(ROOT).as_posix(), **checked,
        files=[record(f) for f in sorted(out.rglob('*')) if f.is_file()]))
    print(json.dumps(dict(ok=True, output=str(out), **checked), indent=2))

if __name__ == '__main__':
    main()

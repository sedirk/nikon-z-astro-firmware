"""Verify preservation, publish progress and freeze the modified7 offline research round."""
from pathlib import Path
import ast, datetime, hashlib, json, re, subprocess, sys
from finalize_calibration_access import FW
from finalize_modified5_recovery import PRIOR as OLD_PRIOR
from verify_modified5_recovery import check_kit as check_recovery
from verify_cal33_control1a_kit import check_kit, DIGESTS, PATHS, REVOKED
from package_cal33_control1a_kit import assess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/raw-spatial-controls-2026-11-12'
KIT = ROOT / 'outputs/Z6-C380-cal33-control1a-reviewed-2026-11-12'
REPORT = ROOT / 'docs/RAW_SPATIAL_CONTROLS_2026-11-12.md'
DOCS = ['README.md', 'docs/PROJECT_GOALS.md', 'docs/NEXT_STEPS.md',
    'docs/RAW_SPATIAL_CONTROLS_2026-11-12.md', 'docs/Z6_CAL33_INSTALL_2026-11-12.txt',
    'docs/Z6_CAL33_FLAT_COMPARE_2026-11-12.txt', 'docs/Z6_CAL33_SHOT_LOG_2026-11-12.txt']
SCRIPTS = ['prepare_spatial_controls_round.py', 'scan_spatial_control_context.py',
    'prepare_cal33_static_lab.py', 'probe_cal33_static_lab.py', 'probe_cal33_abi.py',
    'qemu_cal33_static_probe.py', 'review_cal33_static_lab.py', 'probe_cal33_updater.py',
    'package_cal33_test.py', 'verify_cal33_control1a_kit.py', 'test_cal33_test_kit.py',
    'finalize_spatial_controls.py', 'inspect_native.py', 'record_research_command.py',
    'probe_raw_candidates.py', 'probe_eg_update_route.py', 'probe_preflash_review.py',
    'verify_front_preflash_kit.py', 'probe_front_extra_tables.py', 'probe_real_calibration_front.py']
FAILURES = {'10-independent-byte-review': (1,
    'Direct-branch scan hit a compressed PNG IDAT byte pattern; full PNG chunk CRC validation classified it as data. Failed review/source preserved; command12 passed.')}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))

def write(path, value):
    assert not path.exists(), path
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf8')

def record(path):
    return dict(path=path.relative_to(ROOT).as_posix(), bytes=path.stat().st_size, sha256=sha(path.read_bytes()))

def progress():
    assert read(OUT / 'assessment.json')['ok'] and read(OUT / 'verifier-tests/result.json')['ok']
    changes = []
    for name in DOCS[:3]:
        path = ROOT / name
        old = path.read_bytes()
        assert old == (OUT / 'progress-before' / name.replace('/', '-')).read_bytes(), 'Concurrent document edit: ' + name
        title, body = old.decode('utf8').replace('\r\n', '\n').split('\n', 1)
        prefix = 'docs/' if name == 'README.md' else ''
        output_prefix = '' if name == 'README.md' else '../'
        text = (f'\n\n**2026-11-12 最新：modified7 静态 CAL33 第一控制单变量测试包已生成并通过离线审查。** '
            f'使用本机真实标定副本，静态构建中只将记录+18对应控制置零；40对原生执行中507项寄存器写入仅20068700变化。'
            f'ID35门控、原始传输及等待/完成/错误路径保持，modified4十处既有补丁全部继承。'
            f'36项恢复、26项错误、64项ABI、8项更新文件、5项擦写模型检查及两份QEMU对照通过。'
            f'[报告]({prefix}RAW_SPATIAL_CONTROLS_2026-11-12.md)、'
            f'[测试包入口]({output_prefix}outputs/Z6-C380-cal33-control1a-reviewed-2026-11-12/START_HERE.txt)。\n\n'
            f'**实机状态：机身已恢复；用户现拿去充电，本轮全部继续离线。modified5保持撤回；modified7尚未实机测试。** '
            f'候选是检验前端控制和彩圈因果关系的实验文件；控制的像素数学含义及消圈效果待新NEF。'
            f'最后有新暗场回归的版本仍为modified3，modified7保留暗场补丁字节并安排再次实拍验收。'
            f'三项菜单当前均关闭；待电量恢复后先拍固定布置的modified4新A组，再候选B组。'
            f'[拍摄步骤]({prefix}Z6_CAL33_FLAT_COMPARE_2026-11-12.txt)。\n')
        if name == 'docs/NEXT_STEPS.md':
            text += ('\n当前执行顺序：\n\n'
                '1. 用户充电期间完成本轮冻结；不要求连接机身，不自动刷卡/刷机。\n'
                '2. 在实际恢复版本确认正常拍摄；如为modified4，三项菜单关闭、固定布置下拍新的A平场及暗场。\n'
                '3. 校验01_TEST_MODIFIED7文件后，先一张普通NEF验收快门/保存/回放，再拍匹配B平场与暗场；Err复发即停止重复触发并回退modified4。\n'
                '4. 对比原始CFA的R/G、B/G细环、宽颜色趋势及PWM污染；另复核112点和31邻域关系，分开报告彩圈与暗场结果。\n'
                '5. 有效果时优先回退复测建立可逆因果；无效果则记录当前控制影响域，再恢复本变量后独立研究+1a控制，不盲目累加补丁。\n')
        path.write_bytes((title + text + '\n以下为各轮历史记录；最新交付及当前实机状态以上述更新为准。\n' + body).encode('utf8'))
        changes.append(dict(path=name, before_sha256=sha(old), after_sha256=sha(path.read_bytes())))
    write(OUT / 'progress-changes.json', dict(changes=changes))
    write(OUT / 'candidate-status.json', dict(
        candidate='modified7', status='OFFLINE_REVIEW_PASSED_AWAITING_CONTROLLED_PHYSICAL_TEST',
        sha256=DIGESTS['test'], parent_sha256=DIGESTS['modified4'],
        scope='Static builder0x1017d7b6: CAL33 header+1a cache0xc29a3749 cleared; control0x20068704. Not NEF-exclusive.',
        inherited_patches=10, changed_code_bytes=72, changed_crc_bytes=2,
        id35_transfer_preserved=True, original_resources_preserved=True,
        physical_test=False, ring_removal_verified=False, full_dark_current_restoration_verified=False,
        last_real_dark_regression='modified3', modified5='Recalled after mechanical-shutter Err; user has recovered.',
        camera_availability='User reports battery depleted and camera taken for charging; continue offline.',
        camera_writes_or_capture_this_round=False, card_prepared_this_round=False,
        new_baseline='Confirmed actual restored firmware (prefer exact modified4), three correction menusOFF, fixed setup/focus/light',
        next='Matched A/B flats at three signal levels, three5sISO1600 darks and threebias, first normalNEF smoke test.'))
    write(OUT / 'external-source-notes.json', dict(
        basis='Pinned original firmware; exact real CAL38/ID35 backups; native execution and logged QEMU traces.',
        web_scope='Targeted queries for exact control addresses and WonderLantern shading did not yield relevant primary hardware semantics. No web result used as patch evidence.',
        public_absence_claim=False,
        operational_notes=['PowerShell rg glob tools/fw/qemu*.py was unsupported; later file search used rg --files.',
            'An attempted WSL gdb_rsp.py lookup found no file; the applicable module is rsp.py. No conclusion based on missing guessed file.']))
    print(json.dumps(dict(ok=True, updated_documents=len(changes), physical_test=False)))

def verify():
    assert not (OUT / 'verification.json').exists()
    for path, digest in FW.items():
        assert sha((ROOT / path).read_bytes()) == digest, path
    recalled = ROOT / 'analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED'
    assert sha(recalled.read_bytes()) == REVOKED
    recovery = check_recovery(ROOT / 'outputs/Z6-C380-recovery-from-modified5-2026-11-10')
    prior = []
    for name in [*OLD_PRIOR, 'modified5-failure-2026-11-10', 'raw-front-completion-2026-11-10', 'raw-calibration-access-2026-11-10']:
        path = ROOT / 'analysis' / name / 'evidence-index.json'
        index = read(path)
        for row in index['files']:
            actual = ROOT / row['path']
            assert actual.stat().st_size == row['bytes'] and sha(actual.read_bytes()) == row['sha256'], row['path']
        prior.append(dict(folder=name, files=len(index['files']), index_sha256=sha(path.read_bytes())))
    photos = read(ROOT / 'analysis/modified4-real-2026-11-09/verification.json')['source_hashes']
    for path, digest in photos.items():
        assert sha(Path(path).read_bytes()) == digest, path
    for path, digest in read(OUT / 'inputs.json')['inputs'].items():
        assert sha((ROOT / path).read_bytes()) == digest, path
    review = assess()
    assert review == read(OUT / 'assessment.json')
    kit = check_kit(KIT)
    for row in read(OUT / 'package-result.json')['files']:
        assert sha((ROOT / row['path']).read_bytes()) == row['sha256'], row['path']
    tests = read(OUT / 'verifier-tests/result.json')
    assert tests['ok'] and not tests['physical_card_or_camera_touched']
    assert len(tests['rows']) == 20, len(tests['rows'])
    for name in SCRIPTS:
        path = ROOT / 'tools/fw' / name
        ast.parse(path.read_text(encoding='utf8'))
    for row in read(OUT / 'progress-changes.json')['changes']:
        assert sha((ROOT / row['path']).read_bytes()) == row['after_sha256']
    for doc in (REPORT, KIT / 'REVIEW.md'):
        for link in re.findall(r'\]\(([^)]+)\)', doc.read_text(encoding='utf8')):
            if link.startswith(('https:', 'http:')):
                continue
            target = (doc.parent / link).resolve()
            if target not in (OUT / 'verification.json', OUT / 'evidence-index.json'):
                assert target.exists(), (doc, link)
    commands = []
    for path in sorted((OUT / 'commands').glob('*/command.json')):
        row = read(path)
        if 'exit_code' not in row:
            continue  # the current recorded verifier ends after verification.json is written
        code, reason = FAILURES.get(path.parent.name, (0, None))
        assert row['exit_code'] == code, path
        commands.append(dict(name=path.parent.name, exit_code=row['exit_code'], classification=reason))
    diff = subprocess.run(['git', 'diff', '--check'], cwd=ROOT, capture_output=True)
    (OUT / 'git-diff-check.txt').write_bytes(diff.stdout + diff.stderr)
    assert diff.returncode == 0
    (OUT / 'git-status-after.txt').write_bytes(subprocess.run(['git', 'status', '--short'], cwd=ROOT, capture_output=True, check=True).stdout)
    write(OUT / 'verification.json', dict(ok=True, preserved_firmware=FW, recalled_sha256=REVOKED,
        recovery_kit=recovery, delivery_kit=kit, delivery_manifest=record(KIT / 'manifest.json'),
        prior_frozen=prior, prior_frozen_file_count=sum(r['files'] for r in prior),
        photo_source_hashes=photos, verifier_cases=len(tests['rows']), review=review,
        commands=commands, failures_preserved=FAILURES, physical_flash_or_capture=False, git_commit=False))
    print(json.dumps(dict(ok=True, prior_frozen_files=sum(r['files'] for r in prior), photos=len(photos), verifier_cases=len(tests['rows']))))

def freeze():
    assert read(OUT / 'verification.json')['ok'] and not (OUT / 'evidence-index.json').exists()
    (OUT / 'script-snapshots').mkdir(exist_ok=False)
    (OUT / 'document-snapshots').mkdir(exist_ok=False)
    for name in SCRIPTS:
        (OUT / 'script-snapshots' / name).write_bytes((ROOT / 'tools/fw' / name).read_bytes())
    for name in DOCS:
        (OUT / 'document-snapshots' / name.replace('/', '-')).write_bytes((ROOT / name).read_bytes())
    commands = []
    for path in sorted((OUT / 'commands').glob('*/command.json')):
        row = read(path)
        assert row.get('exit_code') == FAILURES.get(path.parent.name, (0, ''))[0], path
        commands.append(dict(name=path.parent.name, **row))
    files = [record(path) for path in sorted(OUT.rglob('*')) if path.is_file()]
    write(OUT / 'evidence-index.json', dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        freeze_argv=sys.argv, files=files, commands=commands,
        status='Modified6 exact single-control test kit; offline native/QEMU/update review passed. No physical flash or NEF this round; user charging camera.'))
    print(json.dumps(dict(ok=True, frozen_files=len(files), commands=len(commands), classified_failures=len(FAILURES))))

if __name__ == '__main__':
    assert len(sys.argv) == 2 and sys.argv[1] in ('progress', 'verify', 'freeze')
    globals()[sys.argv[1]]()

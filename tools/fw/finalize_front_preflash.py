"""Archive and freeze modified4 controlled-test review without touching samples/cards."""
from pathlib import Path
import ast, datetime, hashlib, json, shutil, subprocess, sys, zipfile
from review_front_preflash import ROOT, ROUND, SOURCES
from verify_front_preflash_kit import DIGESTS, need, check_kit, read_module

KIT = ROOT/'outputs/Z6-C380-front-bit11-reviewed-2026-11-09'
ZIP = KIT.with_suffix('.zip')
FAILURES = {'22-assessment': 'Overbroad memory equality check; diagnosed by same-binary repeats, bounded comparison accepted in 26. All snapshots retained.'}
SCRIPTS = ('qemu_front_owner_watch.py', 'scan_front_config_identity.py', 'inspect_front_menu_records.py',
    'probe_front_actual_owner.py', 'prepare_front_preflash_tools.py', 'review_front_preflash.py',
    'verify_front_preflash_kit.py', 'probe_front_preflash_updater.py', 'qemu_front_preflash.py',
    'assess_front_preflash.py', 'package_front_preflash.py', 'test_front_preflash_verifier.py',
    'finalize_front_preflash.py', 'record_research_command.py', 'inspect_native.py')
DOCS = ('README.md', 'docs/NEXT_STEPS.md', 'docs/PROJECT_GOALS.md',
    'docs/FRONT_PREFLASH_REVIEW_2026-11-09.md', 'docs/Z6_FRONT_INSTALL_2026-11-09.txt',
    'docs/Z6_FRONT_FLAT_COMPARE_2026-11-09.txt')


def read(p):
    return json.loads(p.read_text(encoding='utf8'))


def save(p, value):
    with p.open('x', encoding='utf8') as f:
        json.dump(value, f, indent=2, ensure_ascii=False)


def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for part in iter(lambda: f.read(1 << 20), b''):
            h.update(part)
    return h.hexdigest()


def record(p):
    return dict(path=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=digest(p))


def commands(allow_current=False):
    rows = []
    for p in sorted((ROUND/'commands').glob('*/command.json')):
        d = read(p)
        name = p.parent.name
        if 'exit_code' not in d:
            need(allow_current, 'Incomplete command '+name)
            continue
        need(d['exit_code'] == int(name in FAILURES), 'Unexpected status '+name)
        rows.append(dict(name=name, **d, disposition=FAILURES.get(name, 'completed')))
    return rows


def progress():
    need(read(ROUND/'assessment.json')['ok'], 'Assessment required')
    check_kit(KIT)
    folder = ROUND/'progress-update'
    folder.mkdir(exist_ok=False)
    blocks = {
        'README.md': '''
**2026-11-09 最新：modified4 前端单项关闭已完成离线安装前审查并交付测试包。** 已从实际内存写入接通配置 `3d2 → 1013f0b2 → 请求复制 → 静态 input+45 → context+5d → 20068500 bit11`；候选沿用上一轮 LAB 的单指令字节，保留全部既有补丁。20 次来源回放、9 项文件检查、6 项擦写调度、6 次 QEMU 和 27 项校验器检查通过。该位的物理处理名称及真实彩圈效果待验，当前实拍成果仍为 modified3 的局部暗场效果保持、宽环未整体改善。先以当前 modified3 拍固定布置 A，再一次更新拍 B。[审查报告](docs/FRONT_PREFLASH_REVIEW_2026-11-09.md)、[安装入口](outputs/Z6-C380-front-bit11-reviewed-2026-11-09/START_HERE.txt)、[ZIP](outputs/Z6-C380-front-bit11-reviewed-2026-11-09.zip)、[平场步骤](docs/Z6_FRONT_FLAT_COMPARE_2026-11-09.txt)。下方均保留历史阶段状态。
''',
        'docs/NEXT_STEPS.md': '''
## 当前优先级（2026-11-09，modified4 受控测试包）

[审查报告](FRONT_PREFLASH_REVIEW_2026-11-09.md)：已找到真实配置 3d2 的生产者和前端请求复制，单项清 bit11 的既有 LAB 字节完成离线安装前审查。测试包含 modified3、modified1、stock 回退，固定哈希校验器通过 27 项检查。

1. 当前 modified3 先拍新的固定布置 A；按[步骤](Z6_FRONT_FLAT_COMPARE_2026-11-09.txt)保留机位、焦点、光源、曝光。旧 A 作历史参考。慢快门主组、多信号级优先。
2. 校验并一次更新 modified4；确认普通 NEF 保存/回放后拍匹配 B 与 ISO1600 5 秒 dark。菜单仍为3.80、NEFInfo6/7也继承，务必记录哈希及更新完成。
3. 真实 CFA 环边和冻结112点分别验收；有一致彩圈响应后再安排必要回退复现。当前不宣称所有 RAW 校正关闭或完整暗电流恢复。
4. 逆向继续识别 policy 第2项/bit11 对应硬件处理及真实标定状态。配置默认0是读取标定策略，零 CAL 模拟器的关闭状态不代表真机。
5. 保留六次 QEMU 全量快照与22号失败记录；context+a0/a4 同版本可变，写入者另查，不作全模式或全内存一致性承诺。原始固件和已有暗场补丁保持。

以下为此前计划，当前交付以本次确切哈希和报告为准。
''',
        'docs/PROJECT_GOALS.md': '''
## 当前推进（2026-11-09，modified4 前端受控测试）

最终目标不变。静态 RAW 前端单项控制已从实际生产者追至寄存器，既有 LAB 副本完成离线安装前审查，交付 modified4 测试包和三种回退。新候选保留已验证暗场补丁以及此前两组空间控制；新增变量只有一条静态输入指令。下一验收为固定布置 A/B 的真实 NEF 彩圈与112点暗场回归；bit11的物理名称、全部 RAW 校正关闭、完整暗电流恢复和长期可靠性继续分项记录。见[审查报告](FRONT_PREFLASH_REVIEW_2026-11-09.md)。模拟器配置检查与实机效果始终分开。
'''}
    changes = []
    for name, block in blocks.items():
        p = ROOT/name
        before = p.read_bytes()
        need(before == (ROUND/'progress-before'/Path(name).name).read_bytes(), 'Concurrent edit '+name)
        text = before.decode('utf8')
        need('FRONT_PREFLASH_REVIEW_2026-11-09.md' not in text, 'Already updated')
        backup = folder/('before-'+name.replace('/', '-'))
        backup.write_bytes(before)
        first, rest = text.split('\n', 1)
        p.write_bytes((first+'\n'+block+'\n'+rest).encode('utf8'))
        changes.append(dict(path=name, before_copy=backup.relative_to(ROOT).as_posix(),
                            before_sha256=digest(backup), after_sha256=digest(p)))
    save(folder/'changes.json', dict(changes=changes))
    print(json.dumps(dict(updated=len(changes))))


def archive():
    check_kit(KIT)
    tests = read(ROUND/'verifier-tests/result.json')
    need(tests['ok'] and len(tests['cases']) == 27, 'Verifier tests')
    with zipfile.ZipFile(ZIP, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in sorted(KIT.rglob('*')):
            if p.is_file():
                z.write(p, KIT.name+'/'+p.relative_to(KIT).as_posix())
    checked = []
    with zipfile.ZipFile(ZIP) as z:
        need(z.testzip() is None, 'ZIP CRC')
        expected = {KIT.name+'/'+p.relative_to(KIT).as_posix(): p for p in KIT.rglob('*') if p.is_file()}
        need(len(z.namelist()) == len(expected) and set(z.namelist()) == set(expected), 'ZIP entries')
        for name, p in expected.items():
            h = hashlib.sha256()
            with z.open(name) as f:
                for part in iter(lambda: f.read(1 << 20), b''):
                    h.update(part)
            need(h.hexdigest() == digest(p), 'ZIP content '+name)
            checked.append(dict(path=name, sha256=h.hexdigest()))
    save(ROUND/'archive-verification.json', dict(ok=True, archive=record(ZIP), files=checked))
    print(json.dumps(dict(ok=True, archive=record(ZIP), files=len(checked))))


def verify():
    kit = check_kit(KIT)
    prior = read(ROOT/'analysis/raw-front-controls-2026-11-09/verification.json')
    pins = prior['firmware_preserved']
    for name, expected in pins.items():
        need(digest(ROOT/name) == expected, 'Protected firmware changed '+name)
    for mode, p in SOURCES.items():
        read_module(p, mode)
    photos = read(ROOT/'analysis/modified3-real-2026-11-09/verification.json')['source_hashes']
    for name, expected in photos.items():
        need(digest(Path(name)) == expected, 'Source NEF changed '+name)
    frozen = []
    for name in ('raw-front-controls-2026-11-09', 'modified3-real-2026-11-09'):
        p = ROOT/'analysis'/name/'evidence-index.json'
        d = read(p)
        for row in d['files']:
            need(digest(ROOT/row['path']) == row['sha256'], 'Prior evidence changed '+row['path'])
        frozen.append(dict(index=p.relative_to(ROOT).as_posix(), files=len(d['files'])))
    assessment = read(ROUND/'assessment.json')
    need(assessment['ok'] and assessment['candidate_sha256'] == DIGESTS['test'], 'Assessment')
    for row in assessment['qemu_runs']:
        need(digest(ROOT/row['path']) == row['sha256'], 'QEMU evidence changed')
    for row in read(KIT/'manifest.json')['evidence']:
        need(digest(ROOT/row['path']) == row['sha256'], 'Manifest evidence changed')
    tests = read(ROUND/'verifier-tests/result.json')
    need(tests['ok'] and len(tests['cases']) == 27, 'Verifier cases')
    for source, target in (
        ('docs/Z6_FRONT_INSTALL_2026-11-09.txt', 'START_HERE.txt'),
        ('docs/Z6_FRONT_FLAT_COMPARE_2026-11-09.txt', 'FLAT_COMPARE.txt'),
        ('docs/FRONT_PREFLASH_REVIEW_2026-11-09.md', 'REVIEW.md'),
        ('tools/fw/verify_front_preflash_kit.py', 'verify.py')):
        need((ROOT/source).read_bytes() == (KIT/target).read_bytes(), 'Delivery differs '+source)
    archived = read(ROUND/'archive-verification.json')
    need(archived['ok'] and digest(ZIP) == archived['archive']['sha256'], 'Archive changed')
    for row in read(ROUND/'progress-update/changes.json')['changes']:
        need(digest(ROOT/row['path']) == row['after_sha256'], 'Progress changed')
        need(digest(ROOT/row['before_copy']) == row['before_sha256'], 'Progress backup changed')
    for name in SCRIPTS:
        ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf8'))
    diff = subprocess.run(['git', 'diff', '--check'], cwd=ROOT, capture_output=True)
    need(diff.returncode == 0, 'git diff --check failed: '+diff.stderr.decode(errors='replace'))
    (ROUND/'git-diff-check.txt').write_bytes(diff.stdout+diff.stderr)
    (ROUND/'git-status-after.txt').write_bytes(subprocess.run(['git', 'status', '--short'], cwd=ROOT, capture_output=True, check=True).stdout)
    save(ROUND/'verification.json', dict(ok=True, checked_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        candidate_sha256=DIGESTS['test'], kit=kit, archive=archived['archive'],
        protected_firmware=pins, source_nefs_unchanged=len(photos), source_hashes=photos,
        prior_frozen=frozen, verifier_cases=27, accepted_qemu_runs=6, owner_pairs=10,
        update_file_cases=9, scheduler_cases=6, commands=commands(allow_current=True),
        recorded_failures=FAILURES, lab_bytes_unchanged=True, actual_card_accessed=False,
        physical_flash=False, physical_modified4_nef=False, ring_removal_verified=False,
        git_diff_check=True, git_commit=False, verdict=assessment['verdict']))
    print(json.dumps(dict(ok=True, candidate_sha256=DIGESTS['test'], prior_frozen=frozen,
        source_nefs_unchanged=len(photos), verifier_cases=27)))


def index():
    need(read(ROUND/'verification.json')['ok'], 'Verification missing')
    cmds = commands()
    scripts = ROUND/'source-snapshots'
    scripts.mkdir(exist_ok=False)
    for name in SCRIPTS:
        shutil.copyfile(ROOT/'tools/fw'/name, scripts/name)
    docs = ROUND/'document-snapshots'
    docs.mkdir(exist_ok=False)
    for name in DOCS:
        shutil.copyfile(ROOT/name, docs/name.replace('/', '-'))
    rows = [record(p) for p in sorted(ROUND.rglob('*')) if p.is_file()]
    delivered = [record(p) for p in sorted(KIT.rglob('*')) if p.is_file()]+[record(ZIP)]
    save(ROUND/'evidence-index.json', dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=sys.argv, files=rows, delivery_files=delivered, commands=cmds,
        status='Frozen exact modified4 controlled-test kit. Offline verification only; physical bit identity and NEF/ring effects pending.'))
    print(json.dumps(dict(indexed_files=len(rows), delivery_files=len(delivered), commands=len(cmds))))


if __name__ == '__main__':
    {'progress': progress, 'archive': archive, 'verify': verify, 'index': index}[sys.argv[1]]()

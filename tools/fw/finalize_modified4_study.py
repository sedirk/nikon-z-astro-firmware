"""Assess and freeze real modified4 flat evidence; dark efficacy remains pending."""
import ast, datetime, json, re, subprocess, sys
import numpy as np
from modified4_study_common import ROOT, ROUND, GROUPS, read, write, need, record
from audit_nef import file_sha
from verify_front_preflash_kit import BASE, EDITS, DIGESTS, PATHS, check_kit, read_module

REPORT = ROOT/'docs/MODIFIED4_REAL_NEF_2026-11-09.md'
KIT = ROOT/'outputs/Z6-C380-front-bit11-reviewed-2026-11-09'
SCRIPTS = ('modified4_study_common.py', 'prepare_modified4_analysis.py', 'analyze_modified4_flats.py',
    'plot_modified4_study.py', 'finalize_modified4_study.py', 'audit_nef.py', 'inventory_nas_nef.py',
    'extract_flat_correction_fields.py', 'verify_modified1_decode.py', 'analyze_modified1_flats.py',
    'analyze_modified2_flats.py', 'modified3_study_common.py', 'plot_modified3_study.py',
    'record_research_command.py', 'verify_front_preflash_kit.py')


def assess():
    inputs = read(ROUND/'inputs.json')
    flat = read(ROUND/'flats/result.json')
    fields = read(ROUND/'correction-fields/result.json')
    decode = read(ROUND/'independent-decode/result.json')
    old_fields = read(ROOT/'analysis/modified3-real-2026-11-09/correction-fields/result.json')
    old_decode = read(ROOT/'analysis/modified3-real-2026-11-09/independent-decode/result.json')
    old_assessment = read(ROOT/'analysis/modified3-real-2026-11-09/assessment.json')
    need(all(d['ok'] for d in (inputs, flat, fields, decode, old_fields, old_decode, old_assessment)), 'Failed dependency')
    need(inputs['new_dark_frames'] == 0 and inputs['recorded_setting_differences'] == {}, 'Study design changed')
    need(len(fields['files']) == len(decode['files']) == 3 and decode['total_pixels'] == 73495680, 'Incomplete new data')
    lookup = {r['id']: r for r in inputs['files']}
    for result, ids in ((decode, GROUPS['modified4_flat']), (old_decode, GROUPS['modified3_flat'])):
        matched = []
        for f in result['files']:
            ident = int(f['name'].split('_')[-1].split('.')[0])
            if ident not in ids:
                continue
            row = lookup[ident]
            need(f['mismatches'] == 0 and f['source_sha256'] == row['sha256']
                 and f['pixels_sha256'] == row['audit']['stored_pixels_sha256'], 'Decoder/source mismatch')
            matched.append(ident)
        need(set(matched) == set(ids), 'Missing independent decode')
    valid_fields = []
    for f in old_fields['files']+fields['files']:
        ident = int(f['name'].split('_')[-1].split('.')[0])
        if ident not in lookup:
            continue
        need(f['sha256'] == lookup[ident]['sha256'], 'Fields source mismatch')
        spatial = f['two_table_spatial']
        c = spatial['coefficients']
        need(f['vignette'] == dict(coefficients=[0]*4, strength_L=0, status=1), 'Vignette changed')
        need(spatial['flag_at_4'] == 1 and spatial['flag_at_5a'] == 0, 'Spatial flag changed')
        need(all(c[i] == 0 for i in (1, 2, 4, 5)) and c[0] % 16 == c[3] % 16 == 0, 'Nonneutral spatial coefficients')
        valid_fields.append(dict(name=f['name'], spatial=spatial))
    need(len(valid_fields) == 6, 'Missing field checks')
    modules = {name: read_module(KIT/PATHS[name], name) for name in ('test', 'modified3', 'modified1')}
    retained = []
    for pc, before, after in EDITS[:3]:
        offset = pc-BASE
        values = {k: v[offset:offset+len(bytes.fromhex(after))].hex() for k, v in modules.items()}
        need(set(values.values()) == {after}, 'Inherited dark instruction changed')
        retained.append(dict(pc=hex(pc), values=values))
    need(old_assessment['local_dark_suppression_regression_passed'], 'Prior dark baseline changed')
    sat = {g: sum(p['saturated'] for f in flat['files'] if f['group'] == g for p in f['phases']) for g in GROUPS}
    need(all(n == 0 for n in sat.values()), 'Saturated primary flats')
    centre = np.asarray(flat['centre_green_signals'])
    a, b = float(centre[:3].mean()), float(centre[3:].mean())
    result = dict(ok=True, created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        physical_modified4_nef=True, firmware_user_confirmation=inputs['firmware_confirmation'],
        setup_confirmation=inputs['setup_confirmation'], dark_confirmation=inputs['dark_confirmation'],
        independent_new_pixels=decode['total_pixels'], independent_new_mismatches=0,
        prior_three_decodes_reused_by_hash=True, recorded_setting_differences={},
        ring_metrics=flat['group_radial'], frame_radial=flat['frame_radial'],
        centre_green_signal_A=a, centre_green_signal_B=b, centre_green_change_percent=100*(b/a-1),
        normalized_green_difference=flat['green_group_difference_percent'], saturated_flat_pixels=sat,
        physical_nef_vignette_still_neutral=True, physical_nef_spatial_still_neutral=True,
        physical_fields=valid_fields, modified4_delivered_sha256=DIGESTS['test'],
        dark_patch_bytes_preserved=True, dark_instruction_checks=retained,
        new_dark_frames=0, modified4_physical_dark_regression=None,
        last_dark_verified_version='modified3', last_dark_fingerprint=old_assessment['dark_fingerprint_B'],
        no_dark_inference_from_flats=True, no_full_dark_current_recovery_claim=True,
        ring_removal_demonstrated=False,
        conclusion='Broad colour structure remains without consistent overall reduction. Dark patch bytes retained; no new modified4 dark captures, so physical dark regression is pending.',
        causal_limit='Same equipment/brightness and exposure metadata; placement/focus may differ. 1/8000 tablet flats at one signal setting, not a firmware-only estimate.',
        frontend_bit11_state_readback=False, new_firmware_created=False,
        visual_review='All four PNG figures inspected: legible shared-scale comparisons, persistent broad structure and changed directional illumination; no dark plot generated.')
    write(ROUND/'assessment.json', result)
    print(json.dumps({k: result[k] for k in ('ok', 'centre_green_change_percent', 'new_dark_frames', 'dark_patch_bytes_preserved', 'conclusion')}, ensure_ascii=False))


def progress():
    need(read(ROUND/'assessment.json')['ok'], 'Assessment required')
    out = ROUND/'progress-update'
    out.mkdir(exist_ok=False)
    blocks = {
        'README.md': '''
**2026-11-09 最新实拍：modified4 三张平场保存和独立解码正常，宽彩圈未整体改善。** 与 modified3 对比，R/G 宽起伏1.380→1.544、B/G 1.350→1.311个百分点；两者变化方向不同，用户确认布置/对焦可能移动。NEFInfo6/7中性参数保持。已交付固件的三处暗场补丁字节完整保留；用户确认本次尚未拍暗场，modified4实拍暗场回归待补拍，最后通过的版本仍为modified3。[报告](docs/MODIFIED4_REAL_NEF_2026-11-09.md)、[对比图](analysis/modified4-real-2026-11-09/figures/modified4-ring-comparison.png)。以下保留各轮历史状态。
''',
        'docs/NEXT_STEPS.md': '''
## 当前优先级（2026-11-09，modified4 三张平场实拍）

[实拍报告](MODIFIED4_REAL_NEF_2026-11-09.md)：三张真实NEF独立解码一致，中性保存参数保持；当前宽环没有整体减弱。R/G起伏增大，B/G略降且小变化对分箱尺度敏感。用户确认机位或焦点可能变化，未将幅度变化归因于固件。

1. 当前modified4补三张盖镜头ISO1600、5秒dark即可回归112点，不需先换固件。本次用户确认还没拍，旧modified3的通过结果不算作modified4实拍通过。
2. bit11支线已有真实保存反馈，但尚无消圈收益；继续结合真实policy/寄存器状态和固定标定身份追踪，避免无依据叠加更多开关。
3. 后续细密彩圈验证用固定机位/焦点、慢快门、多个信号级的匹配组。当前屏幕宽结构兼有光源/镜头贡献；先明确下一变量和判据，再安排必要的更新/回退。
4. 已验证暗场补丁和原始固件继续保留；本轮仅分析文件，未新增固件或刷写。

以下为此前计划和安装前状态。
''',
        'docs/PROJECT_GOALS.md': '''
## 当前推进（2026-11-09，modified4 平场实机反馈）

最终目标不变。前端单项关闭候选已由用户确认刷入并保存三张可完整解码的真实NEF；原有中性空间/暗角字段保持。本批平场宽彩圈未整体改善。暗场补丁的交付字节保持原样，modified4新暗场尚未拍摄，实机回归单列待验；此前modified3局部暗场成果继续有效。所有RAW校正关闭、完整暗电流恢复和消圈仍分别验收。[本轮报告](MODIFIED4_REAL_NEF_2026-11-09.md)。
'''}
    changes = []
    for name, block in blocks.items():
        path = ROOT/name
        before = path.read_bytes()
        backup = ROUND/'progress-before'/name.replace('/', '-')
        need(before == backup.read_bytes(), 'Concurrent document edit')
        text = before.decode('utf8')
        need('MODIFIED4_REAL_NEF_2026-11-09.md' not in text, 'Already updated')
        first, rest = text.split('\n', 1)
        path.write_bytes((first+'\n'+block+'\n'+rest).encode('utf8'))
        changes.append(dict(path=name, before=record(backup), after_sha256=file_sha(path)))
    write(out/'changes.json', dict(changes=changes))
    print('Updated README, next steps and goals with separate flat/dark status.')


def verify():
    assessment = read(ROUND/'assessment.json')
    need(assessment['ok'], 'Assessment missing')
    inputs = read(ROUND/'inputs.json')
    flat = read(ROUND/'flats/result.json')
    sources = dict(read(ROOT/'analysis/raw-front-owner-2026-11-09/verification.json')['source_hashes'])
    sources.update({r['path']: r['sha256'] for r in inputs['files']})
    for path, expected in sources.items():
        need(file_sha(path) == expected, 'Source changed '+path)
    for row in read(ROUND/'metadata/inventory.json')['source_states']:
        stat = (ROOT/row['path']).stat()
        need((stat.st_size, stat.st_mtime_ns) == (row['bytes'], row['mtime_ns']), 'Source stat changed')
    need(flat['scalar_checks'] == 144 and flat['modified3_frozen_arrays_exact'], 'Reference controls')
    kit = check_kit(KIT)
    original = ROOT/'firmware/original/Z_6_0380.bin'
    need(file_sha(original) == 'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54', 'Original changed')
    frozen = []
    for name in ('modified3-real-2026-11-09', 'raw-front-owner-2026-11-09'):
        path = ROOT/'analysis'/name/'evidence-index.json'
        data = read(path)
        for row in data['files']:
            need(file_sha(ROOT/row['path']) == row['sha256'], 'Prior evidence changed')
        frozen.append(dict(index=path.relative_to(ROOT).as_posix(), files=len(data['files'])))
    for row in read(ROUND/'figures/result.json')['figures']:
        need(file_sha(ROOT/row['path']) == row['sha256'], 'Figure changed')
    for name in SCRIPTS:
        ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf8'))
    for link in re.findall(r'\]\(([^)]+)\)', REPORT.read_text(encoding='utf8')):
        if not link.startswith('https:'):
            need((REPORT.parent/link).is_file(), 'Report link '+link)
    for row in read(ROUND/'progress-update/changes.json')['changes']:
        need(file_sha(ROOT/row['path']) == row['after_sha256'], 'Progress changed')
    cmds = []
    for path in sorted((ROUND/'commands').glob('*/command.json')):
        value = read(path)
        if 'exit_code' not in value:
            continue
        need(value['exit_code'] == 0, 'Unexpected failed command')
        cmds.append(dict(name=path.parent.name, exit_code=0))
    result = subprocess.run(['git', 'diff', '--check'], cwd=ROOT, capture_output=True)
    need(result.returncode == 0, 'git diff --check')
    (ROUND/'git-diff-check.txt').write_bytes(result.stdout+result.stderr)
    (ROUND/'git-status-after.txt').write_bytes(subprocess.run(['git', 'status', '--short'], cwd=ROOT, capture_output=True, check=True).stdout)
    write(ROUND/'verification.json', dict(ok=True, source_files_unchanged=len(sources), source_hashes=sources,
        original=record(original), kit=kit, prior_frozen=frozen, independent_new_pixels=73495680,
        scalar_checks=144, report=record(REPORT), commands=cmds, new_dark_frames=0,
        modified4_physical_dark_regression=None, dark_patch_bytes_preserved=True,
        ring_removal_demonstrated=False, new_firmware_created=False, git_commit=False))
    print(json.dumps(dict(ok=True, source_files_unchanged=len(sources), prior_frozen=frozen, new_dark_frames=0)))


def index():
    need(read(ROUND/'verification.json')['ok'], 'Verification required')
    out = ROUND/'script-snapshots'
    out.mkdir(exist_ok=False)
    for name in SCRIPTS:
        (out/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    out = ROUND/'document-snapshots'
    out.mkdir(exist_ok=False)
    for name in ('docs/MODIFIED4_REAL_NEF_2026-11-09.md', 'README.md', 'docs/NEXT_STEPS.md', 'docs/PROJECT_GOALS.md'):
        (out/name.replace('/', '-')).write_bytes((ROOT/name).read_bytes())
    cmds = [dict(name=p.parent.name, **read(p)) for p in sorted((ROUND/'commands').glob('*/command.json'))]
    need(all(r.get('exit_code') == 0 for r in cmds), 'Unfinished or failed command')
    write(ROUND/'evidence-index.json', dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), argv=sys.argv,
        files=[record(p) for p in sorted(ROUND.rglob('*')) if p.is_file()], commands=cmds,
        status='Real modified4 flats: broad colour structure remains, inherited neutral fields retained; no new dark frames, so physical dark regression pending.'))
    print(json.dumps(dict(files=len(read(ROUND/'evidence-index.json')['files']), commands=len(cmds))))


if __name__ == '__main__':
    {'assess': assess, 'progress': progress, 'verify': verify, 'index': index}[sys.argv[1]]()

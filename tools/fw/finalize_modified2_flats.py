"""Freeze the physical modified2 flat comparison and update project progress."""
from pathlib import Path
import datetime,json,re,sys
import numpy as np
from audit_nef import file_sha
from verify_vignette_preflash_kit import DIGESTS,check_kit

ROOT=Path(__file__).resolve().parents[2]
ROUND=ROOT/'analysis/modified2-flat-2026-11-09'
REPORT=ROOT/'docs/MODIFIED2_FLATS_2026-11-09.md'


def need(value,message):
    if not value:raise ValueError(message)


def read(path):return json.loads(path.read_text(encoding='utf8'))


def write(path,value):
    need(not path.exists(),'Refusing overwrite '+str(path))
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False,allow_nan=False),encoding='utf8')


def record(path):return dict(path=path.relative_to(ROOT).as_posix(),bytes=path.stat().st_size,sha256=file_sha(path))


def assess():
    inputs=read(ROUND/'inputs.json');data=read(ROUND/'cfa-comparison/result.json')
    old=read(ROOT/'analysis/raw-ring-controls-2026-11-09/nef-fields/result.json')
    new=read(ROUND/'correction-fields/result.json');decode=read(ROUND/'independent-decode/result.json')
    need(inputs['ok'] and data['ok'] and new['ok'] and decode['ok'],'Unpassed input')
    need(inputs['capture_setting_differences']=={},'Capture settings differ')
    need(len(new['files'])==2 and decode['total_pixels']==48997120,'Incomplete B group')
    for row in new['files']:
        need(row['vignette']==dict(coefficients=[0,0,0,0],strength_L=0,status=1),'Unexpected vignette result')
        need(row['two_table_spatial']==old['files'][0]['two_table_spatial'],'Spatial fields changed')
    tags={r['name']:{k:old['files'][0]['nefinfo']['entries'][k]['bytes']==r['nefinfo']['entries'][k]['bytes']
          for k in old['files'][0]['nefinfo']['entries']} for r in new['files']}
    centre=np.array(data['centre_green_signals'])
    summary=dict(ok=True,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        evidence_type='Physical saved NEF comparison; user supplied B after modified2; no flash readback',
        matched_recorded_settings=True,user_conditions=inputs['user_confirmation'],new_B_files=[r['name'] for r in new['files']],
        vignette_before=old['files'][0]['vignette'],vignette_after=new['files'][0]['vignette'],
        spatial_before_after=new['files'][0]['two_table_spatial'],other_nefinfo_equality=tags,
        group_radial_metrics=data['group_radial_metrics'],
        centre_green_mean_A=float(centre[:2].mean()),centre_green_mean_B=float(centre[2:].mean()),
        centre_green_B_over_A_change_percent=float((centre[2:].mean()/centre[:2].mean()-1)*100),
        B_saturated_active_pixels=sum(p['saturated'] for r in data['files'][2:] for p in r['phases']),
        independent_new_pixels=decode['total_pixels'],independent_mismatches=sum(r['mismatches'] for r in decode['files']),
        scalar_checks=data['scalar_block_checks'],frozen_A_arrays_exactly_reproduced=data['frozen_A_arrays_exactly_reproduced'],
        conclusion='Vignette coefficients/L zero in both physical B NEFs; broad colour rings remain with no clear overall reduction in this comparison.',
        causal_limit='Placement/focus may differ; brightness/structure changes are not a firmware-only estimate. One exposure level; observed broad rings not identified as hardcoded quantization rings.',
        new_dark_regression=False,physical_rollback_test=False,new_firmware_created=False,
        next_priority=['17-entry spatial tables and their dedicated static control','Fixed calibration and short-exposure frontend selection','Matched low-ISO/slower-shutter physical groups for finer quantization-ring diagnosis'])
    write(ROUND/'assessment.json',summary)
    print(json.dumps(summary,indent=2,ensure_ascii=False))


def progress():
    need(read(ROUND/'assessment.json')['ok'],'Assessment required')
    folder=ROUND/'progress-update';folder.mkdir(exist_ok=False)
    blocks={
    'README.md':'''\n**2026-11-09 最新实拍：modified2 的暗角四系数和 L 已归零，现有宽环仍在。**用户新 B 组 4870/4873 与旧 A 组 4864/4865 曝光设置一致；位置／对焦可能变化。两张 B 的 48,997,120 个码值独立解码一致，NEFInfo7 保持原非零空间系数。R/G 径向宽起伏约 1.456→1.467 个百分点，B/G 1.448→1.412，未见整体明显减弱；消圈主线接着追两组 17 项表和固定标定。此轮没有新 dark，暗场回归另记。[实拍报告](docs/MODIFIED2_FLATS_2026-11-09.md)、[A/B 对照图](analysis/modified2-flat-2026-11-09/figures/modified2-ring-comparison.png)。以下安装前状态按历史时间阅读。\n''',
    'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，modified2 实拍结果）\n\n[最新实拍报告](MODIFIED2_FLATS_2026-11-09.md)：用户提供的 B 组已正常保存，两张真实 NEFInfo6 四系数及 L 全部归零，NEFInfo7 不变。旧 A 与新 B 的曝光设置匹配，用户确认位置／对焦可能改变。宽颜色环仍明显存在。\n\n1. **把剩余空间表与固定标定作为消圈主线。** 沿两组 17 项表的专用静态入口、坐标保留、缓存分支和 RAW 写回继续定位；不全局修改主属性 +96，不清空整个标定。\n2. **257 项支线保留为独立控制。** 已有真实保存参数反馈；这批的宽环未明显减弱，不继续以系数归零作为消圈验收，不据此外推其它 ISO／曝光条件。\n3. **保持短曝光前端线索。** 新旧组仍为 1/8000 秒，继续确认 144 项表的实际记录选择与写回，区分默认表、旧表复用和真正中性条件。\n4. **后续取样绑定下一处实际修改。** 当前旧 A 已完成本轮比较；新实验采用固定机位／焦点／光源、较慢快门、多信号级，低 ISO 与不同光圈另起匹配组。\n5. **暗场成果继续独立回归。** 新 B 目录目前只有两张平场；现有三处邻域补丁字节保留，112 点新 dark 与实际回退尚待新的实拍。\n\n下方为历史计划，安装前的“尚无 modified2 NEF”已由本轮记录更新。\n''',
    'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，modified2 平场实拍）\n\n最终目标不变。新增 257 项中性化候选已获得用户 B 组实拍：两张 NEF 完整解码一致，暗角四系数及 L 归零，另一组空间系数保持；当前宽环状颜色结构仍存在。后续消圈优先两组 17 项表与固定标定。位置／对焦可能改变的条件已记录，参数反馈与像素因果效果分开；本轮只有平场，新增暗场回归另行验收。详见[实拍报告](MODIFIED2_FLATS_2026-11-09.md)。\n'''}
    changes=[]
    for relative,block in blocks.items():
        path=ROOT/relative;before=path.read_bytes();content=before.decode('utf8')
        need('MODIFIED2_FLATS_2026-11-09.md' not in content,'Already updated')
        backup=folder/('before-'+relative.replace('/','-'));backup.write_bytes(before)
        first,rest=content.split('\n',1);path.write_bytes((first+'\n'+block+'\n'+rest).encode('utf8'))
        changes.append(dict(path=relative,before_copy=str(backup.relative_to(ROOT)),before_sha256=file_sha(backup),after_sha256=file_sha(path)))
    write(folder/'changes.json',dict(changes=changes,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    print(json.dumps(dict(updated=len(changes))))


def verify():
    inputs=read(ROUND/'inputs.json');data=read(ROUND/'cfa-comparison/result.json');assessment=read(ROUND/'assessment.json')
    need(data['ok'] and assessment['ok'],'Analysis failed')
    need(data['scalar_block_checks']==96 and data['frozen_A_arrays_exactly_reproduced'],'Array verification failed')
    for row in inputs['files']:need(file_sha(row['path'])==row['sha256'],'Source file changed')
    metadata=read(ROUND/'metadata/inventory.json')
    for row in metadata['source_states']:
        state=Path(row['path']).stat();need((state.st_size,state.st_mtime_ns)==(row['bytes'],row['mtime_ns']),'Source state changed')
    decode=read(ROUND/'independent-decode/result.json')
    need(decode['ok'] and decode['total_pixels']==48997120 and all(r['mismatches']==0 for r in decode['files']),'Decoder failed')
    figs=read(ROUND/'figures/result.json');need(figs['ok'],'Figures failed')
    for row in figs['figures']:need(file_sha(ROUND/'figures'/row['name'])==row['sha256'],'Figure changed')
    check_kit(ROOT/'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09')
    firmware={'firmware/original/Z_6_0380.bin':'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
        'firmware/decoded/eg1620_038000.bi':DIGESTS['stock'],
        'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN':DIGESTS['modified1'],
        'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN':DIGESTS['test']}
    for relative,digest in firmware.items():need(file_sha(ROOT/relative)==digest,'Firmware changed')
    frozen=[]
    for relative in ('analysis/modified1-flat-2026-11-09/evidence-index.json',
                     'analysis/raw-ring-controls-2026-11-09/evidence-index.json',
                     'analysis/vignette-preflash-2026-11-09/evidence-index.json'):
        previous=read(ROOT/relative)
        for row in previous['files']:need(file_sha(ROOT/row['path'])==row['sha256'],'Prior frozen evidence changed: '+row['path'])
        frozen.append(dict(index=relative,files_checked=len(previous['files'])))
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if not link.startswith('https:'):need((REPORT.parent/link).is_file(),'Broken report link')
    for row in read(ROUND/'progress-update/changes.json')['changes']:
        need(file_sha(ROOT/row['path'])==row['after_sha256'],'Progress changed')
        need(file_sha(ROOT/row['before_copy'])==row['before_sha256'],'Progress backup changed')
    commands=[]
    for path in sorted((ROUND/'commands').glob('*/command.json')):
        value=read(path)
        if 'exit_code' not in value:continue
        need(value['exit_code']==0,'Command failed')
        commands.append(dict(name=path.parent.name,exit_code=0))
    write(ROUND/'verification.json',dict(ok=True,firmware_hashes=firmware,source_files_unchanged=4,
        new_independent_pixels=48997120,scalar_checks=96,prior_frozen=frozen,figures=len(figs['figures']),
        report_sha256=file_sha(REPORT),completed_commands=commands,
        physical_nefinfo6_zero=True,physical_ring_removal=False,new_dark_regression=False,new_firmware_modified=False))
    print(json.dumps(dict(ok=True,source_files=4,new_pixels=48997120,prior_frozen=frozen)))


def index():
    need(read(ROUND/'verification.json')['ok'],'Verification needed')
    scripts=ROUND/'script-snapshots';scripts.mkdir(exist_ok=False)
    names=('prepare_modified2_flat_study.py','analyze_modified2_flats.py','plot_modified2_flats.py',
        'analyze_modified1_flats.py','inventory_nas_nef.py','audit_nef.py','extract_flat_correction_fields.py',
        'bridge_real_nef_contract.py','verify_modified1_decode.py','verify_vignette_preflash_kit.py',
        'record_research_command.py',Path(__file__).name)
    for name in names:(scripts/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    docs=ROUND/'document-snapshots';docs.mkdir(exist_ok=False)
    for relative in ('docs/MODIFIED2_FLATS_2026-11-09.md','README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md'):
        (docs/relative.replace('/','-')).write_bytes((ROOT/relative).read_bytes())
    commands=[dict(name=p.parent.name,**read(p)) for p in sorted((ROUND/'commands').glob('*/command.json'))]
    need(all(r.get('exit_code')==0 for r in commands),'Command unfinished or failed')
    write(ROUND/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
        files=[record(p) for p in sorted(ROUND.rglob('*')) if p.is_file()],commands=commands,
        status='Frozen physical B-flat study. Vignette metadata zero; broad rings remain; placement/focus confound retained.'))
    print(json.dumps(dict(indexed_files=len(read(ROUND/'evidence-index.json')['files']),commands=len(commands))))


if __name__=='__main__':{'assess':assess,'progress':progress,'verify':verify,'index':index}[sys.argv[1]]()

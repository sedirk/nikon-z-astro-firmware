"""Assess and freeze the confirmed modified3 physical comparison."""
import ast, datetime, json, re, subprocess, sys
import numpy as np
from modified3_study_common import ROOT,ROUND,read,write,need,record
from audit_nef import file_sha
from verify_spatial_preflash_kit import check_kit

REPORT=ROOT/'docs/MODIFIED3_REAL_NEF_2026-11-09.md'
SCRIPTS=('modified3_study_common.py','analyze_modified3_flats.py','analyze_modified3_darks.py',
         'plot_modified3_study.py','finalize_modified3_study.py','audit_nef.py','inventory_nas_nef.py',
         'extract_flat_correction_fields.py','bridge_real_nef_contract.py','verify_modified1_decode.py',
         'analyze_modified1_flats.py','analyze_modified2_flats.py','analyze_modified1_nef.py',
         'record_research_command.py','verify_spatial_preflash_kit.py')

def assess():
    inputs=read(ROUND/'inputs.json');flat=read(ROUND/'flats/result.json');dark=read(ROUND/'darks-v2/result.json')
    fields=read(ROUND/'correction-fields/result.json');decode=read(ROUND/'independent-decode/result.json')
    prior=read(ROOT/'analysis/modified2-extra-2026-11-09/correction-fields/result.json')
    prior_decode=read(ROOT/'analysis/modified2-extra-2026-11-09/independent-decode/result.json')
    need(all(r['ok'] for r in (inputs,flat,dark,fields,decode,prior,prior_decode)),'Failed dependency')
    need(inputs['recorded_setting_differences']['flat']=={},'Recorded flat settings differ')
    expected_vignette=dict(coefficients=[0]*4,strength_L=0,status=1)
    need(len(fields['files'])==len(prior['files'])==6,'Wrong field count')
    for row in fields['files']:
        spatial=row['two_table_spatial'];c=spatial['coefficients']
        need(row['vignette']==expected_vignette,'Vignette regression')
        need(spatial['flag_at_4']==1 and spatial['flag_at_5a']==0,'Spatial flags unexpected')
        need(all(c[i]==0 for i in (1,2,4,5)) and c[0]%16==c[3]%16==0,'Unexpected nonneutral spatial coefficient')
    for row in prior['files']:
        need(row['vignette']==expected_vignette and row['two_table_spatial']==dict(coefficients=[142,-79,0,-74,-6,61],flag_at_4=1,flag_at_5a=1),'Prior fields differ')
    lookup={r['id']:r for r in inputs['files']}
    for result in (decode,prior_decode):
        need(len(result['files'])==6 and result['total_pixels']==146991360,'Incomplete independent decode')
        for f in result['files']:
            ident=int(f['name'].split('_')[-1].split('.')[0]);r=lookup[ident]
            need(f['mismatches']==0 and f['source_sha256']==r['sha256'] and f['pixels_sha256']==r['audit']['stored_pixels_sha256'],'Decoder/source mismatch')
    arrays=np.load(ROUND/'darks-v2/arrays.npz')
    aa=np.flatnonzero(~(arrays['deltas'][4:7]>56).all(axis=0));bb=np.flatnonzero(~(arrays['deltas'][7:10]>56).all(axis=0))
    need(np.array_equal(aa,bb) and len(aa)==1,'Dark exception changed')
    point=dark['targets'][int(aa[0])]
    need(all(dark['locked_results'][g]['per_frame_fit']==[0,0,0] for g in ('modified2_dark','modified3_dark')),'Old suppression relation returned')
    a=np.array(flat['centre_green_signals'][:3]);b=np.array(flat['centre_green_signals'][3:6])
    sat={g:sum(p['saturated'] for row in flat['files'] if row['group']==g for p in row['phases']) for g in ('modified2_flat','modified3_flat')}
    need(sat==dict(modified2_flat=0,modified3_flat=0),'Saturated flat pixels')
    result=dict(ok=True,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
      physical_evidence=True,firmware_user_confirmation=inputs['firmware_confirmation'],setup_confirmation=inputs['setup_confirmation'],
      independent_new_pixels=decode['total_pixels'],independent_new_mismatches=0,prior_six_decodes_reused_by_hash=True,
      physical_nef_spatial_active_before=1,physical_nef_spatial_active_after=0,
      physical_fields_after=[dict(name=r['name'],spatial=r['two_table_spatial']) for r in fields['files']],
      physical_nef_vignette_still_neutral=True,ring_metrics=flat['group_radial'],
      centre_green_signal_A=float(a.mean()),centre_green_signal_B=float(b.mean()),
      centre_green_change_percent=float(100*(b.mean()/a.mean()-1)),saturated_flat_pixels=sat,
      dark_fingerprint_A=dark['locked_results']['modified2_dark'],dark_fingerprint_B=dark['locked_results']['modified3_dark'],
      same_low_signal_exception=point,local_dark_suppression_regression_passed=True,
      conclusion='Physical spatial-active/coefficients match modified3 neutral prediction; broad colour rings remain without overall improvement; local dark suppression patch remains effective.',
      causal_limit='Same equipment/settings, possible placement/focus changes; 1/8000 tablet-lit single-exposure flats. Reported differences are not a firmware-only percentage improvement.',
      no_full_dark_current_recovery_claim=True,no_hardware_table_readback=True,new_firmware_created=False,
      next_priority=['Fixed body calibration and frontend control/writer tracing','Controlled slower-shutter multiple-signal-level flats to separate lighting/optics from fine hardcoded rings'])
    write(ROUND/'assessment.json',result)
    print(json.dumps({k:result[k] for k in ('ok','centre_green_change_percent','local_dark_suppression_regression_passed','conclusion')},ensure_ascii=False))

def progress():
    need(read(ROUND/'assessment.json')['ok'],'Assessment missing')
    out=ROUND/'progress-update';out.mkdir(exist_ok=False)
    blocks={
      'README.md':'\n**2026-11-09 最新实拍：modified3 空间关闭标志已进入真实 NEF，暗场效果保持，当前宽彩圈未明显改善。**确认刷入后的 4886/4888/4889 平场与 4890–4892 暗场全部独立解码一致；NEFInfo7 active=0、非中性系数归零，坐标常数项按原政策保留。对照刚归档的 modified2：R/G 宽起伏 1.256→1.380、B/G 1.431→1.350 个百分点；布置可能移动，未作固件单独改善量。两版三张暗场均 0/112 符合旧邻域抑制关系，111 点保留强信号，另一个低信号点两版相同。[报告](docs/MODIFIED3_REAL_NEF_2026-11-09.md)、[平场图](analysis/modified3-real-2026-11-09/figures/modified3-ring-comparison.png)、[暗场图](analysis/modified3-real-2026-11-09/figures/dark-regression.png)。早先误标为 modified3 的 4874–4880 已按用户更正归档到 modified2。下文安装前状态按历史时间阅读。\n',
      'docs/NEXT_STEPS.md':'\n## 当前优先级（2026-11-09，modified3 确认实拍）\n\n[实拍报告](MODIFIED3_REAL_NEF_2026-11-09.md)：NEFInfo7 active 已从 1 变 0，相关非中性系数归零；暗场回归通过。当前屏幕平场宽环仍在，R/G 与 B/G 起伏变化方向不同，位置／对焦变化的影响保留。\n\n1. **把两组 17 项分支记为已有实拍参数反馈的控制。** 保留候选和原始数据；不再以该字段归零重复认定消圈。\n2. **消圈主线转向机身固定标定与前端控制的实际写入者。** 沿已定位的 14 字段控制字／运行时覆盖和 RAW 写回继续追踪，逐项设计关闭条件，不清空整个标定资源。\n3. **区分当前宽颜色结构与细密量化环。** 后续采用固定光源／焦点／机位、较慢快门、多信号级；现有屏幕与镜头光学贡献保留。当前无消圈改善率。\n4. **保持暗场局部回归。** 原冻结 112 点在 modified2 与 modified3 各三张均 0 命中旧关系，111 点强信号延续；同一例外 (121,3740) 在 modified2 就已低信号，不列为 modified3 新回归。无新 bias／温控，不从强点亮度变化外推完整暗电流率。\n\n本轮只分析样本并更新记录，没有新增固件修改或刷写。以下为历史计划。\n',
      'docs/PROJECT_GOALS.md':'\n## 当前推进（2026-11-09，modified3 实机反馈）\n\n最终目标不变。确认刷入后的 modified3 已实际保存六张 NEF；空间 active=0 与非中性系数归零符合候选预期，旧暗角中性参数保持。暗场邻域抑制回归通过；屏幕平场宽彩圈未整体减弱。研究已把这条空间控制推进到真实文件反馈，继续追机身固定标定／前端和实际像素因果关系。参数变化、局部暗场效果、消圈与全暗电流恢复分别验收。[最新报告](MODIFIED3_REAL_NEF_2026-11-09.md)。\n'}
    changes=[]
    for name,block in blocks.items():
        path=ROOT/name;before=path.read_bytes();backup=ROUND/'progress-before'/name.replace('/','-')
        need(before==backup.read_bytes(),'Progress changed during study')
        content=before.decode('utf8');need('MODIFIED3_REAL_NEF_2026-11-09.md' not in content,'Already updated')
        first,rest=content.split('\n',1);path.write_bytes((first+'\n'+block+'\n'+rest).encode('utf8'))
        changes.append(dict(path=name,before=record(backup),after_sha256=file_sha(path)))
    write(out/'changes.json',dict(changes=changes))
    print('Updated README, next steps and project goals.')

def verify():
    assessment=read(ROUND/'assessment.json');need(assessment['ok'],'Assessment missing')
    inputs=read(ROUND/'inputs.json');dark=read(ROUND/'darks-v2/result.json');flat=read(ROUND/'flats/result.json')
    sources={r['path']:r['sha256'] for r in inputs['files']+dark['files']}
    for path,digest in sources.items():need(file_sha(path)==digest,'Source changed: '+path)
    for row in read(ROUND/'metadata/inventory.json')['source_states']:
        st=__import__('pathlib').Path(row['path']).stat()
        need((st.st_size,st.st_mtime_ns)==(row['bytes'],row['mtime_ns']),'Source stat changed')
    need(flat['scalar_checks']==192 and flat['earlier_frozen_arrays_exact'] and dark['stock_locked_values_exact'],'Reference checks failed')
    kit=check_kit(ROOT/'outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09')
    original=ROOT/'firmware/original/Z_6_0380.bin'
    need(file_sha(original)=='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54','Original changed')
    previous=[]
    for relative in ('analysis/spatial-preflash-2026-11-09/evidence-index.json','analysis/modified2-flat-2026-11-09/evidence-index.json'):
        value=read(ROOT/relative)
        for row in value['files']:need(file_sha(ROOT/row['path'])==row['sha256'],'Previous evidence changed')
        previous.append(dict(index=relative,files=len(value['files'])))
    for row in read(ROUND/'figures/result.json')['figures']:need(file_sha(ROOT/row['path'])==row['sha256'],'Figure changed')
    for name in SCRIPTS:ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf8'))
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if not link.startswith('https:'):need((REPORT.parent/link).is_file(),'Broken report link: '+link)
    for row in read(ROUND/'progress-update/changes.json')['changes']:
        need(file_sha(ROOT/row['path'])==row['after_sha256'] and file_sha(ROOT/row['before']['path'])==row['before']['sha256'],'Progress changed')
    commands=[]
    for path in sorted((ROUND/'commands').glob('*/command.json')):
        v=read(path)
        if 'exit_code' not in v:continue
        need(v['exit_code']==(1 if path.parent.name=='07-dark-analysis' else 0),'Unexpected command failure')
        commands.append(dict(name=path.parent.name,exit_code=v['exit_code']))
    status=subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True)
    (ROUND/'git-status-after.txt').write_bytes(status.stdout)
    write(ROUND/'verification.json',dict(ok=True,source_files_unchanged=len(sources),source_hashes=sources,
       original=record(original),kit=kit,prior_frozen=previous,independent_new_pixels=146991360,
       scalar_checks=192,report=record(REPORT),commands=commands,
       recorded_failure='07 incorrectly required the historical capped stock f/22 frame to be f/1.8; corrected reference check, no source or firmware edit.',
       physical_spatial_parameter_feedback=True,local_dark_regression=True,ring_removal=False,new_firmware_created=False))
    print(json.dumps(dict(ok=True,source_files=len(sources),prior_frozen=previous)))

def index():
    need(read(ROUND/'verification.json')['ok'],'Verification required')
    out=ROUND/'script-snapshots';out.mkdir(exist_ok=False)
    for name in SCRIPTS:(out/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    out=ROUND/'document-snapshots';out.mkdir(exist_ok=False)
    for name in ('docs/MODIFIED3_REAL_NEF_2026-11-09.md','README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md'):
        (out/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    commands=[dict(name=p.parent.name,**read(p)) for p in sorted((ROUND/'commands').glob('*/command.json'))]
    for row in commands:need(row.get('exit_code')==(1 if row['name']=='07-dark-analysis' else 0),'Unfinished/unexpected command')
    write(ROUND/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
         files=[record(p) for p in sorted(ROUND.rglob('*')) if p.is_file()],commands=commands,
         status='Confirmed physical modified3 comparison: spatial fields neutral, dark suppression benefit retained, broad colour rings remain.'))
    print(json.dumps(dict(files=len(read(ROUND/'evidence-index.json')['files']),commands=len(commands))))

if __name__=='__main__':
    {'assess':assess,'progress':progress,'verify':verify,'index':index}[sys.argv[1]]()

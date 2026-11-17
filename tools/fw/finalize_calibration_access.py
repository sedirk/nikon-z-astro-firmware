"""Update project progress, verify preservation and freeze the real calibration round."""
from pathlib import Path
import ast,datetime,hashlib,json,re,subprocess,sys
from finalize_front_calibration import FW as BASE_FW
from finalize_modified5_recovery import PRIOR as OLD_PRIOR
from verify_modified5_recovery import REVOKED,check_kit
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'analysis/raw-calibration-access-2026-11-10'
REPORT=ROOT/'docs/RAW_CALIBRATION_ACCESS_2026-11-10.md'
FW=dict(BASE_FW,**{'firmware/decoded/ex1620_037000.bi':'72f1fb29e24b36b872eec697a486abeff8bcef77f6020fa89473fd014aa18131'})
DOCS=['README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md','docs/RAW_CALIBRATION_ACCESS_2026-11-10.md',
      'docs/Z6_MENU_OFF_BASELINE_2026-11-10.txt']
SCRIPTS=['trace_z6_ptp_tables.py','probe_z6_calibration_reader.py','inspect_native.py','z6_wpd_cal_probe.cpp',
    'build_z6_cal_probe.py','z6_wpd_cal_session.cpp','z6_wpd_inventory.cpp','probe_z6_service_boundary.py',
    'inspect_z6_companion_data.py','probe_z6_companion_service.py','analyze_real_calibration.py',
    'probe_real_calibration_front.py','summarize_real_calibration.py','finalize_calibration_access.py',
    'record_research_command.py','probe_raw_candidates.py']
FAILURES={
 '12-native-cal-reader':(1,'Incorrect initial selector expectation; corrected to0=CAL38,1=ID35.'),
 '14-native-cal-reader-v2':(1,'ID0b storage runtime absent in private fixture; selectors4/5 explicitly outside tested read scope.'),
 '15-service-resource-loader':(2,'Unsupported --xref argument; subsequent invocation used --literal.'),
 '50-camera-calibration-backup':(1,'Windows rejected F001/F002 command access with80070057; subsequent gate probeA004. Buildv3 corrected fixed mode-command access and session54 succeeded.'),
 '57-real-calibration-native-front':(1,'Test wrongly expected real normal-record gate1; actual index3 is0. Revised case checks actual selected field and descriptor retention.')}
def read(p):return json.loads(Path(p).read_text(encoding='utf8'))
def sha(b):return hashlib.sha256(b).hexdigest()
def rec(p):return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=sha(p.read_bytes()))
def write(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,ensure_ascii=False,indent=2),encoding='utf8')

def progress():
    summary=read(OUT/'real-calibration-summary/result.json');assert summary['ok']
    changes=[]
    for name in DOCS[:3]:
        p=ROOT/name;old=p.read_bytes();backup=OUT/'progress-before'/name.replace('/','-')
        assert old==backup.read_bytes(),'Concurrent progress change: '+name
        text=old.decode('utf8').replace('\r\n','\n');title,body=text.split('\n',1)
        prefix='docs/' if name=='README.md' else ''
        new=(f'\n\n**2026-11-10 最新：已从本机实际备份CAL38和ID35，共2.25 MiB；144块各读取两遍一致，原厂服务状态成功退出，随后USB身份读取正常。** '
          f'未发送固件或标定写入命令。真实CAL显示静态ID35控制为1，定长数据是6104对围绕600变化的u16；33×4在部分模式为17行非零＋16行零，在另一些模式为全16384。'
          f'24组真实资源副本原生执行通过，记录+18和+1a各自只改变20068700或20068704，ID35传输保持。下一步核实这两项独立控制的硬件作用，再收窄静态单变量候选。'
          f'[本轮报告]({prefix}RAW_CALIBRATION_ACCESS_2026-11-10.md)。\n\n'
          f'**当前实机与交付状态：用户已确认恢复，modified5保持撤回；本轮没有新增可刷文件或NEF。** '
          f'原固件、modified1–4及已验证暗场补丁保留。菜单三项（暗角、自动失真、衍射补偿）此前开启、现均关闭是用户已确认的基线变化；'
          f'后续采用固定布置的“恢复后的modified4＋三项关闭”对照，见[步骤]({prefix}Z6_MENU_OFF_BASELINE_2026-11-10.txt)。'
          f'最后实拍暗场回归通过仍为modified3；modified4新dark待样本。\n')
        if name=='docs/NEXT_STEPS.md':
            new+=('\n当前执行顺序：\n\n'
              '1. 以新取得的真实CAL38/ID35替代零标定夹具，追查20068700/704及表体的像素作用；分别处理记录+18、+1a，不同时改动。\n'
              '2. 优先保留ID35原始门控、数据提交和完成事件，静态候选限定1017d7f0；不复用modified5跳过必要传输的方案。\n'
              '3. 核实16384的硬件单位/旁路条件以及表行索引的空间或信号域。17行非零不直接当作半径曲线，围绕600的定长数据暂列列基线假设。\n'
              '4. 单变量副本完成真实非零参数、静态/取景交替、错误处理、NEF保存与回退审查后再提供新测试包；实拍单独检查彩圈和112点暗场回归。\n')
        p.write_bytes((title+new+'\n以下为前轮历史记录；旧候选放行与待读取状态以本节为准。\n'+body).encode('utf8'))
        changes.append(dict(path=name,before_sha256=sha(old),after_sha256=sha(p.read_bytes())))
    write(OUT/'progress-changes.json',dict(changes=changes))
    write(OUT/'backup-manifest.json',dict(resources=summary['resources'],chunk_bytes=16384,matching_reads_per_chunk=2,
        origin='Camera runtime resources loaded by native service entry; not direct raw flash dump.',
        session='camera-calibration-backup-v3',exited=True,gate_closed=True,post_exit_inventory_ok=True,
        operation_access='Device GENERIC_READ|GENERIC_WRITE for fixed no-data F001/F002; F029 data retrieval uses read IOCTL.',
        data_or_firmware_write_requested=False,session_exe_sha256=read(OUT/'wpd-cal-session-build-v3/build.json')['exe_sha256']))
    write(OUT/'candidate-status.json',dict(new_flash_candidate=False,modified5='recalled; keep recovery to exact modified4',
        real_calibration_backup_complete=True,hardware_nef_test_this_round=False,
        verified=[dict(source='CAL38+0x5e0',actual_byte=1,target='0x2006103c'),
          dict(source='selected33x4 record+0x18',actual_static_byte=1,target='0x20068700'),
          dict(source='selected33x4 record+0x1a',actual_static_byte=1,target='0x20068704')],
        next_candidate_scope='static call0x1017d7f0; one variable; preserve ID35 and required completion/error handling',
        unresolved=['Hardware operation of20068700/704','Physical domain of33x4 indices','Q14 unity interpretation',
                    'Exact ID35 arithmetic','Full real shutter error causality','Final saved NEF ring benefit'],
        dark_patch='Three established instructions preserved; latest real dark regression modified3',
        menus='User reports vignette/auto-distortion/diffraction previouslyON, nowOFF; new fixed-geometry baseline required'))
    write(OUT/'external-source-notes.json',dict(primary_basis='Pinned stock firmware and logged responses from connected Z6.',
        windows_transport_sources=[
          'https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-execute-command-without-data-phase',
          'https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-execute-command-with-data-to-read',
          'https://learn.microsoft.com/en-us/windows-hardware/drivers/portable/handling-access-control'],
        public_search_scope='Targeted Nikon F001/F029 queries did not provide independent Z6-specific command semantics; no global absence claim.'))
    print(json.dumps(dict(ok=True,updated_documents=len(changes),backup_resources=len(summary['resources']))))

def verify():
    assert not (OUT/'verification.json').exists()
    for path,h in FW.items():assert sha((ROOT/path).read_bytes())==h,path
    recalled=ROOT/'analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED'
    assert sha(recalled.read_bytes())==REVOKED
    kit=check_kit(ROOT/'outputs/Z6-C380-recovery-from-modified5-2026-11-10')
    prior=[]
    for name in [*OLD_PRIOR,'modified5-failure-2026-11-10','raw-front-completion-2026-11-10']:
        index=read(ROOT/'analysis'/name/'evidence-index.json')
        for row in index['files']:assert sha((ROOT/row['path']).read_bytes())==row['sha256'],row['path']
        prior.append(dict(folder=name,files=len(index['files'])))
    photos=read(ROOT/'analysis/modified4-real-2026-11-09/verification.json')['source_hashes']
    for path,h in photos.items():assert sha(Path(path).read_bytes())==h,path
    build=read(OUT/'wpd-cal-session-build-v3/build.json');assert build['ok']
    for name,h in build['source_sha256'].items():
        assert sha((OUT/'wpd-cal-session-build-v3'/name).read_bytes())==h
        assert sha((ROOT/'tools/fw'/name).read_bytes())==h
    assert sha((OUT/'wpd-cal-session-build-v3/z6_wpd_cal_session.exe').read_bytes())==build['exe_sha256']
    assert read(OUT/'cal-session-allowlist-v3/result.json')==dict(ok=True,cases=14,camera_opened=False,commands_sent=0)
    session=read(OUT/'camera-calibration-backup-v3/result.json')
    assert session['ok'] and session['exit_succeeded'] and session['gate_closed'] and session['read_commands']==289
    assert not session['firmware_or_calibration_write_requested']
    summary=read(OUT/'real-calibration-summary/result.json');assert summary['ok'] and summary['chunks']==144
    for r in summary['resources']:
        p=OUT/'camera-calibration-backup-v3'/(r['name']+'.bin')
        assert p.stat().st_size==r['bytes'] and sha(p.read_bytes())==r['sha256']
    for name in ('native-cal-reader-v4','native-service-boundary','companion-native-ingress','real-calibration-profile'):
        assert read(OUT/name/'result.json')['ok']
    reader=read(OUT/'native-cal-reader-v4/result.json')
    assert len(reader['reader_cases'])==30 and len(reader['gate_cases'])==4 and len(reader['dispatch'])==71
    native=read(OUT/'real-calibration-native-front-v2/result.json')
    assert native['ok'] and len(native['rows'])==24 and len(native['counterfactuals'])==12
    # Independently compare complete write sequences, not only final register maps.
    for row in native['rows']:
        if row['mutation']=='none':continue
        base=next(b for b in native['rows'] if b['firmware']==row['firmware'] and b['configuration']==row['configuration'] and b['mutation']=='none')
        assert len(base['writes'])==len(row['writes'])
        diff=[(x,y) for x,y in zip(base['writes'],row['writes']) if x!=y]
        assert len(diff)==1
        x,y=diff[0];target='0x20068700' if row['mutation']=='header18_zero' else '0x20068704'
        assert x['address']==y['address']==target and x['value']==1 and y['value']==0
        assert x['size']==y['size'] and x['pc']==y['pc']
        assert base['early_writes']==row['early_writes'] and base['table_sha256']==row['table_sha256']
    for name in SCRIPTS:
        assert (ROOT/'tools/fw'/name).exists(),name
        if name.endswith('.py'):ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf8'))
    for r in read(OUT/'progress-changes.json')['changes']:assert sha((ROOT/r['path']).read_bytes())==r['after_sha256']
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if link.startswith('https:'):continue
        p=(REPORT.parent/link).resolve()
        if p not in (OUT/'verification.json',OUT/'evidence-index.json'):assert p.exists(),link
    commands=[]
    for p in sorted((OUT/'commands').glob('*/command.json')):
        c=read(p)
        if 'exit_code' not in c:continue
        expected,reason=FAILURES.get(p.parent.name,(0,None));assert c['exit_code']==expected,p
        commands.append(dict(name=p.parent.name,exit_code=c['exit_code'],classification=reason))
    diff=subprocess.run(['git','diff','--check'],cwd=ROOT,capture_output=True)
    (OUT/'git-diff-check.txt').write_bytes(diff.stdout+diff.stderr);assert diff.returncode==0
    (OUT/'git-status-after.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    write(OUT/'verification.json',dict(ok=True,preserved_firmware=FW,recalled_sha256=REVOKED,recovery_kit=kit,
        prior_frozen=prior,prior_frozen_file_count=sum(r['files'] for r in prior),photo_source_hashes=photos,
        actual_backup_resources=summary['resources'],cal_session_build=build,original_calibration_files_preserved=True,
        native_front_cases=24,single_field_full_write_comparisons=12,native_reader_cases=30,native_gate_cases=4,
        commands=commands,failures_preserved=FAILURES,photo_or_flash_action=False,git_commit=False))
    print(json.dumps(dict(ok=True,prior_frozen_files=sum(r['files'] for r in prior),photos=len(photos),native_front_cases=24)))

def freeze():
    assert read(OUT/'verification.json')['ok'] and not (OUT/'evidence-index.json').exists()
    (OUT/'script-snapshots').mkdir(exist_ok=False);(OUT/'document-snapshots').mkdir(exist_ok=False)
    for name in SCRIPTS:(OUT/'script-snapshots'/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    for name in DOCS:(OUT/'document-snapshots'/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    commands=[]
    for p in sorted((OUT/'commands').glob('*/command.json')):
        c=read(p);assert c.get('exit_code')==FAILURES.get(p.parent.name,(0,''))[0],p
        commands.append(dict(name=p.parent.name,**c))
    files=[rec(p) for p in sorted(OUT.rglob('*')) if p.is_file()]
    write(OUT/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        freeze_argv=sys.argv,files=files,commands=commands,
        status='Actual CAL38/ID35 backup verified twice per chunk; native service exited. Real calibration frontend replay and two isolated control candidates; no new flash or NEF.'))
    print(json.dumps(dict(ok=True,frozen_files=len(files),commands=len(commands),classified_failures=len(FAILURES))))
if __name__=='__main__':
    assert len(sys.argv)==2 and sys.argv[1] in ('progress','verify','freeze')
    globals()[sys.argv[1]]()

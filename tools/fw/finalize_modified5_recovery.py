"""Finish the recalled-modified5 incident and exact-byte recovery delivery."""
from pathlib import Path
import ast,datetime,json,re,subprocess,sys,zipfile
from record_modified5_failure import ROOT,ROUND,KIT,OLD,NEW,BASE,sha,write,rec
from verify_modified5_recovery import DIGESTS,REVOKED,check_kit,need
from finalize_front_calibration import FW

REPORT=ROOT/'docs/MODIFIED5_FAILURE_RECOVERY_2026-11-10.md'
DOCS=['README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md',
      'docs/MODIFIED5_FAILURE_RECOVERY_2026-11-10.md','docs/Z6_MODIFIED5_RECOVERY_2026-11-10.txt',
      'docs/Z6_ID35_INSTALL_2026-11-09.txt','docs/Z6_ID35_FLAT_COMPARE_2026-11-09.txt','docs/ID35_PREFLASH_REVIEW_2026-11-09.md']
SCRIPTS=['record_modified5_failure.py','withdraw_modified5.py','verify_modified5_recovery.py',
         'test_modified5_recovery_verifier.py','probe_modified5_completion.py','probe_modified5_error_status.py',
         'finalize_modified5_recovery.py','package_id35_preflash.py','inspect_native.py','record_research_command.py',
         'probe_raw_candidates.py','finalize_front_calibration.py']
PRIOR=['id35-preflash-2026-11-09','raw-fixed-operators-2026-11-09','raw-spatial-identity-2026-11-09',
       'raw-front-calibration-2026-11-09','modified4-real-2026-11-09','modified3-real-2026-11-09','raw-front-owner-2026-11-09']


def read(path):return json.loads(Path(path).read_text(encoding='utf8'))


def prepare():
    need(not (ROUND/'delivery-status.json').exists(),'Already prepared')
    need(read(ROUND/'native-completion/result.json')['ok'],'Completion diagnosis failed')
    need(read(ROUND/'native-error-status/result.json')['ok'],'Error consumer diagnosis failed')
    need(read(ROUND/'verifier-tests/result.json')['ok'],'Verifier checks failed')
    changes=[]
    for name in DOCS[:3]:
        p=ROOT/name;before=p.read_bytes();text=before.decode('utf8')
        link='docs/MODIFIED5_FAILURE_RECOVERY_2026-11-10.md' if name=='README.md' else 'MODIFIED5_FAILURE_RECOVERY_2026-11-10.md'
        insertion=f'\n本轮已完成精确回退恢复包、24组完成事件路径和8组错误上报原生诊断、26项校验器正反例；修改后的ID35关闭方案保持撤回。用户确认机械快门、更新菜单可用、尚未回退。实际恢复待用户确认。[故障与恢复报告]({link})。\n'
        marker='以下为历史状态。\n';need(marker in text,'Recall heading missing')
        text=text.replace(marker,marker+insertion,1)
        if name.endswith('NEXT_STEPS.md'):
            insertion='\n当前动作：先恢复modified4并确认单张NEF正常；继续追踪2006103c/ID35描述符与完成事件8的关系、真实CAL内容。0x20到上层事件0x041f0181子码8的路径已确认，实机错误来源待定位。新候选不跳过保护、超时或错误上报，也不靠原样复跑一次通过放行。\n'
            text=text.replace(marker,marker+insertion,1)
        p.write_bytes(text.encode('utf8'));changes.append(dict(path=name,before_sha256=sha(before),after_sha256=sha(p.read_bytes())))
    for name in DOCS[5:]:
        p=ROOT/name;before=p.read_bytes();backup=ROUND/'progress-before'/name.replace('/','-')
        need(not backup.exists(),'Backup exists');backup.write_bytes(before)
        notice='2026-11-10：本文对应的modified5已因机械快门卡住、Err／重启循环撤回。以下仅为历史记录，不再执行安装或实拍步骤。请使用 Z6_MODIFIED5_RECOVERY_2026-11-10.txt 恢复说明；本次诊断见 MODIFIED5_FAILURE_RECOVERY_2026-11-10.md。\n\n'
        if p.suffix=='.md':notice='> '+notice
        p.write_bytes(notice.encode('utf8')+before);changes.append(dict(path=name,before_sha256=sha(before),after_sha256=sha(p.read_bytes())))
    write(ROUND/'progress-changes.json',dict(changes=changes))
    incident=read(ROUND/'incident.json');need(incident['user_clarification']['shutter']=='mechanical','Missing user clarification')
    update=read(ROOT/'analysis/id35-preflash-2026-11-09/updater/result.json')
    inherited_files=[x for x in update['file_checks'] if x.get('label') in ('test_accepts_modified4','test_accepts_modified1','test_accepts_stock')]
    inherited_schedules=[x for x in update['scheduler'] if x.get('label') in ('test_to_modified4','test_to_modified1','test_to_stock')]
    need(len(inherited_files)==len(inherited_schedules)==3,'Missing exact-hash rollback evidence')
    for x in inherited_files:need(x['sha256']==DIGESTS[x['target']] and x['integrity_return']==0,'Update evidence hash/status')
    for x in inherited_schedules:need(x['rom_sha256']==REVOKED and x['prefix_preserved'] and x['tail_canary_preserved'],'Schedule evidence')
    write(ROUND/'inherited-rollback-evidence.json',dict(
        scope='Previously completed native checks reused because all running/target hashes are identical. Not rerun this round; not physical flash.',
        source=rec(ROOT/'analysis/id35-preflash-2026-11-09/updater/result.json'),
        file_checks=[{k:x[k] for k in ('label','sha256','integrity_return','size','running_rom','target')} for x in inherited_files],
        scheduler=[{k:x[k] for k in ('label','rom_sha256','input_sha256','erase_service_calls','program_service_calls','prefix_preserved','tail_canary_preserved')} for x in inherited_schedules]))
    write(ROUND/'sources.json',dict(accessed_local_date='2026-11-10',sources=[dict(
        title='Nikon Z7/Z6 Indicators and Error Messages',
        url='https://onlinemanual.nikonimglib.com/z7_z6/en/13_troubleshooting_02.html',
        use='Err guidance only; persistent or frequent faults require authorized service. Does not validate modified firmware, same-version updates or this hardware-cause hypothesis.')]))
    status=dict(status='MODIFIED5_RECALLED_EXACT_MODIFIED4_RECOVERY',revoked_sha256=REVOKED,
        default_recovery_sha256=DIGESTS['modified4'],mechanical_shutter_reported=True,menu_available=True,
        physical_recovery_confirmed=False,new_ring_candidate=False,original_firmware_preserved=True,
        dark_patch_bytes_preserved=True,last_physical_dark_regression='modified3',
        completion_native_cases=24,error_consumer_native_cases=8,verifier_cases=26,
        facts=['Exact modified4 recovery reverses every modified5 edit.',
               'Native callback bit 0x10 produces completion-event bit 8.',
               'Missing event 8 produces local status 0x20 in the tested native branch.',
               'Native error consumer encodes status 0x20 as event 0x041f0181 subtype 8.'],
        hypothesis='ID35 forced-zero and skipped descriptor may violate physical frontend completion dependencies; shared dispatcher coverage/timing and true calibration state also remain open.',
        limitations=['No physical internal status trace or hardware-cause proof.',
                    'Artificial interrupt/RTOS services do not emulate capture or pixel processing.',
                    'Recovery is not an additional ring-removal result.'])
    write(ROUND/'delivery-status.json',status)
    for source,target in (('tools/fw/verify_modified5_recovery.py','verify.py'),('docs/Z6_MODIFIED5_RECOVERY_2026-11-10.txt','START_HERE.txt')):
        (KIT/target).write_bytes((ROOT/source).read_bytes())
    (KIT/'REVIEW.txt').write_bytes(('2026-11-10 modified5撤回及恢复审查\n\n'
        '恢复文件：从modified5完整反向撤销四处新增改动并重算CRC，逐字节等同原modified4；保留原有十处改动和暗场补丁。\n'
        '离线核验：三份恢复文件固定SHA-256和CRC；26项校验器正反例；24组完成事件和8组错误上报原生代码诊断。\n'
        '实机状态：用户报告modified5机械快门Err/重启，更新菜单可用；恢复结果待用户确认。\n'
        '完成事件缺失到0x20再到上层子码8的代码路径已定位；真实ID35硬件因果尚待定位，不把人工中断注入当作实机复现。\n'
        '本包用于恢复拍摄，不增加新的消圈尝试。不改动快门保护、等待或错误上报。\n'
        f"完整项目记录：{(ROOT / 'docs/MODIFIED5_FAILURE_RECOVERY_2026-11-10.md').as_posix()}\n"
        f"日志：{(ROOT / 'analysis/modified5-failure-2026-11-10').as_posix()}/\n").encode('utf8'))
    manifest=read(KIT/'manifest.json');manifest.update(incident_status=status,files=[dict(path=p.relative_to(KIT).as_posix(),sha256=sha(p.read_bytes()),bytes=p.stat().st_size) for p in sorted(KIT.rglob('*')) if p.is_file() and p.name not in ('manifest.json','delivery-files.json')])
    write(KIT/'manifest.json',manifest)
    write(KIT/'delivery-files.json',dict(files=[dict(path=p.relative_to(KIT).as_posix(),sha256=sha(p.read_bytes()),bytes=p.stat().st_size) for p in sorted(KIT.rglob('*')) if p.is_file() and p.name!='delivery-files.json']))
    check_kit(KIT);print(json.dumps(dict(ok=True,status=status['status'])))


def archive():
    check_kit(KIT);target=KIT.with_suffix('.zip');need(not target.exists(),'Archive exists')
    files=sorted(p for p in KIT.rglob('*') if p.is_file())
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in files:z.write(p,p.relative_to(KIT).as_posix())
    with zipfile.ZipFile(target) as z:
        need(z.testzip() is None,'ZIP CRC failed')
        need(set(z.namelist())=={p.relative_to(KIT).as_posix() for p in files},'ZIP file list')
        for p in files:need(z.read(p.relative_to(KIT).as_posix())==p.read_bytes(),'ZIP byte mismatch')
    write(ROUND/'zip-verification.json',dict(ok=True,archive=rec(target),files=len(files),all_entries_identical=True))
    print(json.dumps(dict(ok=True,archive=str(target),files=len(files))))


def verify():
    checked=check_kit(KIT)
    for p,h in FW.items():need(sha((ROOT/p).read_bytes())==h,'Preserved firmware drift '+p)
    moved=read(ROUND/'recall.json')['moves']
    for row in moved:
        need(not (ROOT/row['old_path']).exists(),'Recalled file remains active')
        need(sha((ROOT/row['new_path']).read_bytes())==row['sha256'],'Quarantine drift')
    failed=(ROOT/moved[0]['new_path']).read_bytes();restored=(KIT/'01_RECOVER_MODIFIED4/EG162080.BIN').read_bytes()
    allowed={len(failed)-2,len(failed)-1}
    for pc,old,new in NEW:
        off=pc-BASE;need(restored[off:off+len(bytes.fromhex(old))]==bytes.fromhex(old),'Not reversed')
        allowed.update(range(off,off+len(bytes.fromhex(new))))
    differences=[i for i,(a,b) in enumerate(zip(failed,restored)) if a!=b]
    need(len(differences)==53 and set(differences)<=allowed,'Unexpected recovery difference')
    prior=[]
    for name in PRIOR:
        index=read(ROOT/'analysis'/name/'evidence-index.json')
        for row in index['files']:need(sha((ROOT/row['path']).read_bytes())==row['sha256'],'Frozen evidence drift '+row['path'])
        prior.append(dict(folder=name,files=len(index['files'])))
    photos=read(ROOT/'analysis/modified4-real-2026-11-09/verification.json')['source_hashes']
    for p,h in photos.items():need(sha(Path(p).read_bytes())==h,'Photo drift '+p)
    for source,target in (('tools/fw/verify_modified5_recovery.py','verify.py'),('docs/Z6_MODIFIED5_RECOVERY_2026-11-10.txt','START_HERE.txt')):
        need((ROOT/source).read_bytes()==(KIT/target).read_bytes(),'Delivery copy drift')
    for row in read(KIT/'delivery-files.json')['files']:need(sha((KIT/row['path']).read_bytes())==row['sha256'],'Kit manifest drift')
    for name in SCRIPTS:ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf8'))
    for row in read(ROUND/'progress-changes.json')['changes']:need(sha((ROOT/row['path']).read_bytes())==row['after_sha256'],'Progress drift')
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if link.startswith('https:'):continue
        p=(REPORT.parent/link).resolve()
        if p not in (ROUND/'verification.json',ROUND/'evidence-index.json'):need(p.exists(),'Broken report link '+link)
    native=read(ROUND/'native-completion/result.json');errors=read(ROUND/'native-error-status/result.json');tests=read(ROUND/'verifier-tests/result.json')
    need(native['ok'] and len(native['cases'])==24 and errors['ok'] and len(errors['cases'])==8,'Native diagnosis')
    need(tests['ok'] and len(tests['cases'])==26,'Verifier test results')
    z=read(ROUND/'zip-verification.json');need(z['ok'] and sha(KIT.with_suffix('.zip').read_bytes())==z['archive']['sha256'],'ZIP drift')
    commands=[]
    for p in sorted((ROUND/'commands').glob('*/command.json')):
        c=read(p)
        if 'exit_code' not in c:continue
        need(c['exit_code']==0,'Unclassified command failure '+p.parent.name)
        commands.append(dict(name=p.parent.name,exit_code=c['exit_code']))
    diff=subprocess.run(['git','diff','--check'],cwd=ROOT,capture_output=True)
    (ROUND/'git-diff-check.txt').write_bytes(diff.stdout+diff.stderr);need(diff.returncode==0,'Whitespace error')
    (ROUND/'git-status-after.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    write(ROUND/'verification.json',dict(ok=True,kit=checked,preserved_firmware=FW,
        recovery_changed_bytes=53,reverted_code_bytes=51,reverted_crc_bytes=2,
        prior_frozen=prior,photo_source_hashes=photos,quarantine=moved,native_completion_cases=24,
        native_error_consumer_cases=8,verifier_cases=26,zip=z['archive'],commands=commands,
        physical_recovery_confirmed=False,new_flash_candidate=False,card_accessed=False,git_commit=False))
    print(json.dumps(dict(ok=True,prior_frozen_files=sum(x['files'] for x in prior),photos=len(photos),verifier_cases=26)))


def index():
    need(read(ROUND/'verification.json')['ok'],'Verification pending')
    scripts=ROUND/'script-snapshots';scripts.mkdir(exist_ok=False)
    for name in SCRIPTS:(scripts/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    docs=ROUND/'document-snapshots';docs.mkdir(exist_ok=False)
    for name in DOCS:(docs/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    commands=[dict(name=p.parent.name,**read(p)) for p in sorted((ROUND/'commands').glob('*/command.json'))]
    need(all(x.get('exit_code')==0 for x in commands),'Incomplete or failed recorded command')
    files=[rec(p) for p in sorted(ROUND.rglob('*')) if p.is_file()]
    need(not (ROUND/'evidence-index.json').exists(),'Already frozen')
    write(ROUND/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
        files=files,commands=commands,manifest=rec(KIT/'manifest.json'),archive=rec(KIT.with_suffix('.zip')),
        status='Recalled modified5; exact modified4 recovery ready. Physical recovery confirmation and hardware cause remain pending.'))
    print(json.dumps(dict(ok=True,files=len(files),commands=len(commands),physical_recovery_confirmed=False)))


if __name__=='__main__':dict(prepare=prepare,archive=archive,verify=verify,index=index)[sys.argv[1]]()

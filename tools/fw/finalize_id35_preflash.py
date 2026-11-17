"""Document and freeze modified5 delivery while retaining the QEMU timeout."""
from pathlib import Path
import ast,datetime,json,re,subprocess,sys,zipfile
from review_id35_preflash import ROOT,ROUND,PREVIOUS,SOURCES
from verify_id35_preflash_kit import DIGESTS,need,sha,check_kit
from finalize_front_calibration import FW

KIT=ROOT/'outputs/Z6-C380-id35-static-reviewed-2026-11-09'
REPORT=ROOT/'docs/ID35_PREFLASH_REVIEW_2026-11-09.md'
FAILURES={'08-qemu-m5-shooting'}
SCRIPTS=['prepare_id35_preflash_tools.py','review_id35_preflash.py','verify_id35_preflash_kit.py',
    'probe_id35_preflash_updater.py','probe_id35_preflash_state.py','qemu_id35_preflash.py',
    'probe_id35_timeout_context.py','assess_id35_preflash.py','package_id35_preflash.py',
    'test_id35_preflash_verifier.py','finalize_id35_preflash.py','probe_raw_candidates.py',
    'probe_eg_update_route.py','probe_preflash_review.py','record_research_command.py','finalize_front_calibration.py']
DOCS=['README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md','docs/ID35_PREFLASH_REVIEW_2026-11-09.md',
      'docs/Z6_ID35_INSTALL_2026-11-09.txt','docs/Z6_ID35_FLAT_COMPARE_2026-11-09.txt']

def read(p):return json.loads(p.read_text(encoding='utf8'))
def write(p,x):p.write_bytes(json.dumps(x,ensure_ascii=False,indent=2).encode('utf8'))
def record(p):return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=sha(p.read_bytes()))

def progress():
    a=read(ROUND/'assessment.json');need(a['ok'],'No assessment')
    need(read(ROUND/'verifier-tests/result.json')['ok'],'Verifier negatives failed')
    check_kit(KIT)
    updates={
      'README.md':'''\n**2026-11-09 最新交付：modified5 ID35 静态单变量实验测试包。** 精确 LAB 字节完成原生文件检查、升级/回退调度及360阶段状态序列；33×4和既有暗场补丁保持。QEMU共6次，5次完成，候选首次等待超时的根因仍开放，失败与原样复跑均保留；因此本包供受控单张实拍，不作为稳定成品。附 modified4、仅暗场补丁版、原厂主模块回退及只读校验器。[审查报告](docs/ID35_PREFLASH_REVIEW_2026-11-09.md)、[安装说明](docs/Z6_ID35_INSTALL_2026-11-09.txt)、[平场对比](docs/Z6_ID35_FLAT_COMPARE_2026-11-09.txt)。当前实机效果仍以既有实拍为准；下一步固定布置A/B与112点暗场回归。以下保留历史状态。\n''',
      'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，modified5 实验测试包）\n\n目标保持：保留暗电流、关闭静态 NEF 写入前的 RAW 校正并消除彩圈。本轮交付 ID35 静态调用单变量 modified5，保留原固件、modified1–4、既有暗场补丁和33×4；离线文件/升级回退/状态检查完成。候选首次QEMU静态入口前等待超时、原样复跑通过的记录完整保留，根因仍开放。现在需要新候选真实NEF的固定布置平场、暗场、拍后取景恢复及重启验收；没有将模拟器算法或色条列为消圈成果。[报告](ID35_PREFLASH_REVIEW_2026-11-09.md)。\n''',
      'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，modified5 受控实拍）\n\n[本轮审查](ID35_PREFLASH_REVIEW_2026-11-09.md)与[安装说明](Z6_ID35_INSTALL_2026-11-09.txt)对应精确哈希 `76474a89…add0d2d7`；包在 `outputs/Z6-C380-id35-static-reviewed-2026-11-09/`。\n\n1. 刷前在当前modified4拍新的固定布置A；最小每版平场3张、ISO1600 5秒dark3张，建议加bias及多信号级慢快门组。保持光源、距离、角度、手动焦点不变；旧平场作历史参考。\n2. 核对完整包和卡上文件后，再按说明做modified5受控单张测试：普通NEF保存/回放，几次分开的单张后取景/拨轮，重启；正常后拍匹配B。照片放 `samples/11.9_modified5`，记录实际哈希和更新完成，避免版本误标。\n3. 新增ID35控制会保持零到下一次原生取景kind0配置；24条保留内存序列360阶段已验证恢复。实机调度与NEF写完后的状态仍单独验收。候选曾有一次目标调用前QEMU超时，同文件复跑通过、现场原生回放一致，根因继续保留为开放项。\n4. 默认回退modified4，另有仅暗场补丁版和stock；回退文件供更新菜单可用时使用，不是救砖机制。固定哈希校验器27项正反例通过；本轮未接触相机或卡。\n5. 比较真实RAW细环与宽颜色趋势，回归112点；实际像素算式和33×4身份继续追证据。若有一致收益再做必要回退复现，若无收益先确认真机原ID35控制是否非零，不叠加多个未知控制。\n\n以下保留此前计划。\n'''}
    changes=[]
    for name,addition in updates.items():
        p=ROOT/name;before=p.read_bytes();backup=ROUND/'progress-before'/name.replace('/','-')
        need(before==backup.read_bytes(),'Progress document changed concurrently '+name)
        head,tail=before.decode('utf8').replace('\r\n','\n').split('\n',1)
        p.write_bytes((head+'\n'+addition+tail).encode('utf8'))
        changes.append(dict(path=name,before_sha256=sha(before),after_sha256=sha(p.read_bytes())))
    write(ROUND/'progress-changes.json',dict(changes=changes))
    write(ROUND/'delivery-status.json',dict(status='EXPERIMENTAL_MODIFIED5_KIT_WITH_DISCLOSED_QEMU_TIMEOUT',
        candidate_sha256=DIGESTS['test'],kit=KIT.relative_to(ROOT).as_posix(),
        new_code_this_round=False,offline_update_checks_passed=True,
        qemu_attempts=6,qemu_completed=5,qemu_failed=1,unresolved_qemu_timeout=True,
        physical_modified5_boot=False,physical_modified5_nef=False,physical_dark_regression=False,ring_removal_verified=False,
        previous_physical_dark_regression='modified3',default_rollback='modified4',
        next='Matched real NEF flat/dark comparison and post-capture/liveview/reboot validation.'))
    print('Updated research status with the experimental delivery and unresolved timeout.')

def archive():
    check_kit(KIT);target=KIT.with_suffix('.zip');need(not target.exists(),'Archive already exists')
    files=sorted(p for p in KIT.rglob('*') if p.is_file())
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in files:z.write(p,p.relative_to(KIT).as_posix())
    with zipfile.ZipFile(target) as z:
        need(z.testzip() is None,'ZIP CRC failed')
        need(set(z.namelist())=={p.relative_to(KIT).as_posix() for p in files},'ZIP entries changed')
        for p in files:need(z.read(p.relative_to(KIT).as_posix())==p.read_bytes(),'ZIP content mismatch')
    write(ROUND/'zip-verification.json',dict(ok=True,archive=record(target),files=len(files),all_entries_identical=True))
    print(json.dumps(dict(ok=True,archive=str(target),bytes=target.stat().st_size,files=len(files))))

def verify():
    checked=check_kit(KIT)
    for p,h in FW.items():need(sha((ROOT/p).read_bytes())==h,'Preserved firmware changed '+p)
    for n,p in SOURCES.items():need(sha(p.read_bytes())==DIGESTS[n],'Source module changed')
    need(read(ROUND/'assessment.json')['ok'] and read(ROUND/'static/result.json')['ok'],'Assessment')
    need(read(ROUND/'updater/result.json')['ok'],'Updater')
    tests=read(ROUND/'verifier-tests/result.json');need(tests['ok'] and len(tests['cases'])==27,'Verifier test count')
    states=read(ROUND/'native-state/result.json');need(states['ok'] and states['source_hashes_unchanged'],'State source')
    need(read(ROUND/'timeout-context-replay/result.json')['ok'],'Timeout context')
    prior=[]
    for name in ('raw-fixed-operators-2026-11-09','raw-spatial-identity-2026-11-09','raw-front-calibration-2026-11-09',
                 'modified4-real-2026-11-09','modified3-real-2026-11-09','raw-front-owner-2026-11-09'):
        j=read(ROOT/'analysis'/name/'evidence-index.json')
        for row in j['files']:need(sha((ROOT/row['path']).read_bytes())==row['sha256'],'Frozen evidence changed '+row['path'])
        prior.append(dict(folder=name,files=len(j['files'])))
    sources=read(ROOT/'analysis/modified4-real-2026-11-09/verification.json')['source_hashes']
    for p,h in sources.items():need(sha(Path(p).read_bytes())==h,'Photo changed '+p)
    for name in SCRIPTS:ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf8'))
    for source,target in (('tools/fw/verify_id35_preflash_kit.py','verify.py'),
                         ('docs/ID35_PREFLASH_REVIEW_2026-11-09.md','REVIEW.md'),
                         ('docs/Z6_ID35_INSTALL_2026-11-09.txt','START_HERE.txt'),
                         ('docs/Z6_ID35_FLAT_COMPARE_2026-11-09.txt','FLAT_COMPARE.txt')):
        need((ROOT/source).read_bytes()==(KIT/target).read_bytes(),'Delivery copy drift '+source)
    allowed=set(DIGESTS.values())|set(FW.values())
    for p in (REPORT,ROOT/'docs/Z6_ID35_INSTALL_2026-11-09.txt'):
        for h in re.findall(r'\b[0-9a-f]{64}\b',p.read_text(encoding='utf8')):need(h in allowed,'Document digest typo')
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if link.startswith('https:'):continue
        p=(REPORT.parent/link).resolve()
        if p not in (ROUND/'verification.json',ROUND/'evidence-index.json'):need(p.exists(),'Broken report link '+link)
    for row in read(ROUND/'progress-changes.json')['changes']:
        need(sha((ROOT/row['path']).read_bytes())==row['after_sha256'],'Progress drift')
    zip_result=read(ROUND/'zip-verification.json');need(zip_result['ok'],'ZIP review')
    need(sha(KIT.with_suffix('.zip').read_bytes())==zip_result['archive']['sha256'],'ZIP drift')
    commands=[];failed=set()
    for p in sorted((ROUND/'commands').glob('*/command.json')):
        j=read(p)
        if 'exit_code' not in j:continue
        if j['exit_code']!=0:failed.add(p.parent.name)
        commands.append(dict(name=p.parent.name,exit_code=j['exit_code']))
    need(failed==FAILURES,'Unclassified command failures '+str(failed))
    diff=subprocess.run(['git','diff','--check'],cwd=ROOT,capture_output=True)
    (ROUND/'git-diff-check.txt').write_bytes(diff.stdout+diff.stderr);need(diff.returncode==0,'Whitespace errors')
    (ROUND/'git-status-after.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    write(ROUND/'verification.json',dict(ok=True,candidate_sha256=DIGESTS['test'],kit=checked,
        preserved_firmware=FW,source_hashes=sources,source_files_unchanged=len(sources),prior_frozen=prior,
        native_state_steps=360,invalid_selector_cases=8,timeout_context_pairs=2,updater_file_cases=9,scheduler_cases=6,
        qemu_attempts=6,qemu_completed=5,qemu_timeout_unresolved=True,verifier_cases=27,
        zip=zip_result['archive'],commands=commands,report=record(REPORT),
        physical_flash=False,new_physical_samples=False,physical_ring_removal=False,git_commit=False))
    print(json.dumps(dict(ok=True,prior_frozen_files=sum(x['files'] for x in prior),samples=len(sources),verifier_cases=27,unresolved_qemu_timeout=True)))

def index():
    need(read(ROUND/'verification.json')['ok'],'Verification pending')
    snap=ROUND/'script-snapshots';snap.mkdir(exist_ok=False)
    for name in SCRIPTS:(snap/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    snap=ROUND/'document-snapshots';snap.mkdir(exist_ok=False)
    for name in DOCS:(snap/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    commands=[dict(name=p.parent.name,**read(p)) for p in sorted((ROUND/'commands').glob('*/command.json'))]
    need(all(c.get('exit_code')==(1 if c['name'] in FAILURES else 0) for c in commands),'Incomplete command record')
    files=[record(p) for p in sorted(ROUND.rglob('*')) if p.is_file()]
    write(ROUND/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
        files=files,commands=commands,delivery_manifest=record(KIT/'manifest.json'),archive=record(KIT.with_suffix('.zip')),
        status='Experimental modified5 controlled-test delivery; one unresolved QEMU pre-target timeout retained. No new physical pixel outcome.'))
    print(json.dumps(dict(files=len(files),commands=len(commands),retained_failed_commands=len(FAILURES))))

if __name__=='__main__':dict(progress=progress,archive=archive,verify=verify,index=index)[sys.argv[1]]()

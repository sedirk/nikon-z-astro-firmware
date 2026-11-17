"""Update live progress, verify preservation, then freeze this evidence round."""
from pathlib import Path
import ast,datetime,hashlib,json,re,subprocess,sys
from finalize_front_calibration import FW
from finalize_modified5_recovery import PRIOR as OLD_PRIOR
from verify_modified5_recovery import REVOKED,check_kit
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'analysis/raw-front-completion-2026-11-10'
REPORT=ROOT/'docs/RAW_FRONT_COMPLETION_2026-11-10.md'
DOCS=['README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md',
      'docs/RAW_FRONT_COMPLETION_2026-11-10.md','docs/Z6_MENU_OFF_BASELINE_2026-11-10.txt']
SCRIPTS=['prepare_front_completion_round.py','scan_front_read_routes.py','z6_wpd_inventory.cpp',
    'build_z6_wpd_inventory.py','map_z6_usb_inventory.py','scan_z6_usb_dispatch.py',
    'probe_z6_irq_dispatch.py','summarize_front_completion.py','finalize_front_completion.py',
    'inspect_native.py','record_research_command.py','probe_raw_candidates.py',
    'probe_modified5_completion.py','verify_modified5_recovery.py']
FAILURES={'06-build-wpd-reader':(2,'Compiler missing SDK winrt include path; fixed in build 07.'),
    '08-camera-readonly-inventory':(1,'WPD list query denied without explicit FILE_READ_ACCESS option; fixed in 09/10 without write access.')}
def read(p):return json.loads(Path(p).read_text(encoding='utf8'))
def sha(b):return hashlib.sha256(b).hexdigest()
def rec(p):return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=sha(p.read_bytes()))
def write(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,ensure_ascii=False,indent=2),encoding='utf8')

def progress():
    assert not (OUT/'progress-changes.json').exists()
    changes=[]
    for name in DOCS[:3]:
        p=ROOT/name;old=p.read_bytes();backup=OUT/'progress-before'/name.replace('/','-')
        assert old==backup.read_bytes(),'Concurrent document change: '+name
        prefix='docs/' if name=='README.md' else ''
        title,body=old.decode('utf8').split('\n',1)
        current=(f'\n\n**2026-11-10 当前状态：用户已确认恢复拍摄；modified5 保持撤回。** '
          f'本轮成功以只读方式取得 Z6 / V3.80 和65个公开厂商命令，已与原厂ROM的65项数据表完全对应。'
          f'原生“注册→IRQ87→完成回调→静态等待”36组检查通过；确认现有QEMU未建模ID35配置与完成位的依赖，'
          f'后续候选优先保留必要传输和完成流程，继续追真正的校正控制。本轮未新增刷机文件，真实标定数据读取入口仍在核对。'
          f'[本轮报告]({prefix}RAW_FRONT_COMPLETION_2026-11-10.md)。\n\n'
          f'**菜单基线补充：用户报告此前暗角控制、自动失真控制、衍射补偿均开启，现在均已关闭。** '
          f'这次变化单独记录；旧NEF及分析保留，下一次固件比较先建立“恢复后的modified4＋三项关闭”新基线，'
          f'固定布置与焦点。参见[基线步骤]({prefix}Z6_MENU_OFF_BASELINE_2026-11-10.txt)。'
          f'最后通过的实拍暗场回归仍为modified3；modified4新5秒暗场待样本。\n')
        if name=='docs/NEXT_STEPS.md':
            current+=('\n当前执行顺序：\n\n'
              '1. 沿实机匹配的65项ROM命令表核实原生PTP处理函数，确定读取数据范围、长度和副作用后再使用标定读取入口。\n'
              '2. 优先取得真实CAL38/ID35记录或识别硬件消费者；将校正使能与必要传输/完成条件分开，保留33×4未知单位的审慎标注。\n'
              '3. 形成有依据的静态单变量副本，保留三处暗场补丁和全部保护/错误上报；不将跳过上传但人工产生完成事件的模型通过作为放行依据。\n'
              '4. 用三项关闭后的固定布置新基线验收最终NEF：分别检查细环/宽颜色趋势及112点暗场关系。原有照片仍作历史参考。\n')
        p.write_text(title+current+'\n以下为此前各轮原始记录；其中“待恢复”和旧候选放行状态以本节更新为准。\n'+body,encoding='utf8')
        changes.append(dict(path=name,before_sha256=sha(old),after_sha256=sha(p.read_bytes())))
    write(OUT/'progress-changes.json',dict(changes=changes))
    write(OUT/'external-search-notes.json',dict(queries=['Nikon "0x9520" firmware','Nikon "0x9533"','Nikon "0x9455"'],
        result='No new authoritative Z6 semantics from these searches; unrelated hits excluded. Primary pinned libgphoto2 symbols retained as limited source evidence.',
        no_inference_of_global_absence=True))
    print(json.dumps(dict(ok=True,progress_documents=len(changes))))

def verify():
    assert not (OUT/'verification.json').exists()
    for path,h in FW.items():assert sha((ROOT/path).read_bytes())==h,path
    recalled=ROOT/'analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED'
    assert sha(recalled.read_bytes())==REVOKED
    kit=ROOT/'outputs/Z6-C380-recovery-from-modified5-2026-11-10';kit_check=check_kit(kit)
    prior=[]
    for name in [*OLD_PRIOR,'modified5-failure-2026-11-10']:
        index=read(ROOT/'analysis'/name/'evidence-index.json')
        for row in index['files']:assert sha((ROOT/row['path']).read_bytes())==row['sha256'],row['path']
        prior.append(dict(folder=name,files=len(index['files'])))
    photos=read(ROOT/'analysis/modified4-real-2026-11-09/verification.json')['source_hashes']
    for path,h in photos.items():assert sha(Path(path).read_bytes())==h,path
    # Check the executed reader corresponds to current reviewed source.
    build=read(OUT/'wpd-reader-v3/build.json');assert build['ok']
    assert sha((ROOT/'tools/fw/z6_wpd_inventory.cpp').read_bytes())==build['source_sha256']
    assert sha((OUT/'wpd-reader-v3/z6_wpd_inventory.exe').read_bytes())==build['exe_sha256']
    inv=read(OUT/'camera-readonly-inventory-v2.json')
    assert inv['ok'] and inv['access']=='GENERIC_READ' and len(inv['vendor_opcodes'])==65
    assert inv['vendor_opcodes_executed']==[] and not inv['capture_or_flash_requested']
    native=read(OUT/'native-irq-dispatch/result.json')
    assert native['ok'] and len(native['cases'])==36 and native['identical_dispatch_for_stock_m4_m5']
    assert read(OUT/'usb-rom-table-match.json')['matches_current_camera_set']
    assert read(OUT/'model-completion-audit.json')['ok']
    state=read(OUT/'candidate-status.json');assert not state['new_flash_candidate']
    for name in SCRIPTS:
        if name.endswith('.py'):ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf8'))
    for row in read(OUT/'progress-changes.json')['changes']:assert sha((ROOT/row['path']).read_bytes())==row['after_sha256']
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if link.startswith('https:'):continue
        p=(REPORT.parent/link).resolve()
        if p not in (OUT/'verification.json',OUT/'evidence-index.json'):assert p.exists(),link
    commands=[]
    for p in sorted((OUT/'commands').glob('*/command.json')):
        c=read(p)
        if 'exit_code' not in c:continue  # current verification record completes after return
        expected,reason=FAILURES.get(p.parent.name,(0,None))
        assert c['exit_code']==expected,p
        commands.append(dict(name=p.parent.name,exit_code=c['exit_code'],classification=reason))
    diff=subprocess.run(['git','diff','--check'],cwd=ROOT,capture_output=True)
    (OUT/'git-diff-check.txt').write_bytes(diff.stdout+diff.stderr);assert diff.returncode==0
    (OUT/'git-status-after.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    write(OUT/'verification.json',dict(ok=True,preserved_firmware=FW,recalled_sha256=REVOKED,recovery_kit=kit_check,
        prior_frozen=prior,prior_frozen_file_count=sum(x['files'] for x in prior),photo_source_hashes=photos,
        readonly_identity_and_vendor_list=True,executed_vendor_opcodes=[],native_dispatch_cases=36,
        sources_preserved=True,commands=commands,failures_preserved=FAILURES,
        physical_recovery_user_reported=True,new_firmware_or_nef=False,git_commit=False))
    print(json.dumps(dict(ok=True,prior_frozen_files=sum(x['files'] for x in prior),photos=len(photos),native_cases=36)))

def freeze():
    assert read(OUT/'verification.json')['ok'] and not (OUT/'evidence-index.json').exists()
    scripts=OUT/'script-snapshots';scripts.mkdir(exist_ok=False)
    for name in SCRIPTS:(scripts/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    docs=OUT/'document-snapshots';docs.mkdir(exist_ok=False)
    for name in DOCS:(docs/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    commands=[]
    for p in sorted((OUT/'commands').glob('*/command.json')):
        c=read(p);assert c.get('exit_code')==FAILURES.get(p.parent.name,(0,''))[0],p
        commands.append(dict(name=p.parent.name,**c))
    files=[rec(p) for p in sorted(OUT.rglob('*')) if p.is_file()]
    write(OUT/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        freeze_argv=sys.argv,files=files,commands=commands,
        status='Recovered per user; native IRQ chain and real read-only USB inventory recorded. Three menu controls now OFF per user. No new flash image.'))
    print(json.dumps(dict(ok=True,frozen_files=len(files),commands=len(commands),classified_failures=len(FAILURES))))

if __name__=='__main__':dict(progress=progress,verify=verify,freeze=freeze)[sys.argv[1]]()

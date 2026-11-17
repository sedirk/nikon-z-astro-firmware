"""Preserve, verify and freeze the ID35 static-call LAB investigation."""
from pathlib import Path
import ast,binascii,datetime,hashlib,json,re,subprocess,sys
from finalize_front_calibration import FW
from review_id35_static_call_lab import EXPECTED,NEW,INHERITED,BASE

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-fixed-operators-2026-11-09'
REPORT=ROOT/'docs/RAW_FIXED_OPERATORS_2026-11-09.md'
RECIPE=ROOT/'patches/z6-c380-id35-static-call-off-lab.json'
LAB=OUT/'static-call-lab/modified4-id35-static-call-off-lab.bi'
FAILURES={'12-native-static-call-lab','13-native-static-call-v2','21-independent-lab-review'}
SCRIPTS=['scan_fixed_operator_candidates.py','prepare_id35_static_lab.py','audit_id35_temporary_scope.py',
    'prepare_id35_static_call_lab.py','probe_id35_static_call_lab.py','qemu_id35_static_call_watch.py',
    'review_id35_static_call_lab.py','finalize_fixed_operators.py','probe_raw_candidates.py',
    'verify_front_preflash_kit.py','inspect_native.py','record_research_command.py','finalize_front_calibration.py']

def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf8'))
def write(p,j):Path(p).write_bytes(json.dumps(j,ensure_ascii=False,indent=2).encode('utf8'))
def record(p):
    p=Path(p);b=p.read_bytes();return dict(path=p.relative_to(ROOT).as_posix(),bytes=len(b),sha256=sha(b))

def progress():
    snap=OUT/'progress-update';snap.mkdir(exist_ok=False)
    additions={
      'README.md':'''\n**2026-11-09 最新：ID35 静态调用专用 LAB 已生成，244 对原生差分通过。** 新增行为限于已定位的静态调用点，ID35 控制置零后跳过定长表提交，普通配置恢复原值；33×4 表及507次前端上传保持。原固件和暗场补丁保留。新副本尚未完成安装前审查，当前已交付测试包仍是 modified4；逐像素硬件运算和真实消圈效果另行验收。[本轮报告](docs/RAW_FIXED_OPERATORS_2026-11-09.md)、[候选状态](analysis/raw-fixed-operators-2026-11-09/candidate-status.json)。以下保留历史状态。\n''',
      'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，ID35 静态单变量候选）\n\n目标保持：保留暗电流、关闭静态 NEF 写入前的 RAW 校正并消除彩圈。已将 ID35 定长区的控制来源、原生零值条件和指定静态调用点接通，形成保留 modified4 全部既有补丁的 LAB 副本；244 对原生差分通过，33×4 保持。原固件、既有样本与旧冻结证据保留。当前验收是离线调用/内存/字节层，新哈希安装前审查和最终 NEF 彩圈、暗场回归分别推进。[报告](RAW_FIXED_OPERATORS_2026-11-09.md)。\n''',
      'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，ID35 静态调用 LAB）\n\n[本轮报告](RAW_FIXED_OPERATORS_2026-11-09.md)和[精确配方](../patches/z6-c380-id35-static-call-off-lab.json)已记录新的单变量副本。\n\n1. 对 SHA-256 `76474a89…add0d2d7` 的 ID35 静态调用 LAB 做完整安装前审查：新哈希原生升级/回退调度、启动/取景/静态交替、非目标调用与异常返回，再整理可刷包。当前文件仍是研究目录中的 LAB，未新增 modified5 安装包。\n2. 坚持一个新增功能变量：`10179d56` 的私有调用标记清零 ID35 控制；33×4、既有暗场及 modified2–4 补丁保持。仅用 context+84 判断的初版副本因作用范围较宽已淘汰，不能选错文件。\n3. 像素验证用固定布置的 modified4/新候选匹配平场，慢快门、多信号级、重复帧，分别比较细环和宽颜色结构；同时做 ISO1600 5秒暗场及 bias 的112点回归。历史平场位置/对焦可能变化，继续作为参考。\n4. 优先取得真实 CAL38 记录、ID35 定长区和原始控制状态，或硬件消费者的独立定义。现有证据确认控制写零和定长表提交条件，未命名具体逐像素算式。33×4 的单位表与通用关闭位仍不猜测。\n5. QEMU 中主 RAW 指针和指定参数前缀相同，后部七个地址样式字段不同，证据已保留。零 CAL 模型用于路径验证，真实 NEF 效果由实拍判定；最后一次新暗场实机回归仍是 modified3。\n\n以下保留此前计划。\n'''}
    changes=[]
    for name,add in additions.items():
        p=ROOT/name;before=p.read_bytes();(snap/(name.replace('/','-')+'.before')).write_bytes(before)
        text=before.decode('utf8').replace('\r\n','\n');head,tail=text.split('\n',1)
        p.write_bytes((head+'\n'+add+tail).encode('utf8'))
        changes.append(dict(path=name,before_sha256=sha(before),after_sha256=sha(p.read_bytes())))
    write(snap/'changes.json',dict(changes=changes))
    manifest=read(OUT/'static-call-lab/manifest.json')
    inherited=[dict(address=hex(pc),before=old,after=new) for pc,old,new in INHERITED]
    write(RECIPE,dict(status='OFFLINE_NATIVE_LAB_PASSED_NOT_INSTALL_KIT',
        base_firmware='firmware/decoded/eg1620_038000.bi',base_sha256=FW['firmware/decoded/eg1620_038000.bi'],
        parent=manifest['parent'],parent_sha256=manifest['parent_sha256'],
        module=LAB.relative_to(ROOT).as_posix(),sha256=EXPECTED,bytes=33502842,
        inherited_edits=inherited,new_edits=manifest['edits'],
        crc=dict(algorithm='CRC-HQX',initial=0,tail_byteorder='big',tail='bf8d',whole_residue=0),
        semantic_variable=manifest['semantic_variable'],
        scope='One observed static frontend call, not independently established NEF-format-exclusive or exhaustive camera-mode coverage.',
        instruction_change_bytes=51,crc_change_bytes=2,
        native_pairs=244,physical_pixels_verified=False,installation_review_complete=False))
    rejected=read(OUT/'lab-module/manifest.json')
    write(OUT/'lab-module/DISPOSITION.json',dict(status='REJECTED_SCOPE_TOO_BROAD_DO_NOT_INSTALL',
        reason='CTX+84 is shared by nine observed temporary set/clear paths; it is broader than the selected static call.',
        module=rejected['module'],sha256=rejected['sha256'],
        replacement=LAB.relative_to(ROOT).as_posix(),replacement_sha256=EXPECTED,
        original_experiment_preserved=True))
    write(OUT/'candidate-status.json',dict(status='OFFLINE_NATIVE_LAB_PASSED_NOT_INSTALL_KIT',
        selected_candidate=LAB.relative_to(ROOT).as_posix(),sha256=EXPECTED,recipe=RECIPE.relative_to(ROOT).as_posix(),
        baseline='modified4',static_call='0x10179d56',native_gate='0x2006103c',off_value=0,
        native_pairs=244,selector_domain=list(range(28))+[65535],selector_domain_test_calls=2048,
        table33x4_changed=False,front_upload_writes_equal=507,
        physical_ring_effect_verified=False,physical_dark_regression_for_this_hash=None,
        last_physical_dark_regression='modified3',new_physical_samples=False,
        hardware_pixel_formula=None,installation_review_complete=False,new_install_kit=False,
        next_actions=['Exact-hash native updater/rollback rehearsal and startup/live-view/static review.',
                      'Matched fixed-layout final NEF flat comparison and 112-point dark regression.',
                      'Actual body CAL/ID35 contents or hardware consumer definition to identify pixel math.']))
    write(OUT/'source-notes.json',dict(local_evidence='Original C3.80 instructions, modified4 byte baseline, private nonzero native fixtures, pinned QEMU traces.',
        read_only_search_scope='ID35 literals; first 5 MiB aligned Thumb immediate candidates; relevant ASCII labels and project emulator source.',
        false_positive='Seven extra 0x000a6e90 literal matches are UTF-16 UI text, not established code references.',
        public_search_scope='Targeted primary-source searches for Nikon shading/defect processing and exact register/table identities; no authoritative Z6 mapping obtained.',
        background_only=['https://patents.google.com/patent/US7463294B2/en',
                         'https://patents.google.com/patent/US20020025164A1/en'],
        patent_limit='Background search leads only; neither is used as evidence for Z6 register function or numerical table semantics.',
        emulator='https://github.com/WonderLantern/z6-qemu',
        emulator_limit='Existing simplified model is not a recovered Nikon proprietary calibration operator.'))
    print('Updated report pointers, exact patch recipe, candidate status and rejected-candidate disposition.')

def verify():
    assert __debug__
    for p,d in FW.items():assert sha((ROOT/p).read_bytes())==d,p
    lab=LAB.read_bytes();assert sha(lab)==EXPECTED and len(lab)==33502842 and binascii.crc_hqx(lab,0)==0
    review=read(OUT/'independent-review-v2/result.json')
    assert review['ok'] and review['sha256']==EXPECTED and review['native_pairs']==244
    assert review['inherited_edits_preserved']==10 and len(review['callers'])==49
    assert review['changed_code_bytes']==51 and review['changed_crc_bytes']==2
    src=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();encodings=0
    for p in OUT.glob('*.json'):
        j=read(p)
        if not isinstance(j,dict):continue
        for span in j.get('ranges',[]):
            for row in span['instructions']:
                n=int(row['pc'],16)-BASE;b=bytes.fromhex(row['bytes'])
                assert src[n:n+len(b)]==b,(p,row);encodings+=1
    a=read(OUT/'native-static-call-v3/result.json');b=read(OUT/'native-submode-supplement/result.json')
    assert a['ok'] and b['ok'] and a['sources_unchanged'] and b['sources_unchanged']
    assert len(a['rows'])+len(b['rows'])==244
    assert all(r['only_expected_gate_change'] for r in a['rows']+b['rows'])
    assert all(r['values']==list(range(28))+[65535] for r in b['selector_domain'])
    assert sum(r['calls'] for r in b['selector_domain'])==2048
    for s in a['restoration']:
        assert [r['gate'] for r in s['sequence']]==([17,0,17] if s['variant']=='lab' else [17,17,17])
    x,y=a['builder_rows'];assert len(x['writes'])==507
    for key in ('packet','table','front_registers','writes'):assert x[key]==y[key]
    for variant in ('m4','lab'):
        j=read(OUT/f'qemu-static-call-{variant}/result.json');assert j['ok'] and j['firmware_unchanged']
    recipe=read(RECIPE);assert recipe['sha256']==EXPECTED and len(recipe['inherited_edits'])==10
    assert recipe['new_edits']==read(OUT/'static-call-lab/manifest.json')['edits']
    assert read(OUT/'lab-module/DISPOSITION.json')['status']=='REJECTED_SCOPE_TOO_BROAD_DO_NOT_INSTALL'
    samples=read(ROOT/'analysis/modified4-real-2026-11-09/verification.json')['source_hashes']
    for p,h in samples.items():assert sha(Path(p).read_bytes())==h,p
    prior=[]
    for name in ('raw-spatial-identity-2026-11-09','raw-front-calibration-2026-11-09',
                 'modified4-real-2026-11-09','modified3-real-2026-11-09','raw-front-owner-2026-11-09'):
        j=read(ROOT/'analysis'/name/'evidence-index.json')
        for row in j['files']:assert sha((ROOT/row['path']).read_bytes())==row['sha256'],row['path']
        prior.append(dict(folder=name,files=len(j['files'])))
    for s in SCRIPTS:ast.parse((ROOT/'tools/fw'/s).read_text(encoding='utf8'))
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if link.startswith('https:'):continue
        p=(REPORT.parent/link).resolve()
        if p not in (OUT/'verification.json',OUT/'evidence-index.json'):assert p.exists(),link
    for row in read(OUT/'progress-update/changes.json')['changes']:
        assert sha((ROOT/row['path']).read_bytes())==row['after_sha256']
    commands=[];failed=set()
    for p in sorted((OUT/'commands').glob('*/command.json')):
        j=read(p)
        if 'exit_code' not in j:continue
        if j['exit_code']!=0:failed.add(p.parent.name)
        commands.append(dict(name=p.parent.name,exit_code=j['exit_code']))
    assert failed==FAILURES,failed
    diff=subprocess.run(['git','diff','--check'],cwd=ROOT,capture_output=True)
    (OUT/'git-diff-check.txt').write_bytes(diff.stdout+diff.stderr);assert diff.returncode==0
    (OUT/'git-status-after.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    write(OUT/'verification.json',dict(ok=True,firmware_hashes=FW,lab_sha256=EXPECTED,
        source_hashes=samples,source_files_unchanged=len(samples),prior_frozen=prior,
        disassembled_instruction_encodings_checked=encodings,native_pairs=244,
        full_selector_domain_cases=2048,front_upload_writes_equal=507,direct_callers_reviewed=49,
        commands=commands,report=record(REPORT),recipe=record(RECIPE),new_lab_module_created=True,
        new_install_kit=False,new_physical_samples=False,hardware_pixel_formula=None,
        physical_ring_effect_verified=False,installation_review_complete=False,git_commit=False))
    print(json.dumps(dict(ok=True,native_pairs=244,samples=len(samples),prior_frozen=prior)))

def index():
    assert read(OUT/'verification.json')['ok']
    snap=OUT/'script-snapshots';snap.mkdir(exist_ok=False)
    for name in SCRIPTS:(snap/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    snap=OUT/'document-snapshots';snap.mkdir(exist_ok=False)
    for name in ('README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md',REPORT.relative_to(ROOT).as_posix(),RECIPE.relative_to(ROOT).as_posix()):
        (snap/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    commands=[dict(name=p.parent.name,**read(p)) for p in sorted((OUT/'commands').glob('*/command.json'))]
    assert all(c.get('exit_code')==(1 if c['name'] in FAILURES else 0) for c in commands)
    files=[record(p) for p in sorted(OUT.rglob('*')) if p.is_file()]
    write(OUT/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=sys.argv,files=files,commands=commands,
        status='Offline static-call ID35 LAB; no new install kit, physical ring result or recovered hardware pixel formula.'))
    print(json.dumps(dict(files=len(files),commands=len(commands),retained_failed_runs=len(FAILURES))))

if __name__=='__main__':dict(progress=progress,verify=verify,index=index)[sys.argv[1]]()

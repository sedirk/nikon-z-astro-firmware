"""Verify, document and freeze the post-modified4 frontend investigation."""
from pathlib import Path
import ast,datetime,hashlib,json,re,struct,subprocess,sys

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-front-calibration-2026-11-09'
REPORT=ROOT/'docs/RAW_FRONT_CALIBRATION_2026-11-09.md'
BASE=0x10020000
SCRIPTS=('qemu_front_calibration_watch.py','probe_front_extra_tables.py',
         'probe_modified4_front_tables.py','probe_secondary_calibration.py',
         'finalize_front_calibration.py','probe_raw_candidates.py','inspect_native.py',
         'record_research_command.py')
FAILURES={'07-extra-table-probe','08-extra-table-probe','20-secondary-native'}
FW={
 'firmware/original/Z_6_0380.bin':'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
 'firmware/decoded/eg1620_038000.bi':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
 'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN':'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875',
 'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN':'6790186e7e088ae7c504677be052aecdbf3868616207bfda5606b36d37149038',
 'outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09/01_TEST_MODIFIED3/EG162080.BIN':'a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd',
 'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'}

def sha(data):return hashlib.sha256(data).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf8'))
def write(p,v):Path(p).write_text(json.dumps(v,ensure_ascii=False,indent=2),encoding='utf8')
def record(p):
    p=Path(p);b=p.read_bytes();return dict(path=p.relative_to(ROOT).as_posix(),bytes=len(b),sha256=sha(b))
def word(mem,offset):return struct.unpack_from('<I',bytes.fromhex(mem['bytes']),offset)[0]

def survey():
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    rows=[]
    for ident in (0x0b,0x35,0x38):
        pc=0x11f1606c+(ident-0x38)*28
        d=struct.unpack_from('<7I',blob,pc-BASE);assert d[0]==ident
        sp=0x11f15a20+(d[5]-0x18)*44;s=struct.unpack_from('<11I',blob,sp-BASE)
        assert s[0]>=BASE+len(blob)
        rows.append(dict(resource_id=hex(ident),directory_rom=hex(pc),directory_words=[hex(x) for x in d],
                         storage_id=hex(d[5]),storage_rom=hex(sp),storage_words=[hex(x) for x in s],
                         source_outside_main_module=True))
    write(OUT/'resource-survey.json',dict(ok=True,firmware_sha256=sha(blob),resources=rows,
        limit='Static storage descriptors and observed runtime base; does not establish per-body uniqueness or actual stored contents.'))
    gate=dict(ok=True,status='RESEARCH_ONLY_NO_NEW_FIRMWARE',base_firmware_sha256=list(FW.values())[-1],
        physical_ring_effect=False,physical_modified4_dark_regression=None,
        candidates=[dict(name='ID35 fixed-length frontend upload',
            source='CAL38 + 0x540 + record_index*80 byte; observed temporary still record_index=2',
            producer='0x1011c798',packet='0xc29a3230+0x1c',register='0x2006103c',
            native_zero_condition='CAL byte is zero; both register and upload gate receive zero',
            upload='0x1011c3f4 -> 0x101229b8 -> 0x100cda34',
            data='ID35 + 0xacdf0, 24416 bytes for observed mode 1',
            next_required=['Identify data and spatial/pixel behavior; actual CAL is absent from the current fixture.',
                           'Bound any override to still phase; common loader also serves other modes.',
                           'Keep modified1 dark instructions and existing release unchanged.']),
          dict(name='ID0b variable-list frontend upload',producer='0x1011c53c',
            packet='0xc29a32b4+0x24',register='0x20061250',
            native_zero_condition='context+0x84 nonzero OR byte context+0x5a == 2; otherwise inherit CAL halfword+0x32',
            upload='0x1011c2a0 -> 0x101229b8 -> 0x100cda34',
            next_required=['Identify the policy producer and physical list operation separately from ID35.',
                           'Follow restoration after temporary stage; zero in that stage is not permanent disabling.']),
          dict(name='33x4 CAL table',producer='0x1011e2ce -> 0x1011e23e',
            upload='0x1010b3a8',register_banks=['0x20068f00','0x20068f44','0x20068fcc','0x20068f88'],
            native_zero_condition=None,
            next_required=['Resolve whether entries encode spatial multipliers, coordinates, thresholds or another operation.',
                           'Do not use zero tables or the alternating bank field as an assumed neutral/off state.'])])
    write(OUT/'candidate-status.json',gate)
    write(OUT/'sources.json',dict(date='2026-11-09',purpose='Original sources consulted for ring interpretation; local addresses come from firmware experiments.',sources=[
        dict(url='https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_hardcoded_correction.html',
             interpretation='Author reports hardcoded raw correction in tested cameras; not proof of our register identity.'),
        dict(url='https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_ring_generation.html',
             interpretation='Author describes spatial channel scaling and integer rounding; fitted camera parameters are not transferable defaults.'),
        dict(url='https://github.com/WonderLantern/WonderLantern-z6',interpretation='Upstream firmware work; no new upstream release claim in this round.'),
        dict(url='https://github.com/WonderLantern/z6-qemu',interpretation='Emulator source; its synthetic pixel behavior is not physical RAW evidence.')] ))
    print('Saved three resource descriptors, gate candidates and source links.')

def progress():
    out=OUT/'progress-update';out.mkdir(exist_ok=False)
    blocks={
      'README.md':'''\n**2026-11-09 最新逆向：结合 modified4 实拍，已接通更早的 ID35/ID0b 标定入口及两个原厂归零条件。** `CAL38 → 2006103c` 控制定长数据上传；`context+5a=2 → 20061250=0` 控制另一条列表路径。134 组隔离原生测试通过，QEMU 记录到静态阶段实际进入 ID35 选择器。另已接通 33×4 标定表到硬件寄存器，完整 modified4 构造中单项变化只影响一个目标寄存器。以上为代码／内存／上传证据；当前实拍仍是宽环未整体改善、modified4 新暗场待拍。本轮未新增刷机文件，原版及 modified1–4 保持。[研究报告](docs/RAW_FRONT_CALIBRATION_2026-11-09.md)、[候选状态](analysis/raw-front-calibration-2026-11-09/candidate-status.json)。\n''',
      'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，modified4 后的固定标定定位）\n\n最终目标保持为保留暗电流、关闭静态 NEF 写入前的 RAW 校正并消除彩圈。依据 modified4 的真实平场反馈，本轮接通更早的定长 ID35 和可变列表 ID0b 路径，确认 2006103c 与 20061250 的原厂归零条件；另定位 33×4 表的完整原生上传。寄存器变化、实机像素变化分别记录；本轮没有新增固件，已验证暗场补丁保留。下一变量优先从这些已定位的源字段／策略生产者收窄，仍需确定空间作用后进入单变量候选审查。[报告](RAW_FRONT_CALIBRATION_2026-11-09.md)。\n''',
      'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，标定源字段与关闭条件）\n\n[本轮报告](RAW_FRONT_CALIBRATION_2026-11-09.md)已把更多固定标定从数据来源连到驱动；[候选状态](../analysis/raw-front-calibration-2026-11-09/candidate-status.json)逐条列出已确认条件和未验收项。\n\n1. 优先识别 `CAL38+5e0 → 2006103c` 与 `ID35+acdf0` 的实际数据／空间作用。当前静态 mode=1 临时阶段进入此路径，长度24416字节，与6104×4吻合；不能只因长度吻合就命名为彩圈校正。查 ID35 存储源13420000及相关生产者，保留原内容。\n2. 追 `context+5a` 的真实请求生产者与静态收窄点。值2明确清20061250并跳过ID0b上传；context+84临时阶段也会清零，需分清后续恢复。两个入口分别验收，不一并关闭。\n3. 33×4表已完成逐项到寄存器和完整modified4构造验证；下一项是物理含义／真正使能字段。20068708会交替，空报文会保留旧寄存器，均不作为关闭方案；2×48缓存只有4/96项在本次选择器中更新。\n4. 候选进入安装前审查前，选择单一原厂归零条件，限定静态路径、保留既有暗场指令，并检查启动／取景／正常NEF／回退。此轮没有新modified5可刷包。\n5. modified4暗场回归仍待新5秒dark；上次modified3实拍通过与当前字节保留分开。下一次彩圈A/B固定机位与焦点、慢快门、多信号级，并记录修改文件哈希。\n\n以下保留各轮历史计划。\n'''}
    changes=[]
    for name,block in blocks.items():
        p=ROOT/name;before=p.read_bytes();assert 'RAW_FRONT_CALIBRATION_2026-11-09.md' not in before.decode('utf8')
        backup=out/name.replace('/','-');backup.write_bytes(before)
        first,rest=before.decode('utf8').split('\n',1)
        p.write_bytes((first+'\n'+block+'\n'+rest).encode('utf8'))
        changes.append(dict(path=name,before=record(backup),after_sha256=sha(p.read_bytes())))
    write(out/'changes.json',dict(changes=changes));print('Updated three project documents, preserving previous bytes.')

def verify():
    memory_count=0
    def memories(v):
        nonlocal memory_count
        if isinstance(v,dict):
            if isinstance(v.get('bytes'),str) and 'sha256' in v:
                b=bytes.fromhex(v['bytes']);assert sha(b)==v['sha256']
                if 'size' in v:assert len(b)==v['size']
                memory_count+=1
            for x in v.values():memories(x)
        elif isinstance(v,list):
            for x in v:memories(x)
    for p,d in FW.items():assert sha((ROOT/p).read_bytes())==d,p
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    decoded=0
    for p in OUT.iterdir():
        if not p.is_file() or p.suffix=='.txt':continue
        j=read(p)
        if 'ranges' not in j:continue
        assert j['firmware_sha256']==FW['firmware/decoded/eg1620_038000.bi']
        for ran in j['ranges']:
            for ins in ran['instructions']:
                off=int(ins['pc'],16)-BASE;b=bytes.fromhex(ins['bytes'])
                assert blob[off:off+len(b)]==b;decoded+=1
    sessions=[]
    for folder,count in (('native-calibration-watch',45),('native-secondary-watch-v2',28)):
        root=OUT/folder;j=read(root/'result.json');events=read(root/'events.json')
        assert j['ok'] and j['firmware_unchanged'] and j['event_count']==len(events)==count
        assert all(not x['saturated'] for x in j['windows'])
        assert sha((root/'probe-source.py').read_bytes())==j['probe_sha256']
        memories(events);memories(j)
        sessions.append(dict(path=folder,events=count,firmware_unchanged=True))
    events=read(OUT/'native-secondary-watch-v2/events.json')
    chain=[e for e in events if e['phase']=='native-settle']
    assert [e['event'] for e in chain]==['raw_destination_ready','secondary_dispatch','cal_gate_store',
        'secondary_global_upload','gate_6103c_written','secondary_dispatch','id35_table_selector',
        'secondary_processing_upload','static_front_builder','temporary_stage_exit','secondary_dispatch']
    e=next(e for e in chain if e['event']=='cal_gate_store')
    assert int(e['registers']['r0'],16)==0xc97000a0
    assert word(e['memory']['calibration_state'],0x18)==0xc9868000
    assert word(e['memory']['calibration_state'],0x1c)==0
    assert word(e['memory']['secondary_global'],0x1c)==0
    assert not any(e['event']=='secondary_descriptor_submit' for e in chain)
    extra=read(OUT/'extra-table-probe-v3/result.json')
    assert extra['ok'] and extra['original_unchanged'] and len(extra['cases'])==60 and len(extra['mutations'])==3
    assert extra['dc0_control_sequence']==[1,0,1,0]
    memories(extra)
    builder=read(OUT/'modified4-builder/result.json')
    assert builder['ok'] and builder['firmware_unchanged'] and len(builder['rows'])==4 and len(builder['comparisons'])==2
    for row in builder['rows']:assert len(row['writes'])==507 and row['cal_unchanged']
    assert all(x['one_register_only'] and x['changed_register']=='0x20068fd8' for x in builder['comparisons'])
    memories(builder)
    gates=read(OUT/'secondary-gate-probe/result.json')
    assert gates['ok'] and gates['firmware_unchanged']
    counts={k:len(gates[k]) for k in ('id35','global_gate','processing_gate','id0b')}
    assert counts==dict(id35=56,global_gate=52,processing_gate=18,id0b=8)
    sources=read(ROOT/'analysis/modified4-real-2026-11-09/verification.json')['source_hashes']
    for p,d in sources.items():assert sha(Path(p).read_bytes())==d,p
    prior=[]
    for name in ('modified4-real-2026-11-09','modified3-real-2026-11-09','raw-front-owner-2026-11-09'):
        j=read(ROOT/'analysis'/name/'evidence-index.json')
        for row in j['files']:assert sha((ROOT/row['path']).read_bytes())==row['sha256'],row['path']
        prior.append(dict(folder=name,files=len(j['files'])))
    for s in SCRIPTS:ast.parse((ROOT/'tools/fw'/s).read_text(encoding='utf8'))
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if not link.startswith('https:'):
            target=(REPORT.parent/link).resolve()
            if target!=OUT/'verification.json':assert target.exists(),link
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
    write(OUT/'verification.json',dict(ok=True,firmware_hashes=FW,source_hashes=sources,
        source_files_unchanged=len(sources),prior_frozen=prior,disassembled_instructions_bytes_checked=decoded,
        memory_blocks_checked=memory_count,sessions=sessions,selector_cases=60,modified4_builders=4,
        secondary_cases=counts,commands=commands,report=record(REPORT),
        new_firmware_created=False,new_physical_samples=False,physical_ring_removal_verified=False,
        modified4_physical_dark_regression=None,git_commit=False))
    print(json.dumps(dict(ok=True,memory_blocks=memory_count,secondary_cases=counts,source_files=len(sources),prior=prior)))

def index():
    assert read(OUT/'verification.json')['ok']
    snap=OUT/'script-snapshots';snap.mkdir(exist_ok=False)
    for name in SCRIPTS:(snap/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    snap=OUT/'document-snapshots';snap.mkdir(exist_ok=False)
    for name in ('README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md','docs/RAW_FRONT_CALIBRATION_2026-11-09.md'):
        (snap/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    commands=[dict(name=p.parent.name,**read(p)) for p in sorted((OUT/'commands').glob('*/command.json'))]
    assert all(c.get('exit_code')==(1 if c['name'] in FAILURES else 0) for c in commands)
    files=[record(p) for p in sorted(OUT.rglob('*')) if p.is_file()]
    write(OUT/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
         argv=sys.argv,files=files,commands=commands,status='Original instruction and model trace evidence only; no new firmware or physical pixel-effect claim.'))
    print(json.dumps(dict(files=len(files),commands=len(commands),retained_failed_development_runs=len(FAILURES))))

if __name__=='__main__':
    assert __debug__
    dict(survey=survey,progress=progress,verify=verify,index=index)[sys.argv[1]]()

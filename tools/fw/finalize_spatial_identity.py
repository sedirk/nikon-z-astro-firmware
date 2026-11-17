"""Verify and freeze the native spatial-identity investigation; no firmware edits."""
from pathlib import Path
import ast,datetime,hashlib,json,re,struct,subprocess,sys
from finalize_front_calibration import FW

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-spatial-identity-2026-11-09'
REPORT=ROOT/'docs/RAW_SPATIAL_IDENTITY_2026-11-09.md'
FAILURES={'24-id0b-static-scope','28-final-verification'}
SCRIPTS=['inspect_calibration_callers.py','probe_id0b_generator.py','probe_id0b_static_scope.py',
         'finalize_spatial_identity.py','probe_raw_candidates.py','probe_front_control_sources.py',
         'inspect_native.py','record_research_command.py','finalize_front_calibration.py']
GENS=['id0b-empty','id0b-two','id0b-shift','id0b-mode0','id0b-mode0-shift','id35-fixed-separation']

def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf8'))
def write(p,x):Path(p).write_text(json.dumps(x,ensure_ascii=False,indent=2),encoding='utf8')
def record(p):
    p=Path(p);b=p.read_bytes();return dict(path=p.relative_to(ROOT).as_posix(),bytes=len(b),sha256=sha(b))

def progress(repair=False):
    target=OUT/'progress-update'
    if not repair:target.mkdir(exist_ok=False)
    changes=[]
    additions={
      'README.md':'''\n**2026-11-09 最新逆向：ID0b 已用完整原生生成器确认是离散行列位置流，静态临时阶段原厂已清其控制。** 六次生成与八组请求来源回放，把该支线从首选消圈开关中降级；ID35定长区另行保留，人工单值改变不影响ID0b生成。33×4表补齐头部映射并定位19个共享调用点，静态候选应收窄到1017d7f0一侧。当前交付仍为modified4，本轮未生成新刷机文件；实际彩圈效果仍沿用既有实拍结论。[本轮报告](docs/RAW_SPATIAL_IDENTITY_2026-11-09.md)、[单变量计划](analysis/raw-spatial-identity-2026-11-09/candidate-status.json)。以下保留历史状态。\n''',
      'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，前端空间身份）\n\n目标保持：保留暗电流、关闭静态 NEF 写入前的 RAW 校正并消除彩圈。本轮以原版代码生成ID0b，验证其离散位置编码；由配置3df到20061250的原生链确认当前静态临时阶段已关闭这一路，故暂不把该策略作为下一消圈刷机变量。ID35定长表与33×4仍为优先目标，静态调用边界已列出。原版、modified1–4与既有暗场补丁保持，离线位置/寄存器证据与最终NEF效果分别验收。[报告](RAW_SPATIAL_IDENTITY_2026-11-09.md)。\n''',
      'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，空间身份与单变量筛选）\n\n[本轮报告](RAW_SPATIAL_IDENTITY_2026-11-09.md)与[候选状态](../analysis/raw-spatial-identity-2026-11-09/candidate-status.json)更新了优先级。\n\n1. 优先识别ID35+acdf0的定长数据，以及CAL38+47180分组33×4表的真实数值/硬件功能。ID0b位置生成器不等于ID35整个资源；已执行的固定区单值改变没有进入ID0b输出。不要继续将已知位置流当作未知径向系数追踪。\n2. 暂缓static input+47强制2候选：实际配置源是3df，静态temporary=1已使20061250为0；原生非零对照中再强制2无额外作用。其它阶段另行验证，不能宣称所有静态模式都无关。\n3. 静态ID35配置调用点10179d56、静态33×4构造调用点1017d7f0已列入单变量计划。33×4选择器共有19个已找到直接调用点，避免全局替换；先确定一个真实关闭控制，再选择一条路径进入候选。\n4. 33×4头部四对u16尚未认定坐标；20068708为交替/强制控制，空报文保留旧表，均不当作已知关闭。1011e242至1011e286条件标志存活，改中间指令必须保持。读取真实标定内容或找到独立硬件处理定义是下一优先证据。\n5. 目前交付维持modified4，未新增modified5；保留112点暗场回归、固定布置多信号级慢快门平场判据。modified4新dark仍待样本，本轮没有新实拍。\n\n以下保留此前计划。\n'''}
    for name,addition in additions.items():
        p=ROOT/name;backup=target/(name.replace('/','-')+'.before')
        before=backup.read_bytes() if repair else p.read_bytes()
        if not repair:backup.write_bytes(before)
        old=before.decode('utf8').replace('\r\n','\n');head,tail=old.split('\n',1)
        p.write_bytes((head+'\n'+addition+tail).encode('utf8'))
        changes.append(dict(path=name,before_sha256=sha(before),after_sha256=sha(p.read_bytes())))
    write(target/'changes.json',dict(changes=changes))
    write(OUT/'candidate-status.json',dict(status='RESEARCH_DESIGN_NO_NEW_FIRMWARE',
        base_firmware_sha256=list(FW.values())[-1],physical_ring_effect_verified=False,
        physical_modified4_dark_regression=None,selected_next_patch=None,
        candidates=[
          dict(id='id35-fixed',priority='continue',static_call='0x10179d56',
               source='CAL38+0x540+index*80 byte',gate='0x2006103c',native_off_value=0,
               table='ID35+0xacdf0 / 24416 bytes in observed mode1',
               identity='Fixed-size frontend data; spatial coefficient/mask/index meaning unresolved.',
               required='Identify data operation; scope override to static caller without changing source calibration or other modes.'),
          dict(id='table33x4',priority='continue',static_call='0x1017d7f0',
               selector='0x1011e2ce',shared_direct_calls=19,record_copy='0x1011e23e',
               table_source='CAL38+0x47180+group*600+category*300',native_off_value=None,
               identity='132 u16 table entries plus numeric controls; physical spatial or signal-domain meaning unresolved.',
               required='Actual CAL values or independent hardware/consumer evidence; retain source data and non-static calls.'),
          dict(id='id0b-policy2',priority='deprioritized_for_current_static_window',
               proposed_static_read='0x100f64a0',config='0x3df',context_byte='0x5a',gate='0x20061250',
               native_off_condition='temporary != 0 OR policy == 2',
               evidence='Complete native generator encodes discrete x/y. Nonzero gate already zero during observed temporary static stage.',
               scope_limit='Does not exclude all later stages or all camera modes.')],
        acceptance=['One processing control per candidate relative to exact modified4 hash.',
                    'Preserve original firmware and all existing patch bytes, including modified1 dark patch.',
                    'Nonzero CAL positive control; explicit clearing rather than retained stale registers.',
                    'Static-only request path, other-mode restoration, instruction flags and buffer boundaries.',
                    'Separate installation audit, physical saved-NEF ring comparison, and dark-point regression.']))
    write(OUT/'source-notes.json',dict(primary_external_reference='https://github.com/WonderLantern/z6-qemu',
        external_scope='Existing emulator model provenance only; no external register identity or new release conclusion used.',
        main_evidence='Local original firmware instructions, bounded native execution, and reinspection of frozen prior traces.',
        search_limit='Targeted public searches this round did not supply an authoritative 200686e4/33x4 hardware definition. This is not an exhaustive absence claim.',
        host_inventory='Read-only Windows PnP enumeration listed two built-in USB cameras, no Nikon; no device commands sent.'))
    print('Updated progress documents and explicit candidate status.')

def verify():
    assert __debug__
    for p,d in FW.items():assert sha((ROOT/p).read_bytes())==d,p
    source=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    decoded=0
    for p in OUT.glob('*.json'):
        j=read(p)
        for span in j.get('ranges',[]):
            for row in span['instructions']:
                n=int(row['pc'],16)-0x10020000;b=bytes.fromhex(row['bytes'])
                assert source[n:n+len(b)]==b,(p,row);decoded+=1
    reports={};outputs={}
    for name in GENS:
        j=read(OUT/name/'result.json');b=(OUT/name/'generated.bin').read_bytes()
        assert j['ok'] and j['source_hashes_unchanged'] and j['output_guard'] and j['workspace_guard']
        assert not j['code_patches'] and not j['service_stubs'] and not j['memory_write_hooks']
        assert j['firmware_sha256']==FW['firmware/decoded/eg1620_038000.bi']
        assert sha(b)==j['output_sha256'] and len(b)==0x25fff8 and b[0x24fffc:0x250000]==b'ENDM'
        assert len(j['coordinate_calls'])==17 and len(j['groups'])==17
        for g in j['groups']:
            off=int(g['offset'],16);count=struct.unpack_from('<I',b,g['mode']*4)[0]
            assert count==g['count'] and [hex(x) for x in struct.unpack_from('<'+'H'*min(count,64),b,off)]==g['first_words']
        reports[name]=j;outputs[name]=b
    expected=[0xe0c8,0x2064,0xe1f4,0x2320,0xffff]
    shifted=[0xe0c8,0x2066,0xe1f6,0x2320,0xffff]
    assert reports['id0b-empty']['groups'][0]['first_words']==['0xffff']
    assert reports['id0b-mode0']['groups'][0]['first_words']==[hex(x) for x in expected]
    assert reports['id0b-mode0-shift']['groups'][0]['first_words']==[hex(x) for x in shifted]
    assert outputs['id35-fixed-separation']==outputs['id0b-mode0']
    for name in ('id0b-mode0','id0b-mode0-shift','id35-fixed-separation'):
        assert all(not (int(r['offset'],16)<0xacdf4 and int(r['offset'],16)+r['size']>0xacdf0)
                   for r in reports[name]['source_reads'])
    mode0=next(c for c in reports['id0b-mode0']['coordinate_calls'] if c['mode']==0)
    assert [r[:2] for r in mode0['records_u16']]==[[100,200],[800,500]]
    control=read(OUT/'id0b-static-scope-v2/result.json')
    assert control['ok'] and control['firmware_unchanged'] and control['temporary_policy2_has_no_additional_gate_effect']
    assert len(control['rows'])==8
    for row in control['rows']:
        assert row['id35_gate']==1 and row['id0b_gate']==int(not row['temporary'] and row['policy']!=2)
        assert bytes.fromhex(row['request'])[0x47]==row['policy']
        assert bytes.fromhex(row['context_before']['bytes'])[0x5a]==row['policy']
        if row['temporary']:assert row['descriptor']==['0x560acdf0','0x5f60']
    scoped=read(OUT/'table33-call-scope.json')
    sites=[r['pc'] for r in scoped['branches'] if r['operands']=='#0x1011e2ce']
    assert len(sites)==19 and '0x1017d7f0' in sites
    assert [r['pc'] for r in scoped['branches'] if r['operands']=='#0x1017d7b6']==['0x10179d7c']
    oldevents=read(ROOT/'analysis/raw-front-calibration-2026-11-09/native-secondary-watch-v2/events.json')
    chain=[e for e in oldevents if e['phase']=='native-settle']
    dispatch=[e for e in chain if e['event']=='secondary_dispatch']
    assert [int(e['registers']['r0'],16) for e in dispatch]==[0,1,2]
    assert [int.from_bytes(bytes.fromhex(e['memory']['context']['bytes'])[0x84:0x88],'little') for e in dispatch]==[1,1,0]
    assert any(e['event']=='id35_table_selector' for e in chain) and not any(e['event']=='id0b_table_selector' for e in chain)
    sources=read(ROOT/'analysis/modified4-real-2026-11-09/verification.json')['source_hashes']
    for p,d in sources.items():assert sha(Path(p).read_bytes())==d,p
    prior=[]
    for name in ('raw-front-calibration-2026-11-09','modified4-real-2026-11-09','modified3-real-2026-11-09','raw-front-owner-2026-11-09'):
        j=read(ROOT/'analysis'/name/'evidence-index.json')
        for row in j['files']:assert sha((ROOT/row['path']).read_bytes())==row['sha256'],row['path']
        prior.append(dict(folder=name,files=len(j['files'])))
    for s in SCRIPTS:ast.parse((ROOT/'tools/fw'/s).read_text(encoding='utf8'))
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if not link.startswith('https:'):
            p=(REPORT.parent/link).resolve()
            if p!=OUT/'verification.json':assert p.exists(),link
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
        source_files_unchanged=len(sources),prior_frozen=prior,native_generator_cases=6,native_gate_cases=8,
        disassembled_instruction_encodings_checked=decoded,shared_table33_direct_call_count=19,
        id35_fixed_mutation_does_not_change_generated_id0b=True,
        static_scope='Reverified frozen modified4 native-settle trace and bounded nonzero-calibration native stages.',
        commands=commands,report=record(REPORT),new_firmware_created=False,
        new_physical_samples=False,physical_ring_removal_verified=False,modified4_physical_dark_regression=None,git_commit=False))
    print(json.dumps(dict(ok=True,generators=6,gate_cases=8,samples=len(sources),prior_frozen=prior)))

def index():
    assert read(OUT/'verification.json')['ok']
    snap=OUT/'script-snapshots';snap.mkdir(exist_ok=False)
    for name in SCRIPTS:(snap/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    snap=OUT/'document-snapshots';snap.mkdir(exist_ok=False)
    for name in ('README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md','docs/RAW_SPATIAL_IDENTITY_2026-11-09.md'):
        (snap/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    commands=[dict(name=p.parent.name,**read(p)) for p in sorted((OUT/'commands').glob('*/command.json'))]
    assert all(c.get('exit_code')==(1 if c['name'] in FAILURES else 0) for c in commands)
    files=[record(p) for p in sorted(OUT.rglob('*')) if p.is_file()]
    write(OUT/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=sys.argv,files=files,commands=commands,status='Offline native spatial encoding and scope verification; no new firmware or physical ring result.'))
    print(json.dumps(dict(files=len(files),commands=len(commands),retained_failed_runs=len(FAILURES))))

if __name__=='__main__':dict(progress=progress,repair_progress=lambda:progress(True),verify=verify,index=index)[sys.argv[1]]()

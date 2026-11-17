"""Audit the lab patch and preserve/index the 2026-11-09 ring-control research."""
from pathlib import Path
import binascii, datetime, hashlib, json, re, struct, sys
import capstone
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC
from audit_nef import file_sha
from build_raw_candidates import apply_candidate
from probe_raw_candidates import ROOT,BASE,OWNER,FRAME,Rig,sha
from probe_still_vignette_neutral import seed,VREQ,VOUT,CURVE,MIXED

OUT=ROOT/'analysis/raw-ring-controls-2026-11-09'
REPORT=ROOT/'docs/RAW_RING_CONTROLS_2026-11-09.md'


def read(path):return json.loads(path.read_text(encoding='utf8'))
def write(path,value):
    assert not path.exists(),path
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf8')


def review():
    folder=OUT/'candidate-review';folder.mkdir(exist_ok=False)
    (folder/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    original=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    cat=read(ROOT/'patches/z6-c380-still-vignette-neutral-lab.json')
    lab,manifest=apply_candidate(original,cat,cat['candidates'][0])
    labfile=OUT/'lab-modules/still-neighborhood-plus-vignette-neutral-lab.bi'
    assert lab==labfile.read_bytes()
    current=(ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN').read_bytes()
    assert sha(current)=='eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875'
    new_edits=cat['candidates'][0]['edits'][3:]
    allowed={i for e in new_edits for i in range(int(e['address'],0)-BASE,int(e['address'],0)-BASE+4)}
    differences=[i for i,(a,b) in enumerate(zip(current,lab)) if a!=b]
    assert set(differences)<=allowed|{len(lab)-2,len(lab)-1}
    assert len(differences)==8
    assert all(binascii.crc_hqx(b,0)==0 for b in (original,current,lab))
    restored=bytearray(lab)
    for off in allowed:restored[off]=current[off]
    restored[-2:]=current[-2:];assert bytes(restored)==current
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);md.detail=True
    disassembly=[]
    for e in cat['candidates'][0]['edits']:
        for which in ('before','after'):
            ins=list(md.disasm(bytes.fromhex(e[which]),int(e['address'],0)))
            assert len(ins)==1 and ins[0].size==4
            assert f'{ins[0].mnemonic} {ins[0].op_str}'==e['instruction_'+which]
            disassembly.append(dict(address=e['address'],which=which,bytes=e[which],
                                    instruction=e['instruction_'+which],updates_flags=ins[0].update_flags))
    assert all(not r['updates_flags'] for r in disassembly)
    snapshot=read(ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json')['final']
    fields=read(OUT/'nef-fields/result.json')['files'][0]
    report=dict(ok=False,new_code_changed_bytes=6,total_changed_bytes_vs_modified1=8,
        changed_offsets_vs_modified1=[hex(i) for i in differences],lab_sha256=sha(lab),
        module_crc_verified=True,exact_restore_to_modified1=True,disassembly=disassembly,guards=[])
    try:
        # Positive/negative source-pointer control: uncached lens type 1 has an
        # unmapped polynomial grid. The baseline must reach it, whereas native
        # neutral selection should return without accessing that grid.
        for variant,blob in (('modified1',current),('vignette-neutral-lab',lab)):
            rig=Rig(blob,snapshot);invalid=[]
            def on_invalid(uc,access,address,size,value,data):
                invalid.append(dict(access=access,address=hex(address),size=size,pc=hex(uc.reg_read(UC_ARM_REG_PC))))
                return False
            rig.uc.hook_add(un.UC_HOOK_MEM_INVALID,on_invalid)
            seed(rig,dict(cached=0,strength=2,owner_neutral=0),fields['vignette']['coefficients'],fields['two_table_spatial']['coefficients'])
            rig.put(OWNER+0x227c,1,'B');rig.put(OWNER+0x227c+0x1a,1,'B')
            rig.put(OWNER+0x227c+0x40,0x68000000)
            error=None;call=None
            try:call=rig.call(0x100c29c6,[VREQ,VOUT])
            except un.UcError as exc:error=str(exc)
            row=dict(variant=variant,expected_invalid_grid=variant=='modified1',invalid=invalid,error=error,call=call)
            if variant=='modified1':
                assert error and invalid and 0x68000000<=int(invalid[0]['address'],16)<0x68010000,row
            else:
                assert error is None and not invalid
                for ptr in (CURVE,MIXED):assert bytes(rig.uc.mem_read(ptr,514))==struct.pack('<257H',*([1024]*257))
                assert '0x101a1240' in call['blocks']
            report['guards'].append(row)
        report['ok']=True
    finally:
        report['original_preserved']=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()==original
        write(folder/'result.json',report)
    print(json.dumps(dict(ok=report['ok'],code_bytes=6,guards=len(report['guards']))))


def update():
    folder=OUT/'progress-update';folder.mkdir(exist_ok=False)
    blocks={
    'README.md':'''\n**2026-11-09 最新：平场系数已接到原厂控制点，并生成独立实验副本。**两张平场相同的 NEFInfo7 在原厂普通／缓存路径中逐字节重现；新增 22 组空间控制与 33 组机身固定记录实验。257 项暗角曲线中性化副本保留现有暗场补丁，相对已安装候选只增加 6 个代码字节及 2 个 CRC 字节；64 组处理链、64 组入口／ABI 检查通过。当前为离线 LAB 候选，实际消圈、安装审查和稳定性分别验收。[本轮报告](docs/RAW_RING_CONTROLS_2026-11-09.md)、[实验配方](patches/z6-c380-still-vignette-neutral-lab.json)。以下平场与暗场实拍结果继续保留。\n''',
    'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，空间控制与暗角中性化副本）\n\n[最新报告](RAW_RING_CONTROLS_2026-11-09.md)：真实平场的两组空间系数已接到原厂生成／导出代码；257 项曲线实验副本已经过离线参数、上传与 ABI 对照，属于 LAB 阶段。\n\n1. **下一版只增加一个可验收变量。** 保留 modified1 的邻域关闭，独立验收 257 项曲线中性化；先完成该副本的准确文件升级入口审查，再安排同条件实拍。现有 01_TEST 包不被新副本覆盖。\n2. **先固定平场基线。** 保留当前镜头与机身，在当前 modified1 下拍固定光圈、多个信号级、较慢快门的重复平场；同条件复拍新候选以判断 R/G、B/G 环形台阶是否改变。新 f/8 组与旧 f/1.8 分开比较，光源旋转辅助识别屏幕结构。\n3. **两组 17 项表独立实验。** 原厂 22 组对照已区分源缺失、bit2 抑制和缓存标志。缓存下只改模式或单个标志会保留系数／表；若制作下一候选，需针对静态入口并保留坐标与其他缓存消费者，不全局强制 properties+96。\n4. **机身固定标定继续追控制和写回。** 新增 cal+49a70 的 204 字节记录到六组前端寄存器的传播；它只负责四组，另两组有独立写入者。保持原标定，不用跳过上传或清零整块作为关闭。\n5. **把 1/8000 秒作为短曝光支线线索。** 两张现有平场落在此前 144 项表的短曝光数值区域；记录选择／旧表复用仍要区分。慢快门新组同时帮助分离屏幕条带与短曝光处理，但其变化不可单独归因于固件。\n6. **暗信号成果持续回归。** 新副本离线保留 bank+584/+594 关闭状态、四偏移、0x720、BlackLevel、空间表与 RAW 输出路由；最终以实际 NEF、112 点和星点／暗场统计复查。\n\n下方保留各历史阶段计划。\n''',
    'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，实际平场约束下的独立候选）\n\n最终目标不变。两张平场的相同非零空间参数已连接到原厂函数和关闭条件；新增保留 modified1 暗场补丁、让 257 项暗角曲线走原厂中性分支的 LAB 副本。参数／寄存器对照与代码完整性已经验证，实机消圈是下一项独立验收；机身固定标定、两组 17 项表和全部 RAW 校正仍分项追踪。见[本轮报告](RAW_RING_CONTROLS_2026-11-09.md)。\n'''}
    changes=[]
    for relative,block in blocks.items():
        path=ROOT/relative;before=path.read_bytes();text=before.decode('utf8')
        assert 'RAW_RING_CONTROLS_2026-11-09.md' not in text
        first,rest=text.split('\n',1);after=(first+'\n'+block+'\n'+rest).encode('utf8')
        backup=folder/('before-'+relative.replace('/','-'));backup.write_bytes(before);path.write_bytes(after)
        changes.append(dict(path=relative,before_copy=str(backup.relative_to(ROOT)),before_sha256=sha(before),after_sha256=sha(after)))
    write(folder/'changes.json',dict(changes=changes,updated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    print(json.dumps(dict(updated=len(changes))))


def verify():
    old=read(ROOT/'analysis/modified1-flat-2026-11-09/verification.json')
    for rel,digest in old['firmware_hashes'].items():assert file_sha(ROOT/rel)==digest,rel
    fields=read(OUT/'nef-fields/result.json');sp=read(OUT/'spatial-replay/result.json')
    front=read(OUT/'front-fixed-record/result.json');lab=read(OUT/'lab-native-v2/result.json');reviewed=read(OUT/'candidate-review/result.json')
    assert all(x['ok'] for x in (fields,sp,front,lab,reviewed))
    assert len(sp['cases'])==22 and len(front['cases'])==33
    assert (len(lab['chains']),len(lab['matrix']),len(lab['comparisons']))==(64,64,32)
    for f in fields['files']:assert file_sha(f['path'])==f['sha256']
    real=fields['files'][0]['nefinfo']['entries']['0x7']['bytes']
    for row in sp['cases']:
        if row['fixture']['name'] in ('cached-active','cached-mode7','ordinary-active'):assert row['tag_hex']==real
    for row in lab['chains']:
        if row['variant']=='vignette-neutral-lab':assert row['curve']==row['mixed']==[1024]*257 and row['blend']==0
    for row in lab['comparisons']:assert all(0x2890<=int(k,16)<0x2c98 for k in row['changed_registers'])
    for row in read(OUT/'progress-update/changes.json')['changes']:
        assert file_sha(ROOT/row['path'])==row['after_sha256']
        assert file_sha(ROOT/row['before_copy'])==row['before_sha256']
    for target in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if not target.startswith('https:'):assert (REPORT.parent/target).exists(),target
    # Validate the previous round's frozen files without requiring its live
    # progress documents to remain at the historical content.
    frozen=read(ROOT/'analysis/modified1-flat-2026-11-09/evidence-index.json')
    for row in frozen['files']:assert file_sha(ROOT/row['path'])==row['sha256'],row['path']
    commands=[]
    for path in sorted((OUT/'commands').glob('*/command.json')):
        value=read(path)
        if 'exit_code' in value:
            assert value['exit_code']==(1 if path.parent.name=='12-probe-lab-vignette' else 0),path
            commands.append(dict(name=path.parent.name,exit_code=value['exit_code']))
    write(OUT/'verification.json',dict(ok=True,firmware_hashes=old['firmware_hashes'],
        unchanged_flat_files=2,frozen_prior_round_files=len(frozen['files']),spatial_cases=22,front_cases=33,
        lab_chains=64,lab_matrix=64,lab_pairs=32,source_pointer_guard_cases=2,
        lab_sha256=reviewed['lab_sha256'],report_sha256=file_sha(REPORT),completed_commands=commands,
        physical_ring_removal_accepted=False,new_candidate_preflash_reviewed=False))
    print(json.dumps(dict(ok=True,prior_frozen_files=len(frozen['files']),completed_commands=len(commands))))


def index():
    assert read(OUT/'verification.json')['ok']
    scripts=OUT/'script-snapshots';scripts.mkdir(exist_ok=False)
    names=['extract_flat_correction_fields.py','bridge_real_nef_contract.py','audit_nef.py','inspect_native.py',
           'probe_flat_spatial_controls.py','probe_front_fixed_record.py','probe_still_vignette_neutral.py',
           'probe_raw_candidates.py','probe_still_neighborhood_off.py','build_raw_candidates.py',
           'record_research_command.py',Path(__file__).name]
    for name in names:(scripts/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    docs=OUT/'document-snapshots';docs.mkdir(exist_ok=False)
    for rel in ('docs/RAW_RING_CONTROLS_2026-11-09.md','README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md',
                'patches/z6-c380-still-vignette-neutral-lab.json'):
        (docs/rel.replace('/','-')).write_bytes((ROOT/rel).read_bytes())
    commands=[dict(name=p.parent.name,**read(p)) for p in sorted((OUT/'commands').glob('*/command.json'))]
    assert all(v.get('exit_code')==(1 if v['name']=='12-probe-lab-vignette' else 0) for v in commands)
    rows=[dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,sha256=file_sha(p)) for p in sorted(OUT.rglob('*')) if p.is_file()]
    write(OUT/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
        files=rows,commands=commands,script_snapshots=len(names),status='Frozen round; experimental candidate, hardware effect not evaluated.'))
    print(json.dumps(dict(indexed_files=len(rows),commands=len(commands))))


if __name__=='__main__':
    {'review':review,'update':update,'verify':verify,'index':index}[sys.argv[1]]()

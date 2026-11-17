"""Verify immutable inputs and front-control evidence; update project entry docs."""
from pathlib import Path
from datetime import datetime, timezone
import argparse, binascii, hashlib, json, struct
from build_raw_candidates import apply_candidate

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-front-controls-2026-11-09'

def read(p):return json.loads(p.read_text(encoding='utf8'))
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()
def raw(x):return bytes.fromhex(x['bytes'])
def save(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2),encoding='utf8')
def record(p):return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=sha(p))
def memories(x):
    if isinstance(x,dict):
        if {'bytes','sha256','size'}<=x.keys() and isinstance(x['bytes'],str):
            b=raw(x);assert len(b)==x['size'] and hashlib.sha256(b).hexdigest()==x['sha256']
        for y in x.values():memories(y)
    elif isinstance(x,list):
        for y in x:memories(y)

def verify():
    previous=read(ROOT/'analysis/modified3-real-2026-11-09/verification.json')
    for name,digest in previous['source_hashes'].items():assert sha(Path(name))==digest,name
    prior_index=read(ROOT/'analysis/modified3-real-2026-11-09/evidence-index.json')
    for f in prior_index['files']:
        p=ROOT/f['path'];assert p.stat().st_size==f['bytes'] and sha(p)==f['sha256'],str(p)
    firmware={
        'firmware/original/Z_6_0380.bin':'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
        'firmware/decoded/eg1620_038000.bi':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
        'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN':'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875',
        'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN':'6790186e7e088ae7c504677be052aecdbf3868616207bfda5606b36d37149038',
        'outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09/01_TEST_MODIFIED3/EG162080.BIN':'a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd'}
    for name,digest in firmware.items():assert sha(ROOT/name)==digest,name
    original=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    m3=(ROOT/next(k for k in firmware if '01_TEST_MODIFIED3' in k)).read_bytes()
    catalog=read(ROOT/'patches/z6-c380-front-bit11-off-lab.json')
    rebuilt,manifest=apply_candidate(original,catalog,catalog['candidates'][0])
    lab=OUT/'lab-module/modified3-front-bit11-off-lab.bi'
    assert rebuilt==lab.read_bytes()
    assert sha(lab)=='bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
    restored=bytearray(rebuilt);offset=0x100f64b4-0x10020000
    restored[offset:offset+4]=m3[offset:offset+4];restored[-2:]=m3[-2:]
    assert restored==m3
    results={name:read(OUT/name/'result.json') for name in ('source-probe','lab-probe','transitions')}
    for x in results.values():assert x['ok'];memories(x)
    assert len(results['source-probe']['rows'])==112 and len(results['source-probe']['comparisons'])==56
    lp=results['lab-probe'];assert len(lp['comparisons'])==56 and len(lp['abi'])==128
    assert len(lp['full_builder'])==4
    for temp in (0,1):
        ref,new=[next(x for x in lp['full_builder'] if x['temp']==temp and x['variant']==v) for v in ('modified3','bit11-lab')]
        w0,w1=ref['calls'][1]['writes'],new['calls'][1]['writes'];assert len(w0)==len(w1)==507
        differences=[]
        for i,(old,neww) in enumerate(zip(w0,w1)):
            if old!=neww:
                assert {k:v for k,v in old.items() if k!='value'}=={k:v for k,v in neww.items() if k!='value'}
                assert old['address']=='0x20068500' and int(neww['value'],16)==int(old['value'],16)&~0x800
                differences.append(i)
        assert len(differences)==1
    assert len(results['transitions']['rows'])==24 and len(results['transitions']['liveview_equal'])==6
    native=[]
    for dirname,count,value in [('native-trace-modified3',33,0),('native-trace-lab',34,2)]:
        r=read(OUT/dirname/'result.json');events=read(OUT/dirname/'events.json')
        assert r['ok'] and r['firmware_unchanged'] and len(events)==count
        assert all(not w['saturated'] for w in r['windows'])
        memories(events)
        ready=next(e for e in events if e['event']=='static_context_ready')
        builder=next(e for e in events if e['event']=='static_front_builder')
        assert raw(ready['memory']['context'])[0x5d]==raw(builder['memory']['context'])[0x5d]==value
        assert any(e['event']=='raw_destination_ready' and e['phase']=='native-settle' for e in events)
        native.append(dict(directory=dirname,events=count,static_override=value,zero_calibration=True))
    for p in OUT.glob('*.json'):
        d=read(p)
        if not isinstance(d,dict):continue
        for span in d.get('ranges',[]):
            for ins in span['instructions']:
                off=int(ins['pc'],16)-0x10020000;b=bytes.fromhex(ins['bytes'])
                assert original[off:off+len(b)]==b
    commands=[]
    for p in sorted((OUT/'commands').glob('*/command.json')):
        x=read(p)
        if 'exit_code' not in x:continue
        assert x['exit_code']==(1 if p.parent.name.startswith(('09-','11-')) else 0),p
        commands.append(dict(name=p.parent.name,exit_code=x['exit_code']))
    report=dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),firmware_preserved=firmware,
        source_nefs_unchanged=len(previous['source_hashes']),prior_frozen_files=len(prior_index['files']),
        exact_modified3_recovery=True,exact_lab_reconstruction=True,lab=record(lab),native=native,
        selection_pairs=56,lab_pairs=56,abi_cases=128,full_builder_paths=4,writes_per_path=507,
        transitions=24,liveview_equal_pairs=6,commands=commands,hardware_effect='No new physical samples; modified3 physical assessment retained.',
        caveat='1013fa20 is a distinct back-end owner; its artificial prefix is not the measured frontend producer.')
    save(OUT/'verification.json',report)
    print(json.dumps(dict(ok=True,source_nefs=report['source_nefs_unchanged'],prior_files=report['prior_frozen_files'],lab_sha256=sha(lab))))

def docs():
    assert read(OUT/'verification.json')['ok']
    before=OUT/'project-documents-before';after=OUT/'project-documents-after'
    before.mkdir(exist_ok=False);after.mkdir(exist_ok=False)
    insertions={
        'README.md':'**2026-11-09 最新离线进展：前端 bit11 已定位到静态输入覆盖点，新增单指令 LAB 副本。**继承 modified3 和已验证暗场补丁；完整静态前端构造/上传每次507次写入中，仅目标位变化。56对候选控制链、128次 ABI/标志检查、24步静态/取景参数交替及两版 QEMU 跟踪通过。副本尚未完成安装前审查；bit11物理处理身份、真机置位和彩圈效果继续定位，实拍结论仍为 modified3 暗场保持、宽环未整体改善。[本轮报告](docs/RAW_FRONT_CONTROLS_2026-11-09.md)、[配方](patches/z6-c380-front-bit11-off-lab.json)。下方为此前实拍和历史记录。',
        'docs/NEXT_STEPS.md':'## 当前优先级（2026-11-09，前端单项控制 LAB）\n\n[本轮报告](RAW_FRONT_CONTROLS_2026-11-09.md)：静态 `100f64b4 → input+45 → context+5d → 20068500 bit11` 已形成单指令实验副本。非零标定下仅目标寄存器位变化，暗场/暗角/两组17项修改继承；新版本无实拍、无安装包。\n\n1. 优先追真正前端源对象 `c236d378+259` 的建立/复制来源及 ID38 policy 位，确定硬件处理身份。QEMU 中 `1013fa20` 的后端 owner 是另一个对象，勿用同偏移替代真正来源。\n2. 对确切 LAB 哈希 `bdf30026…a4ef1b` 审查两个静态调用点、完整模式返回、升级/回退；当前单指令范围仍不等于 NEF 独占。\n3. 后续实拍以 modified3 为 A，固定机位/焦点/光源，多信号级和慢快门主组；检查实际 CFA 环边并回归112点，宽光学/屏幕结构与细密量化环分开。\n4. 不清空整个 CAL，不把3d8多处联动、空配置包或模型零表作为消圈关闭方案。\n\n以下为此前轮次记录。',
        'docs/PROJECT_GOALS.md':'## 当前推进（2026-11-09，前端静态控制实验）\n\n最终目标不变。依据 modified3 实拍中暗场效果保持、宽环仍在，研究转向更前端的固定标定控制。已定位一个原厂显式清位条件，并做成继承 modified3 的单指令 LAB 副本；控制链、原厂507次上传、ABI及保留状态参数切换分别验证。新位对应的物理处理和消圈效果仍待定位/实拍，尚未生成安装包；已验证暗场补丁和原始固件保持。[本轮报告](RAW_FRONT_CONTROLS_2026-11-09.md)。'}
    for name,body in insertions.items():
        p=ROOT/name;content=p.read_bytes();key=name.replace('/','__')
        (before/key).write_bytes(content)
        text=content.decode('utf8');head,tail=text.split('\n',1)
        p.write_text(head+'\n\n'+body+'\n\n'+tail,encoding='utf8')
        (after/key).write_bytes(p.read_bytes())
    sources=OUT/'final-sources';sources.mkdir(exist_ok=False)
    for name in ('scan_front_operands.py','prepare_front_bit11_lab.py','probe_front_control_sources.py',
        'probe_front_bit11_lab.py','probe_front_bit11_transitions.py','qemu_front_control_sources.py','finalize_front_controls.py'):
        (sources/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    (OUT/'report.md').write_bytes((ROOT/'docs/RAW_FRONT_CONTROLS_2026-11-09.md').read_bytes())
    save(OUT/'assessment.json',dict(physical_reference='docs/MODIFIED3_REAL_NEF_2026-11-09.md',
        current_physical_result='modified3: dark suppression regression passed; broad rings not overall improved; geometry/focus may move.',
        verified_offline=['static input45 -> ctx5d -> control2 -> master bit11',
            '3d8 is coupled to preparation stage/bit3/thresholds; not selected as a narrow patch',
            'modified3 LAB adds one instruction, preserves all nine prior edits',
            'native source owner differs from observed backend owner; artificial prefix is not an observed full chain'],
        hypothesis='bit11 might control a remaining RAW operation; physical function/ring causality and actual enabled state unresolved',
        next=['identify actual frontend +259 writer and calibration flag meaning','preflash scope/updater/rollback review','matched physical A/B and dark regression'],
        package_status='LAB only; no update filename or installation kit'))
    print('Project documents and frozen source copies saved.')

def index():
    files=[record(p) for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='evidence-index.json'
        and '27-freeze-index' not in p.parts]
    save(OUT/'evidence-index.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),files=files,
        excludes=['evidence-index.json','commands/27-freeze-index (recorder still writing while index is created)']))
    for f in files:assert sha(ROOT/f['path'])==f['sha256']
    print(json.dumps(dict(ok=True,indexed=len(files))))

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('action',choices=('verify','docs','index'))
    {'verify':verify,'docs':docs,'index':index}[ap.parse_args().action]()

if __name__=='__main__':main()

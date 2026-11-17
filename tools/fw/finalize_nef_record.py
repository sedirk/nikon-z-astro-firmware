"""Index this round's retained evidence, dependencies, failed trials and local links."""
from pathlib import Path
import argparse,ast,datetime,hashlib,json,re
import numpy as np
import rawpy
from audit_nef import file_sha
from verify_nef_save import ROOT,EVIDENCE,MODELS

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path)
a=p.parse_args();assert __debug__ and not a.output.exists()
report=dict(recorded_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    physical_nef_samples_received=False,user_next_step='User will capture original-firmware NEFs after this round.',
    scope='Only native serialization and software data contracts have been validated; no physical RAW correction or dark-current outcome.',commands={},initial_trials={})
for folder in ('header-attempt','qemu-header','qemu-header-trace','qemu-header-backed'):
    r=json.loads((EVIDENCE/folder/'result.json').read_text());assert r['ok'] is False
    report['initial_trials'][folder]=dict(ok=False,phase=r.get('phase'),error=r.get('error'),
        failure_pc=r.get('failure',{}).get('pc'),preserved=True)
with rawpy.imread(str(EVIDENCE/'qemu-nef-save/serialization-fixture.NEF')) as raw:
    s=raw.sizes
    report['initial_trials']['qemu-nef-save']=dict(decodes=True,all_zero=bool(np.all(raw.raw_image==0)),
        recommended_crop_within_raw=(s.crop_left_margin+s.crop_width<=s.raw_width and s.crop_top_margin+s.crop_height<=s.raw_height))
    assert not report['initial_trials']['qemu-nef-save']['recommended_crop_within_raw']
r=json.loads((EVIDENCE/'qemu-nef-markers/result.json').read_text())
with rawpy.imread(str(EVIDENCE/'qemu-nef-markers/serialization-fixture.NEF')) as raw:
    pixels=raw.raw_image;v=np.array(r['raw_payload']['marker_values'],dtype=np.uint16);xx=np.arange(pixels.shape[1])
    bad=sum(int(np.count_nonzero(pixels[y]!=v[(xx+y)%len(v)])) for y in range(pixels.shape[0]))
    assert bad>0
    report['initial_trials']['qemu-nef-markers']=dict(decodes=True,packing='MSB-first trial',marker_mismatches=bad,
        resolution='LSB-first payload trial verified separately; failed file retained.')
deps=['probe_raw_candidates.py','probe_release_contract.py','record_research_command.py','inspect_native.py',
    'probe_nef_constructor.py','qemu_nef_header_probe.py','probe_nef_length.py','audit_nef.py','verify_nef_save.py',
    'snapshot_nef_sources.py','finalize_nef_record.py']
report['script_sha256']={}
for name in deps:
    path=ROOT/'tools/fw'/name;ast.parse(path.read_text(encoding='utf-8'))
    report['script_sha256'][name]=file_sha(path)
linux=Path(r'\\wsl.localhost\Ubuntu-24.04\home\z6lab\z6lab\z6-qemu')
report['linux_model_sources']={name:file_sha(linux/'qemu'/name) for name in MODELS}
assert report['linux_model_sources']==MODELS
depdir=EVIDENCE/'runtime-dependencies';depdir.mkdir(exist_ok=False)
for name in ('interactive.py','probe.py','rsp.py'):
    data=(linux/'tools'/name).read_bytes();(depdir/name).write_bytes(data)
report['linux_python_dependencies']={name:file_sha(depdir/name) for name in ('interactive.py','probe.py','rsp.py')}
expected_failures={'03-nef-header-attempt':1,'05-qemu-nef-header':1,'06-qemu-header-trace':1,'09-qemu-header-backing':1}
for path in sorted((EVIDENCE/'commands').glob('*/command.json')):
    r=json.loads(path.read_text())
    if 'exit_code' not in r:
        report.setdefault('commands_running_when_indexed',[]).append(path.parent.name);continue
    assert r['exit_code']==expected_failures.get(path.parent.name,0),(path,r['exit_code'])
    report['commands'][path.parent.name]=r['exit_code']
docs=['docs/RAW_NEF_SAVE_2026-11-08.md','docs/Z6_SAMPLE_CAPTURE_2026-11-08.md']
links=[]
for name in docs:
    source=ROOT/name;body=source.read_text(encoding='utf-8')
    for match in re.finditer(r'\]\(([^\n)]+)\)',body):
        dest=match[1]
        if '://' in dest or dest.startswith('#'):continue
        dest=dest.split('#')[0]
        resolved=(source.parent/dest).resolve()
        assert resolved.exists(),(name,dest)
        links.append(dict(source=name,target=resolved.relative_to(ROOT).as_posix()))
report['local_links']=links
for folder in sorted(EVIDENCE.glob('qemu-*')):
    if not (folder/'serialization-fixture.NEF').exists():continue
    (folder/'FIXTURE_NOTICE.txt').write_text(
        '本目录 NEF 是编码后人工数据的封装测试文件，不是真机拍摄。\n'
        '原厂头部／分块代码执行，103fabac 由主机文件写入适配器承接。\n'
        '暗电流、RAW 校正关闭、消圈及硬件编码效果均不由此文件证明。\n'
        '像素来源、适用范围与 SHA-256 见同目录 result.json。\n',encoding='utf-8')
curated=json.loads((EVIDENCE/'curated-save-code.json').read_text());assert all(r['decoded_to_end'] for r in curated['ranges'])
report['curated_ranges']=len(curated['ranges'])
report['files']={}
running=set(report.get('commands_running_when_indexed',[]))
for path in sorted(EVIDENCE.rglob('*')):
    if not path.is_file() or path==a.output.resolve() or '__pycache__' in path.parts:continue
    rel=path.relative_to(EVIDENCE)
    if rel.parts[0]=='commands' and len(rel.parts)>1 and rel.parts[1] in running:continue
    report['files'][rel.as_posix()]=dict(size=path.stat().st_size,sha256=file_sha(path))
report['documentation_sha256']={name:file_sha(ROOT/name) for name in docs+[
    'README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md']}
a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
print(json.dumps(dict(files=len(report['files']),links=len(links),commands=len(report['commands']),
    expected_failed_commands=len(expected_failures),initial_msb_mismatches=bad)))

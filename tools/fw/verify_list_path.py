"""Check the saved observations that support LIST_PATH_2026-11-02.md."""
from pathlib import Path
from collections import Counter
import ast
import hashlib
import json
import re
import struct

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/list-path-2026-11-02'
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8'))

def main():
    expected={
        'firmware/original/Z_6_0380.bin':'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
        'firmware/decoded/eg1620_038000.bi':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
        'firmware/decoded/ex1620_037000.bi':'72f1fb29e24b36b872eec697a486abeff8bcef77f6020fa89473fd014aa18131',
        'firmware/decoded/vr1620_010200.bi':'48aaa4d82d709ff6a97b9618cfdbbb706304588642a7f1a73bfc4a525c22a37a',
        'firmware/decoded/_tpj01_v140.bin':'e60998537d46a15c430154aeeb589026aca015256d27e2d5990589d23a59c88e',
    }
    for name,sha in expected.items():assert digest(ROOT/name)==sha, name
    runtime=read(OUT/'runtime/result.json')
    assert runtime['ok'] and runtime['firmware_unchanged']
    events=read(OUT/'runtime/path-observations.json')
    counts=Counter(e['event'] for e in events)
    def named(name):return [e for e in events if e['event']==name]
    assert len(events)==runtime['path_observation_count']
    assert counts['list_builder_exit']==1
    blob=(OUT/'runtime'/named('list_builder_exit')[0]['memory']['all_list_groups']['file']).read_bytes()
    assert blob==(b'\xff'*4+bytes(508))*456+bytes(6*0x39000)
    assert counts['list_mmio_write_before']==counts['list_mmio_write_after']==counts['selected_list_bus_address']==7
    for event in named('list_group_select'):assert int(event['registers']['r0'],16)==6
    for event in named('selected_list_bus_address'):
        regs=event['registers']
        assert int(regs['r5'],16)==int(regs['r0'],16)+6*0x39000==0x8d41e400
        assert event['memory']['selected_bus_head']['zero_bytes']==128
    for event in named('list_mmio_write_before'):
        assert int(event['mmio_address'],16)==0x2006b3e0 and int(event['value_to_write'],16)==0x8d41e400
        structure=bytes.fromhex(event['memory']['programming_structure']['head'])
        assert struct.unpack_from('<I',structure,0x18)[0]==0x8d41e400
    for event in named('list_source_set')+named('list_builder_entry'):
        source=event['memory']['source']
        assert source['bytes']==source['zero_bytes']==0xdfff8
        assert source['sha256']==hashlib.sha256(bytes(0xdfff8)).hexdigest()
        entries=bytes.fromhex(event['memory']['resource_b_c_directory']['head'])
        assert struct.unpack_from('<I',entries,8)[0]==0x80400000
        assert struct.unpack_from('<I',entries,36)[0]==0x80660000
    assert counts['resource_b_mode_load']==counts['resource_b_mode_null_fallback']==7
    assert not counts['resource_b_upload_pointer']
    synth=read(OUT/'synthetic-layout.json')
    assert synth['firmware_unchanged'] and len(synth['resource_b_pointer_cases'])==28
    assert all(c['matches_independent_expected'] and c['tail_guard_unchanged'] for c in synth['list_cases'])
    assert synth['list_cases'][1]['all_other_groups_untouched']
    assert all(x['decoded_to_end'] for x in read(OUT/'curated-native.json')['ranges'])
    source=ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu/nikon-z6.c'
    ctext=source.read_text()
    mentions=[dict(line=i,text=line.strip()) for i,line in enumerate(ctext.splitlines(),1) if 'capture_filter2_config' in line]
    assert len(mentions)==3
    for name in ('inspect_native.py','probe_list_layout.py','qemu_baseline_probe.py','qemu_path_observer.py','verify_list_path.py'):
        ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf-8'))
    doc=ROOT/'docs/LIST_PATH_2026-11-02.md'
    for link in re.findall(r'\]\(([^)]+)\)',doc.read_text(encoding='utf-8')):
        if '://' not in link:assert (doc.parent/link).exists() or link.endswith('verification.json'),link
    files=sorted(p for p in OUT.rglob('*') if p.is_file() and p.name!='verification.json')
    files += [doc,ROOT/'docs/NEXT_STEPS.md',ROOT/'docs/POST_REBOOT_2026-11-02.md',ROOT/'README.md']
    files += [ROOT/'tools/fw'/n for n in ('inspect_native.py','probe_list_layout.py','qemu_baseline_probe.py','qemu_path_observer.py','verify_list_path.py')]
    report=dict(ok=True,firmware_hashes_unchanged=expected,runtime_events=len(events),event_counts=counts,
                qemu_source_sha256=digest(source),qemu_filter2_mentions=mentions,
                assertions=['all seven runtime groups checked','selected group 6 and MMIO address/value agree',
                            'source length and all-zero digest checked','both independent synthetic layouts match',
                            '28 native pointer cases passed','curated ranges decode to specified boundaries',
                            'local document links and Python syntax valid'],
                evidence=[dict(file=str(p.relative_to(ROOT)).replace('\\','/'),bytes=p.stat().st_size,sha256=digest(p)) for p in files])
    (OUT/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=True,runtime_events=len(events),evidence_files=len(files),event_counts=counts),indent=2))

if __name__=='__main__':main()

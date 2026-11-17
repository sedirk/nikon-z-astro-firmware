"""Recheck saved native code/dataflow evidence, not camera RAW pixel behavior."""
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'analysis/raw-nef-influence-2026-11-03'
BASE = 0x10020000
COMMIT = '419a1f2a91a1f2d3a0209027c29606475f7fe26f'

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def u32(data, off=0):
    return struct.unpack_from('<I',data,off)[0]

def u16(data, off=0):
    return struct.unpack_from('<H',data,off)[0]

def memory(area):
    data=bytes.fromhex(area['bytes'])
    assert len(data)==area['size']
    assert hashlib.sha256(data).hexdigest()==area['sha256']
    return data

def check_memory_tree(value):
    if isinstance(value,dict):
        if {'bytes','size','sha256'} <= value.keys():
            memory(value)
        for child in value.values():
            check_memory_tree(child)
    elif isinstance(value,list):
        for child in value:
            check_memory_tree(child)

def main():
    assert __debug__, 'Run without -O.'
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    previous=read(ROOT/'analysis/raw-preprocess-2026-11-03/verification.json')
    hashes=previous['firmware_hashes_unchanged']
    assert len(hashes)==5
    for name,digest in hashes.items():
        assert sha(ROOT/name)==digest, name
    eg_sha=hashes['firmware/decoded/eg1620_038000.bi']
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    metrics={}
    absent={'still_raw_processing_entry','processing_submit_wrapper','processing_packet_builder',
            'instance_1_queue_submit','still_raw_encoding_entry','file_package_builder'}
    for name,count in (('native-source',64),('native-front-register',78)):
        path=OUT/name
        run,rows=read(path/'result.json'),read(path/'events.json')
        assert run['ok'] and run['firmware_unchanged'] and run['firmware_sha256']==eg_sha
        assert run['upstream_commit']==COMMIT and run['event_count']==len(rows)==count
        assert sha(path/'probe-source.py')==run['probe_sha256']
        check_memory_tree(run)
        check_memory_tree(rows)
        calls=[c['result'] for c in run['calls']]
        assert [c['function'] for c in calls]==['0x101efaa8','0x101eedb4','0x10170cca','0x10170cca']
        assert calls[1]['payload']=='0000010000000000000000000000000001000000000000000000000000000000'
        assert int(calls[1]['return_r0'],16)==0
        assert calls[2]['arguments']==['0x64'] and calls[3]['arguments']==['0x1388']
        actions=[json.loads(s) for s in (path/'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boot,=[x for x in actions if x['kind']=='boot']
        assert not boot['firmware_modified'] and not boot['camera_access'] and boot['guest_state_modified']
        assert boot['build']['binary_sha256']==previous['recorded_qemu_binary_sha256']
        assert boot['build']['sources']['qemu/nikon-z6.c']==previous['qemu_source_sha256']
        assert not any(len(x['result']['trace'])>=256 for x in actions if x['kind']=='original_firmware_call')
        counts=Counter(row['event'] for row in rows)
        assert not absent & counts.keys()
        for row in rows:
            assert run['points'][row['registers']['r15']]==row['event']
            areas=row['memory']
            if row['event']=='source_parameter_callback_dispatch':
                assert row['callback']=='0x100bcd87'
            if row['event']=='source_offset_register_packer':
                assert row['registers']['r14']=='0x100bcd5b'
                assert memory(areas['source_offset_register_input'])==bytes(12)
            if row['event']=='offset_calibration_lookup':
                ctx=memory(areas['calibration_context'])
                assert u32(ctx,0x14)==0xc9700000
                table=areas['offset_calibration_table']
                assert int(table['address'],16)==0xc9700000+0xbc7f6
                assert memory(table)==bytes(7*33*12)
        if name=='native-front-register':
            assert counts['source_offset_register_packer']==6 and counts['source_callback']==6
        assert memory(run['final']['config_3e1'])==b'\0'
        assert memory(run['final']['processing_mode_global'])[0]==1
        metrics[name]=dict(events=count,counts=dict(counts),unobserved_entries=sorted(absent))

    for name,count in (('isolated-influence',20),('isolated-influence-v2',20),
                       ('isolated-influence-v3',21),('isolated-influence-v4',25)):
        run=read(OUT/name/'result.json')
        assert run['ok'] and run['firmware_unchanged'] and run['firmware_sha256']==eg_sha
        assert len(run['cases'])==count and sha(OUT/name/'probe-source.py')==run['probe_sha256']
        check_memory_tree(run)
        for case in run['cases']:
            assert all(c['stopped_at']==c['until'] for c in case['calls'])
    run=read(OUT/'isolated-influence-v4/result.json')
    assert run['unmapped_payloads']==['0x60000000','0x62000000','0x64000000','0x66000000']
    cases={c['name']:c for c in run['cases']}
    assert len(cases)==25
    for flag in (0,1,2):
        value=0 if flag else 300
        c=cases[f'config-to-four-slots-{flag}']
        assert c['scalar']==value and c['negative_halfwords']==[(-value)&65535]*4
        assert memory(c['owner'])==struct.pack('<4H',*([value]*4))
        c=cases[f'config-to-nef-blacklevel-{flag}']
        assert c['tag_id']=='0x003d' and c['values']==[value]*4
        assert memory(c['tag_payload'])==memory(c['owner'])==struct.pack('<4H',*([value]*4))
        assert memory(c['tag_entry'])==struct.pack('<HHII',0x3d,3,4,0x100)
        assert u32(memory(c['package_request']),4)==0x50000000
        assert u32(memory(c['raw_descriptor']),8)==0x64000000
        assert '0x1028a9d8' in c['calls'][-1]['blocks']
    for flag,gate in ((0,0),(1,0),(2,0),(0,1)):
        c=cases[f'source-packet-{flag}-{gate}']
        value=0 if flag or gate else 300
        assert c['record']==[101,202,303,value,405]
        assert c['source_registers']==[(101<<16)|202,(303<<16)|value,405]
        assert memory(c['context'])[0x5b]==flag
        assert c['calls'][-1]['stopped_at']=='0x100d7de2'
    for flag in (0,1):
        c=cases[f'parameter-finalizer-{flag}']
        assert c['gains']==([512]*4 if flag else [768,512,512,1024])
        assert c['negatives']==[0xfed4]*4
    for bank in (0,1):
        for mode in (0,1):
            c=cases[f'offset-dispatch-{bank}-{mode}']
            skip=bank==1 and mode==1
            assert c['skipped_normal_configuration']==skip
            assert c['registers']['0x3ec']==(0x5a5a5a5a if skip else 0x62000000)
            assert c['registers']['0x710']==c['registers']['0x714']==(0x5a5a5a5a if skip else 0x1ed41ed4)
    for c in run['cases']:
        if not c['name'].startswith('raw-handoff-'):
            continue
        request=memory(c['request'])
        assert u32(request,0x374)==(0 if c['global_flag'] else 1)
        assert c['replacement']==(c['owner_mode']==0 and c['output_present'])
        assert c['final_input_handle']==('0x5001b100' if c['replacement'] else '0x5001b000')
        assert c['encoder_reached']==(c['owner_mode']==0)
        if c['encoder_reached']:
            assert int(c['calls'][-1]['r0'],16)==int(c['final_input_handle'],16)+0x24
            assert c['calls'][-1]['r1']=='0x5001b250'
    assert cases['encoded-descriptor-to-container']['raw_payload_bytes']==0x123456
    assert cases['nef-raw-stream-chunk']['order']==[0,7,8,5,6,3]
    assert cases['nef-raw-stream-chunk']['chunk']==[0x64000000,0x123456,0]
    assert 0x3d in cases['nef-makernote-selection']['tags']
    inventory=read(OUT/'config-and-tag-inventory.json')
    assert inventory['firmware_sha256']==eg_sha
    assert len(inventory['config_immediate_consumers'])==7
    for c in inventory['config_immediate_consumers']:
        for i in c['instructions']:
            pc=int(i['pc'],16)
            assert blob[pc-BASE:pc-BASE+len(bytes.fromhex(i['bytes']))]==bytes.fromhex(i['bytes'])
    for entry in inventory['metadata'].values():
        if isinstance(entry,dict) and 'rom' in entry:
            start=int(entry['rom'],16)-BASE
            value=bytes.fromhex(entry['bytes'])
            assert blob[start:start+len(value)]==value
    assert inventory['metadata']['tag_id']=='0x3d' and inventory['metadata']['count']==4
    assert inventory['metadata']['callback']=='0x1028a9d9'
    assert inventory['metadata']['selected_tags']==cases['nef-makernote-selection']['tags']

    curated=read(OUT/'curated-evidence.json')
    assert curated['firmware_sha256']==eg_sha and len(curated['ranges'])==36
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    for span in curated['ranges']:
        lo,hi=int(span['start'],16),int(span['end'],16)
        decoded=list(md.disasm(blob[lo-BASE:hi-BASE],lo))
        assert span['decoded_to_end'] and decoded[-1].address+decoded[-1].size==hi
        assert len(decoded)==len(span['instructions'])
        for ins,row in zip(decoded,span['instructions']):
            assert (hex(ins.address),ins.bytes.hex(),ins.mnemonic,ins.op_str)==(
                row['pc'],row['bytes'],row['mnemonic'],row['operands'])
            if 'literal_address' in row:
                assert u32(blob,int(row['literal_address'],16)-BASE)==int(row['literal_value'],16)
    source=read(OUT/'exiftool-nikon-tags.source.json')
    assert sha(OUT/'exiftool-nikon-tags.html')==source['sha256']
    html=(OUT/'exiftool-nikon-tags.html').read_text(encoding='utf-8')
    row=html[html.index("title='0x003d"):].split('</tr>',1)[0]
    assert 'BlackLevel' in row and 'int16u[4]' in row

    scripts=[ROOT/'tools/fw'/n for n in ('probe_nef_influence.py','qemu_nef_influence_probe.py',
        'inspect_nef_influence.py','inspect_native.py','record_research_command.py','verify_nef_influence.py')]
    for path in scripts+list(OUT.rglob('probe-source.py')):
        ast.parse(path.read_text(encoding='utf-8'))
    docs=[ROOT/n for n in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md',
        'docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_NEF_INFLUENCE_2026-11-03.md')]
    for path in docs:
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target=(path.parent/link.split('#')[0]).resolve()
                assert target.exists() or target==OUT/'verification.json', (path,link)
    for path in scripts[:3]+[scripts[-1],docs[-1]]:
        assert all(line==line.rstrip() for line in path.read_text(encoding='utf-8').splitlines()), path
    pending=[]
    for path in sorted((OUT/'commands').glob('*/command.json')):
        command=read(path)
        if 'exit_code' not in command:
            assert any('verify_nef_influence.py' in x for x in command['argv'])
            pending.append(path.parent.name)
        else:
            assert command['exit_code']==0, path
    qemu_source=ROOT/f'work/src/z6-qemu-{COMMIT}/qemu/nikon-z6.c'
    assert sha(qemu_source)==previous['qemu_source_sha256']
    evidence=[p for p in OUT.rglob('*') if p.is_file() and p.name!='verification.json'
              and not any(q in p.parts for q in pending)]
    report=dict(ok=True,generated_at_utc=datetime.now(timezone.utc).isoformat(),
        firmware_hashes_unchanged=hashes,native_runs=metrics,isolated_case_count=25,
        curated_range_count=36,config_direct_consumer_count=7,
        current_verification_record_pending=pending,
        recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        qemu_source_sha256=previous['qemu_source_sha256'],
        scripts={p.relative_to(ROOT).as_posix():sha(p) for p in scripts},
        docs={p.relative_to(ROOT).as_posix():sha(p) for p in docs},
        evidence_sha256={p.relative_to(OUT).as_posix():sha(p) for p in sorted(evidence)},
        scope='Saved original-code executions, metadata bytes and descriptor/MMIO dataflow. '
              'No complete NEF, physical RAW pixel effect, dark-current preservation or ring removal verified.')
    (OUT/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('ok','isolated_case_count','curated_range_count',
                     'config_direct_consumer_count')},indent=2))

if __name__=='__main__':
    main()

"""Audit saved C3.80 routing evidence; does not validate camera pixel behavior."""
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-output-routing-2026-11-03'
BASE=0x10020000

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def check_memory(value):
    if isinstance(value,dict):
        if {'bytes','size','sha256'}<=value.keys():
            data=bytes.fromhex(value['bytes'])
            assert len(data)==value['size']
            assert hashlib.sha256(data).hexdigest()==value['sha256']
        for child in value.values():
            check_memory(child)
    elif isinstance(value,list):
        for child in value:
            check_memory(child)

def main():
    assert __debug__, 'Run without -O.'
    previous=read(ROOT/'analysis/raw-nef-influence-2026-11-03/verification.json')
    hashes=previous['firmware_hashes_unchanged']
    assert len(hashes)==5
    for name,digest in hashes.items():
        assert sha(ROOT/name)==digest,name
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    versions={}
    for name,count,ok in (('isolated-routing',0,False),('isolated-routing-v2',15,True),
                          ('isolated-routing-v3',17,True),('isolated-routing-v4',23,True),
                          ('isolated-routing-v5',23,False),('isolated-routing-v6',25,True)):
        result=read(OUT/name/'result.json')
        assert result['case_count']==len(result['cases'])==count
        assert result['ok']==ok and result['firmware_unchanged']
        assert result['firmware_sha256']==hashes['firmware/decoded/eg1620_038000.bi']
        assert sha(OUT/name/'probe-source.py')==result['probe_sha256']
        check_memory(result)
        versions[name]=dict(ok=ok,completed_cases=count)
    final=read(OUT/'isolated-routing-v6/result.json')
    assert sha(ROOT/'tools/fw/probe_raw_routing.py')==final['probe_sha256']
    cases={c['name']:c for c in final['cases']}
    assert len(cases)==25
    segments=0
    mmio_writes=0
    for case in cases.values():
        for call in case['calls']:
            assert call['until']==call['stopped_at']
            assert call['blocks'] and int(call['blocks'][0],16)==int(call['entry'],16)
            segments+=1
            for write in call['writes']:
                addr=int(write['address'],16)
                assert 0x20380000<=addr<0x20390000 or 0x203c0000<=addr<0x203d0000
                mmio_writes+=1
    for gain,limits in ((256,(16383,16683)),(512,(32466,32767)),(1024,(32767,32767))):
        for flag,limit in enumerate(limits):
            c=cases[f'config-adjacent-limit-{gain}-{flag}']
            assert c['capped_parameter']==limit and c['third_values']==[300]*4
            assert c['scalar']==(300 if flag==0 else 0)
            assert c['registers']['0x720']==hex(limit)
            table=c['selected_original_table']
            start=int(table['address'],16)-BASE
            assert blob[start:start+table['size']]==bytes.fromhex(table['bytes'])
            assert c['registers']['0x718']==c['registers']['0x71c']=='0x12c012c'
    for scalar in (0,300):
        c=cases[f'cached-adjacent-values-{scalar}']
        assert c['registers']['0x720']=='0x3039'
        assert c['calls'][0]['stopped_at']=='0x1019f3d0'
        assert '0x1019f3d0' not in c['calls'][0]['blocks']
        assert '0x1019f10c' not in c['calls'][0]['blocks']
    for name in ('ordinary-zero','excluded-bit','excluded-mode','cached-polynomial'):
        c=cases['spatial-'+name]
        assert c['packed_tables']['bytes']==c['hardware_table_writes']['bytes']
        assert c['bank1_registers']['0x3ec']=='0x62000000'
        assert c['bank1_registers']['0x710']==c['bank1_registers']['0x714']=='0x1ed41ed4'
    native=read(OUT/'native-existing-summary.json')
    assert sha(ROOT/native['source'])==native['source_sha256']
    assert len(native['rows'])==16 and native['events_total']==78
    assert Counter(r['event'] for r in native['rows'])=={
        'processing_driver':5,'parameter_pointer_builder':6,'four_slot_parameter_generator':5}
    for row in native['rows']:
        if row['event']=='processing_driver':
            assert row['raw_output_pointer']=='0x0' and row['control_bytes']==[1,0,0,0,0]
        if row['event']=='four_slot_parameter_generator':
            assert row['scalar']==0 and row['gain']==512 and row['third_halfwords']==[300]*4
            assert row['capped_parameter']==32767 and row['cached_parameter_selector']==0

    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    instructions=0
    for path in OUT.glob('*.json'):
        report=read(path)
        for span in report.get('ranges',[]):
            if path.name=='curated-evidence-v2.json':
                assert span['decoded_to_end'],span
            for ins in span['instructions']:
                pc=int(ins['pc'],16)
                data=bytes.fromhex(ins['bytes'])
                assert blob[pc-BASE:pc-BASE+len(data)]==data
                decoded=list(md.disasm(data,pc))
                assert len(decoded)==1
                assert (decoded[0].mnemonic,decoded[0].op_str)==(ins['mnemonic'],ins['operands'])
                if 'literal_address' in ins:
                    offset=int(ins['literal_address'],16)-BASE
                    assert struct.unpack_from('<I',blob,offset)[0]==int(ins['literal_value'],16)
                instructions+=1
    assert len(read(OUT/'curated-evidence-v2.json')['ranges'])==31

    commands={}
    for path in sorted((OUT/'commands').glob('*/command.json')):
        command=read(path)
        if 'exit_code' not in command:
            assert any('verify_raw_routing.py' in arg for arg in command['argv'])
            continue  # The current recorder writes its exit code after us.
        commands[path.parent.name]=command['exit_code']
    failures={k:v for k,v in commands.items() if v!=0}
    assert failures=={'10-routing-probe':1,'11-constructor-calibration':2,'27-routing-probe':1},failures
    documents=['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md',
               'docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_NEF_INFLUENCE_2026-11-03.md',
               'docs/RAW_OUTPUT_ROUTING_2026-11-03.md']
    checked_links=0
    for name in documents:
        path=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in link or link.startswith('#'):
                continue
            target=(path.parent/link.split('#')[0]).resolve()
            if target==OUT/'verification.json':
                continue
            assert target.exists(),(name,link)
            checked_links+=1
    scripts=['tools/fw/probe_raw_routing.py','tools/fw/inspect_raw_routing.py','tools/fw/verify_raw_routing.py']
    for name in scripts:
        ast.parse((ROOT/name).read_text(encoding='utf-8'))
    qemu_source=ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu/nikon-z6.c'
    assert sha(qemu_source)==previous['qemu_source_sha256']
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    artifacts={str(path.relative_to(ROOT)):sha(path) for path in OUT.rglob('*')
               if path.is_file() and path.name!='verification.json' and 'commands' not in path.parts}
    artifacts.update({name:sha(ROOT/name) for name in documents+scripts})
    result=dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),firmware_hashes_unchanged=hashes,
                qemu_source_sha256=sha(qemu_source),qemu_rerun_this_round=False,
                latest_cases=25,segments=segments,recorded_mmio_writes=mmio_writes,
                versions=versions,native_existing_rows=16,curated_ranges=31,
                disassembled_instructions_checked=instructions,local_links_checked=checked_links,
                command_exit_codes=commands,expected_failed_commands=failures,artifacts=artifacts,
                limitation='Validates recorded software evidence, not silicon pixel semantics or NEF output.')
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('ok','latest_cases','segments','recorded_mmio_writes',
                                         'curated_ranges','disassembled_instructions_checked','local_links_checked')}))

if __name__=='__main__':
    main()

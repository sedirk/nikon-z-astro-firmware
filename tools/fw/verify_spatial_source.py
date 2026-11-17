"""Audit saved parameter-source evidence; does not validate camera pixels."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-spatial-source-2026-11-03'
BASE=0x10020000

def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def raw(row):return bytes.fromhex(row['bytes'])

def memory_check(obj):
    if isinstance(obj,dict):
        if {'bytes','size','sha256'}<=obj.keys():
            data=raw(obj)
            assert len(data)==obj['size'] and hashlib.sha256(data).hexdigest()==obj['sha256']
        for child in obj.values():memory_check(child)
    elif isinstance(obj,list):
        for child in obj:memory_check(child)

def main():
    assert __debug__
    previous=read(ROOT/'analysis/raw-pixel-stage-2026-11-03/verification.json')
    hashes=previous['firmware_hashes_unchanged']
    assert len(hashes)==5
    for name,digest in {**hashes,**previous['model_sources_unchanged']}.items():
        assert sha(ROOT/name)==digest,name
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    versions={}
    for suffix,count,ok in [('',1,False)]+[(f'-v{i}',1,False) for i in range(2,6)]+[('-v6',5,True),('-v7',14,True)]:
        directory=OUT/('isolated-source'+suffix)
        result=read(directory/'result.json')
        assert result['ok']==ok and len(result['cases'])==count
        assert result['firmware_unchanged'] and result['firmware_sha256']==hashes['firmware/decoded/eg1620_038000.bi']
        assert sha(directory/'probe-source.py')==result['probe_sha256']
        memory_check(result)
        versions[directory.name]=dict(ok=ok,cases=count,accepted=ok)
    final=read(OUT/'isolated-source-v7/result.json')
    assert sha(ROOT/'tools/fw/probe_spatial_source.py')==final['probe_sha256']
    cases={c['name']:c for c in final['cases']}
    segments=prefixes=0
    for c in cases.values():
        for call in c['calls']:
            assert call['until']==call['stopped_at']
            assert call['blocks'][0]==call['entry']
            assert call['writes']==[] and call['source_registers']==[]
            segments+=1
            if call['until']!='0x53000000':
                assert call['entry']=='0x1015e970' and call['until']=='0x10164b5c'
                prefixes+=1
    assert (segments,prefixes)==(73,5)
    pipeline=['0x1015e0a0','0x101c2660','0x10072714','0x100c0eda',
              '0x10196fe4','0x10197500','0x101975be','0x10197678']
    conversion_reads={}
    for name in ('ordinary','alternate','wrap','source-inactive'):
        c=cases[name]
        assert [x['entry'] for x in c['calls']]==pipeline
        mult=3 if name=='alternate' else 1
        active=name!='source-inactive'
        coefficients=[16*mult,0,0,32*mult,0,0] if active else [0]*6
        assert c['coefficients']==coefficients
        assert list(struct.unpack('<34h',raw(c['table'])))==([mult]*17+[2*mult]*17 if active else [0]*34)
        index=0 if name=='wrap' else 1
        address=0xc2802f7c+index*0xda0
        assert c['selected_index']==index and int(c['cache']['address'],16)==address
        for key,offset,value in (('provider',12,address),('built',0x54,address+16),('properties',0x40,address+16)):
            assert struct.unpack_from('<I',raw(c[key]),offset)[0]==value
        grid=[0]*864
        if active:
            for knot in range(8):grid[knot*108]=16*mult;grid[knot*108+54]=32*mult
        assert list(struct.unpack_from('<864i',raw(c['cache']),16))==grid
        reads=[r for r in c['calls'][0]['reads'] if r['pc']=='0x1015e064']
        conversion_reads[name]=len(reads)
        assert len(reads)==(864 if active else 0)
        if active:
            start=int(c['source_packet']['address'],16)+10
            assert [int(r['address'],16) for r in reads]==list(range(start,start+3456,4))
            assert b''.join(raw(r) for r in reads)==raw(c['source_packet'])[10:3466]
            assert [x['id'] for x in c['calls'][0]['property_accesses']]==['0x1045','0x303e']
            assert ('0x1007a9dc' in c['calls'][0]['blocks'])==(name=='alternate')
        else:assert '0x1015e05e' not in c['calls'][0]['blocks']
    assert raw(cases['provider-type2']['provider'])==bytes(16)
    assert cases['provider-type2']['calls'][0]['r0']=='0x0'
    for state in range(5):
        c=cases[f'publish-state-{state}'];value=state if state in (1,2,3) else 0
        assert c['mapped']==value and c['calls'][0]['r0']=='0x1c14'
        assert int(c['calls'][0]['r1'],16)==value
        assert [x['entry'] for x in c['calls']]==['0x1015e970','0x10070366','0x1017039e']
        assert int(c['calls'][-1]['r0'],16)==value
        assert struct.unpack('<I',raw(c['property_value']))[0]==value
        assert raw(c['state_memory'])[0x18]==state
    unchanged=cases['publisher-unchanged']['calls'][0]
    assert unchanged['r0']=='0x0' and '0x10164b5c' not in unchanged['blocks']
    for state in (0,2,3):
        c=cases[f'builder-state-{state}'];props=raw(c['properties'])
        assert c['coefficients']==[0]*6 and raw(c['table'])==bytes(68)
        assert raw(c['built'])[0]==(3 if state==3 else 0)
        assert props[0x2c]==0 and props[0x40:0x44]==bytes(4) and props[0x48]==int(state==3)
    minimal=read(OUT/'minimal-branch.json')['rows']
    assert len(minimal)==4
    for c in minimal:assert c['r1']=='0x303e' and c['stored']=='451000003e300000'

    metadata=read(OUT/'source-metadata-v2.json')
    assert metadata['property']['value_address']=='0xc24cd198' and metadata['property']['type']==7
    for row in [metadata['property']['group'],metadata['property']['descriptor']]+metadata['property_arrays']+metadata['buffer_descriptors']:
        offset=int(row['address'],16)-BASE
        assert blob[offset:offset+row['size']]==raw(row)
    for address in (0x10163d5c,0x1015c370):
        assert blob[address-BASE:address-BASE+11]==b'LensInfo.c\x00'
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    instruction_count=0
    for path in OUT.glob('*.json'):
        obj=read(path);memory_check(obj)
        if not isinstance(obj,dict):continue
        for span in obj.get('ranges',[]):
            start,end=int(span['start'],16),int(span['end'],16)
            decoded=list(md.disasm(blob[start-BASE:end-BASE],start))
            assert len(decoded)==len(span['instructions'])
            if path.name=='curated-evidence.json':assert span['decoded_to_end']
            for ins,row in zip(decoded,span['instructions']):
                assert (hex(ins.address),ins.bytes.hex(),ins.mnemonic,ins.op_str)==(row['pc'],row['bytes'],row['mnemonic'],row['operands'])
                if 'literal_address' in row:
                    assert struct.unpack_from('<I',blob,int(row['literal_address'],16)-BASE)[0]==int(row['literal_value'],16)
                instruction_count+=1
    assert len(read(OUT/'curated-evidence.json')['ranges'])==26
    commands={}
    for path in sorted((OUT/'commands').glob('*/command.json')):
        command=read(path)
        if 'exit_code' not in command:
            assert any('verify_spatial_source.py' in x for x in command['argv'])
            continue
        commands[path.parent.name]=command['exit_code']
    failures={k:v for k,v in commands.items() if v}
    assert failures=={name:1 for name in ('09-source-chain-probe','10-source-chain-probe',
                    '11-source-property-trace','12-source-stack-trace','13-source-instruction-trace')},failures
    documents=['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md',
               'docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_PIXEL_STAGE_2026-11-03.md',
               'docs/RAW_SPATIAL_SOURCE_2026-11-03.md']
    links=0
    for name in documents:
        path=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in link or link.startswith('#'):continue
            target=(path.parent/link.split('#')[0]).resolve()
            if target!=OUT/'verification.json':assert target.exists(),(name,link)
            links+=1
    scripts=['tools/fw/'+x for x in ('probe_spatial_source.py','inspect_spatial_source.py',
                                    'check_spatial_branch.py','verify_spatial_source.py')]
    for name in scripts:ast.parse((ROOT/name).read_text(encoding='utf-8'))
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    artifacts={str(path.relative_to(ROOT)):sha(path) for path in OUT.rglob('*')
               if path.is_file() and path.name!='verification.json' and 'commands' not in path.parts}
    artifacts.update({name:sha(ROOT/name) for name in documents+scripts})
    result=dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),
        firmware_hashes_unchanged=hashes,model_sources_unchanged=previous['model_sources_unchanged'],
        qemu_rerun_this_round=False,latest_cases=14,segments=segments,bounded_prefixes=prefixes,
        conversion_reads=conversion_reads,curated_ranges=26,disassembled_instructions_checked=instruction_count,
        local_links_checked=links,versions=versions,command_exit_codes=commands,expected_failed_commands=failures,
        artifacts=artifacts,limitation='Validates original parameter-source code evidence, not real lens states, physical ISP behavior or saved NEF pixels.')
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('ok','latest_cases','segments','bounded_prefixes','conversion_reads',
                     'curated_ranges','disassembled_instructions_checked','local_links_checked')}))

if __name__=='__main__':main()

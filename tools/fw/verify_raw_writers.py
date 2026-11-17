"""Check saved writer/IRQ evidence against original firmware; no physical-pixel claims."""
from pathlib import Path
from datetime import datetime, timezone
import ast, hashlib, json, re, struct
import capstone

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-writers-2026-11-03'
BASE=0x10020000
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def raw(row):return bytes.fromhex(row['bytes'])
def value(row,offset,fmt='I'):return struct.unpack_from('<'+fmt,raw(row),offset)[0]
def memory_check(obj):
    if isinstance(obj,dict):
        if {'bytes','size','sha256'}<=obj.keys():
            data=raw(obj)
            assert len(data)==obj['size'] and hashlib.sha256(data).hexdigest()==obj['sha256']
        for child in obj.values():memory_check(child)
    elif isinstance(obj,list):
        for child in obj:memory_check(child)
def allcalls(case):
    return case['calls']+case.get('before',{}).get('calls',[])+case.get('after',{}).get('calls',[])

def main():
    assert __debug__
    prev=read(ROOT/'analysis/raw-spatial-source-2026-11-03/verification.json')
    firmware=prev['firmware_hashes_unchanged'];models=prev['model_sources_unchanged']
    assert len(firmware)==5 and len(models)==4
    for name,digest in {**firmware,**models}.items():assert sha(ROOT/name)==digest,name
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    versions={}
    for name,count,ok in [('isolated-writers',0,False),('isolated-writers-v2',8,True),
                          ('isolated-writers-v3',8,True),('isolated-completion',3,False),
                          ('isolated-completion-v2',15,True)]:
        result=read(OUT/name/'result.json');memory_check(result)
        assert result['ok']==ok and len(result['cases'])==count
        assert result['firmware_unchanged'] and result['firmware_sha256']==firmware['firmware/decoded/eg1620_038000.bi']
        assert sha(OUT/name/'probe-source.py')==result['probe_sha256']
        versions[name]=dict(ok=ok,cases=count)
    writers=read(OUT/'isolated-writers-v3/result.json');complete=read(OUT/'isolated-completion-v2/result.json')
    for filename,result in [('probe_raw_writers.py',writers),('probe_raw_completion.py',complete)]:
        assert sha(ROOT/'tools/fw'/filename)==result['probe_sha256']
    segments=prefixes=0;by_kind=[]
    for result in (writers,complete):
        count=0
        for case in result['cases']:
            for call in allcalls(case):
                assert call['stopped_at']==call['until']
                assert call['blocks'][0]==call['entry']
                count+=1;prefixes+=call['until']!='0x53000000'
        by_kind.append(count);segments+=count
    assert by_kind==[228,39] and segments==267
    metadata=read(OUT/'writer-metadata.json');memory_check(metadata)
    for row in [metadata['receiver_jump_table']]+[x['descriptor'] for x in metadata['rows']]:
        offset=int(row['address'],16)-BASE;assert blob[offset:offset+row['size']]==raw(row)
    descriptors={x['slot']:x for x in metadata['rows']}
    for slot,d in descriptors.items():
        entry=int(d['dispatch_entry'],16)
        assert int(d['dispatch_target'],16)==0x10131dee+2*blob[entry-BASE]
    pipeline=['0x1015e0a0','0x101c2660','0x10072714','0x100c0eda',
              '0x10196fe4','0x10197500','0x101975be','0x10197678']
    source_reads=0
    for case in writers['cases']:
        slot,index,success=case['slot'],case['initial_index'],case['success']
        desc=descriptors[slot];old=int(desc['buffers'][index],16);new=int(desc['buffers'][index^1],16)
        assert int(case['old_pointer'],16)==old and int(case['receive_pointer'],16)==new
        assert int(case['published_pointer'],16)==(new if success else old)
        assert (case['read_counter'],case['write_counter'])==(index+int(success),index+int(success)+1)
        req=case['request'];projection=case['projection'];transfer=case['transfer'];dma=case['dma_descriptor']
        assert raw(req)[4:6]==bytes((0x24,0x10 if slot==15 else 0x12))
        assert value(req,10,'H')==value(req,12,'H')==0xd8c
        assert value(req,16)==int(desc['staging'],16) and value(req,20)==new
        assert value(projection,20)==new and value(transfer,4)==new
        assert value(transfer,8)==value(transfer,12)==1734
        assert value(dma,4,'H')==1733 and value(dma,20)==new and value(dma,16)==0x50010804
        assert value(case['dma_register_cells'],12)==new and value(case['dma_register_cells'],8)==0x50010804
        assert value(case['dma_register_cells'],0)&0xffff==1733
        assert raw(case['scales'])==bytes((12,20))
        assert sum(raw(case['old_packet']))%256==0
        assert (sum(raw(case['received_packet']))%256==0)==success
        entry={x['entry']:x for x in case['calls']}
        assert entry['0x1007b0bc']['until']=='0x1007b168'
        assert entry['0x1008c6a0']['until']=='0x1008c6b2'
        assert entry['0x1008c754']['until']=='0x1008c772'
        assert entry['0x100d27be']['until']=='0x10068b06'
        assert int(entry['0x1008bd92']['registers']['r0'],16)==int(success)
        assert ('0x100c34be' in entry['0x10131d64']['blocks'])==success
        for phase,mult,ptr in [('before',1,old),('after',3 if success else 1,new if success else old)]:
            outcome=case[phase]
            assert [x['entry'] for x in outcome['calls']]==pipeline
            assert outcome['coefficients']==[16*mult,0,0,32*mult,0,0]
            assert list(struct.unpack('<34h',raw(outcome['table'])))==[mult]*17+[2*mult]*17
            expected=[0]*864
            for knot in range(8):expected[108*knot]=16*mult;expected[108*knot+54]=32*mult
            assert list(struct.unpack_from('<864i',raw(outcome['selected_cache']),16))==expected
            observed=[r for r in outcome['calls'][0]['reads'] if r['pc']=='0x1015e064']
            assert [int(r['address'],16) for r in observed]==list(range(ptr+10,ptr+3466,4))
            packet=case['received_packet'] if phase=='after' and success else case['old_packet']
            assert b''.join(raw(r) for r in observed)==raw(packet)[10:3466]
            source_reads+=len(observed)
    assert source_reads==16*864
    for case in complete['cases']:
        last=case['calls'][-1]
        if case['name'].startswith('bank'):
            bank=case['bank'];event=case['event_before_OS']
            assert [x['entry'] for x in case['calls'][:2]]==['0x1010615a','0x10105eae']
            assert last['entry']==('0x10105870' if bank else '0x101058ac')
            assert value(case['mmio'],8)==value(case['mmio'],16)==1
            assert value(case['mmio'],0x24)==case['synthetic_status']
            if event is None:assert last['until']=='0x53000000'
            else:
                assert last['until']=='0x10105264'
                assert int(last['registers']['r1'],16)==event
                assert int(last['registers']['r0'],16)==(0xc1d8833c if bank else 0xc1d881d0)
            assert case['peer_accumulator_fixture']=='0xffffffff'
        elif case['name'].startswith('completion'):
            assert last['entry']=='0x100d67d8' and last['until']=='0x10105264'
            assert last['registers']['r0']=='0xc1d8833c' and last['registers']['r1']=='0x8'
            assert case['state']=={'0x42170801':0,'0x4217080b':2,'0x42170806':1}[case['supplied_message']]
        else:
            assert last['entry']=='0x100ae3d2' and last['until']=='0x100ae438'
            assert int(last['args'][0],16)==case['injected_prior_return']
            assert list(struct.unpack('<2I',raw(case['before_handles'])))==[0x50003000,0x50004000]
            expected=[0x50004000,0x50003000] if case['has_output'] else [0x50003000,0x50004000]
            assert list(struct.unpack('<2I',raw(case['after_handles'])))==expected
            assert value(case['owner_field'],0)==0xabc002
            assert '0x100b555a' in last['blocks'] and '0x100d68b2' in last['blocks']
            for bank,call in enumerate(case['calls'][:2]):
                mmio=[r for r in call['reads'] if r['pc']=='0x10108978']
                assert len(mmio)==1 and int(mmio[0]['address'],16)==0x20380000+bank*0x40000+0x118
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);ins_count=0
    for path in OUT.glob('*.json'):
        obj=read(path)
        for span in obj.get('ranges',[]):
            start,end=int(span['start'],16),int(span['end'],16)
            ins=list(md.disasm(blob[start-BASE:end-BASE],start))
            assert len(ins)==len(span['instructions'])
            if path.name=='curated-evidence-v2.json':assert span['decoded_to_end']
            for native,row in zip(ins,span['instructions']):
                assert (hex(native.address),native.bytes.hex(),native.mnemonic,native.op_str)==(row['pc'],row['bytes'],row['mnemonic'],row['operands'])
                if 'literal_address' in row:assert struct.unpack_from('<I',blob,int(row['literal_address'],16)-BASE)[0]==int(row['literal_value'],16)
                ins_count+=1
    assert len(read(OUT/'curated-evidence-v2.json')['ranges'])==30
    commands={}
    for path in sorted((OUT/'commands').glob('*/command.json')):
        command=read(path)
        if 'exit_code' not in command:
            assert any('verify_raw_writers.py' in x for x in command['argv']);continue
        commands[path.parent.name]=command['exit_code']
    failures={k:v for k,v in commands.items() if v}
    assert failures=={'14-receive-publication-probe':1,'21-raw-completion-probe':1},failures
    documents=['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md',
               'docs/RAW_SPATIAL_SOURCE_2026-11-03.md','docs/RAW_WRITERS_2026-11-03.md']
    links=0
    for name in documents:
        path=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in link or link.startswith('#'):continue
            target=(path.parent/link.split('#')[0]).resolve()
            if target!=OUT/'verification.json':assert target.exists(),(name,link)
            links+=1
    scripts=['tools/fw/'+name for name in ('inspect_writer_metadata.py','probe_raw_writers.py','probe_raw_completion.py','verify_raw_writers.py')]
    for name in scripts:ast.parse((ROOT/name).read_text(encoding='utf-8'))
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    model=next(name for name in models if name.endswith('nikon-functional-isp.h'))
    lines=(ROOT/model).read_text(encoding='utf-8').splitlines()
    evidence=dict(path=model,sha256=sha(ROOT/model),lines=[dict(number=i,text=lines[i-1]) for i in range(1,76)],
        limitation='Unchanged local model source; no runtime or physical ISP validation.')
    (OUT/'model-dummy-evidence.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    artifacts={str(path.relative_to(ROOT)):sha(path) for path in OUT.rglob('*')
               if path.is_file() and path.name!='verification.json' and 'commands' not in path.parts}
    artifacts.update({name:sha(ROOT/name) for name in documents+scripts})
    result=dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),firmware_hashes_unchanged=firmware,
        model_sources_unchanged=models,qemu_rerun_this_round=False,latest_cases=23,segments=267,
        receive_segments=228,completion_segments=39,bounded_segments=prefixes,coefficient_reads_verified=source_reads,
        curated_ranges=30,disassembled_instructions_checked=ins_count,local_links_checked=links,
        versions=versions,command_exit_codes=commands,expected_failed_commands=failures,artifacts=artifacts,
        limitation='Checks saved native software evidence. Does not validate real DMA, physical ISP arithmetic, dark current or saved NEF pixels.')
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('ok','latest_cases','segments','bounded_segments','coefficient_reads_verified',
                                         'curated_ranges','disassembled_instructions_checked','local_links_checked')}))

if __name__=='__main__':main()

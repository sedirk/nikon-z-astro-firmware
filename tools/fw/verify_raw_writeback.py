"""Verify the Nov 4 native-buffer evidence, segmented replay and routing cases."""
from pathlib import Path
from datetime import datetime, timezone
import ast, gzip, hashlib, json, re, struct
import capstone

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-writeback-2026-11-04'
BASE=0x10020000
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def raw(row):return bytes.fromhex(row['bytes'])
def value(row,offset=0,fmt='I'):return struct.unpack_from('<'+fmt,raw(row),offset)[0]
def memory_check(obj):
    if isinstance(obj,dict):
        if {'bytes','size','sha256'}<=obj.keys():
            data=raw(obj);assert len(data)==obj['size'] and hashlib.sha256(data).hexdigest()==obj['sha256']
        for child in obj.values():memory_check(child)
    elif isinstance(obj,list):
        for child in obj:memory_check(child)

def main():
    assert __debug__
    prior=read(ROOT/'analysis/raw-writers-2026-11-03/verification.json')
    firmware=prior['firmware_hashes_unchanged'];models=prior['model_sources_unchanged']
    assert len(firmware)==5 and len(models)==4
    for name,digest in {**firmware,**models}.items():assert sha(ROOT/name)==digest,name
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    native_dir=OUT/'native-writeback';isolated_dir=OUT/'isolated-writeback'
    native=read(native_dir/'result.json');events=read(native_dir/'events.json')
    isolated=read(isolated_dir/'result.json')
    for folder,result,script in ((native_dir,native,'qemu_raw_writeback_probe.py'),
                                  (isolated_dir,isolated,'probe_raw_writeback.py')):
        assert result['ok'] and result['firmware_unchanged']
        assert result['firmware_sha256']==firmware['firmware/decoded/eg1620_038000.bi']
        assert sha(folder/'probe-source.py')==sha(ROOT/'tools/fw'/script)==result['probe_sha256']
        memory_check(result)
    memory_check(events)
    assert native['model_sources']=={Path(k).name:v for k,v in models.items()}
    for name,digest in isolated['observed_files'].items():assert sha(Path(name))==digest
    assert native['event_count']==len(events)==8 and len(isolated['cases'])==10
    still=[e for e in events if e['phase']=='native-settle']
    assert [e['event'] for e in still]==['still_lower_submit','front_full_geometry_entry',
        'front_full_geometry_built','front_primary_address_assignment','front_primary_descriptor_ready']
    obj=still[0]['memory']['still_object'];handle=still[0]['memory']['still_handle_1f8']
    assert value(obj,0x1f8)==int(handle['address'],16)
    address=value(handle,0x34);stride=value(handle,0x26,'H');width=value(handle,0x28,'H');height=value(handle,0x2a,'H')
    assert (address,stride,width,height,value(handle,0x24,'B'))==(0xa448e000,9168,6104,4222,2)
    assert raw(handle)==raw(native['final']['still_handle_1f8'])
    for event in still[1:]:
        assert event['memory']['still_object']['address']==obj['address']
        assert event['memory']['still_handle_1f8']['address']==handle['address']
    for event in still[1:3]:
        assert value(event['memory']['front_request'],4)==int(handle['address'],16)
        assert raw(event['memory']['front_handle'])==raw(handle)
    assert still[1]['registers']['r14']=='0x100c006f'
    assignment=still[3]['assignment'];ring=still[4]['memory']['front_parameters']
    assert assignment==dict(address='0xc25ee248',value=hex(address))
    assert value(ring,0x24)==address and value(ring,0x1a,'H')==stride
    assert value(ring,0,'B')==value(ring,1,'B')==0
    assert len(native['payloads'])==2
    payload_hashes=[]
    for record in native['payloads']:
        file=native_dir/record['file'];data=gzip.decompress(file.read_bytes())
        assert sha(file)==record['gzip_sha256'] and file.stat().st_size==record['gzip_size']
        assert len(data)==record['size']==stride*height==38707296
        assert hashlib.sha256(data).hexdigest()==record['sha256']
        assert len(data)-data.count(0)==record['nonzero_bytes']==0
        assert record['address']==hex(address) and record['handle']==handle['address']
        assert record['object']==obj['address']
        payload_hashes.append(record['sha256'])
    assert len(set(payload_hashes))==1
    segments=0
    for case in isolated['cases']:
        for call in case['calls']:
            assert call['stopped_at']==call['until'] and call['blocks'][0]==call['entry']
            segments+=1
        if case['name'].startswith('front-replay'):
            assert case['calls'][0]['entry']=='0x100bd820' and case['calls'][0]['until']=='0x100bd874'
            assert case['calls'][1]['entry']=='0x100bd5cc' and case['calls'][1]['until']=='0x53000000'
            assert raw(case['observed_geometry'])==raw(case['replayed_geometry'])
            assert raw(case['address_registers'])==raw(case['observed_ring'])[0x24:0x44]
            assert value(case['channel_registers'],8)==value(case['observed_ring'],0x1a,'H')
            expected=(2,6104<<16,4222<<16,0,0) if case['phase']=='native-settle' else (0,2034<<16,1434<<16,0,0)
            assert struct.unpack('<5I',raw(case['geometry_registers']))==expected
        else:
            mode,flag,exists=case['owner_mode'],case['owner_fileflag'],case['has_replacement']
            expected=exists and flag in (0,1) and mode not in (3,4,5,6)
            assert case['replacement_selected']==expected
            assert value(case['request'],8)==0x50005000
            assert value(case['request'],0x1a8)==(0x50006000 if expected else 0)
            assert case['calls'][0]['entry']=='0x100ae33e' and case['calls'][0]['until']=='0x100ae3b4'
            last=case['calls'][1];assert last['entry']=='0x100af648'
            if flag not in (0,1):assert last['until']=='0x53000000'
            elif mode in (3,4,5,6):
                assert last['until']=='0x101af8e6'
                assert int(last['registers']['r0'],16)==address and int(last['registers']['r1'],16)==stride*height
            else:
                assert last['until']=='0x100a323e'
                assert last['registers']['r0']=='0x50005024' and last['registers']['r1']=='0x50007050'
    assert segments==20
    log_path=native_dir/'session/qemu-1.log';log=log_path.read_text(encoding='utf-8').splitlines()
    writes=[dict(line=i+1,text=line) for i,line in enumerate(log)
            if line==f'Z6_PROCESSING_ADDRESS channel=0 offset=0x50 value={address:#010x} dma_completed=0']
    assert len(writes)==1
    streams=[i+1 for i,line in enumerate(log) if line.startswith('Z6_RAW_NATIVE0_STREAM ')]
    assert streams and max(streams)<writes[0]['line']
    samples=[dict(line=i+1,text=line) for i,line in enumerate(log) if line.startswith('Z6_RAW_NATIVE0_TEST ')]
    assert len(samples)==4 and all('destination=0xa448e000 ' not in row['text'] for row in samples)
    later={'still_raw_processing_entry','replacement_raw_address_configuration','still_raw_encoding_entry','raw_encoder_descriptor_entry'}
    assert not later&{e['event'] for e in events}
    modelname=next(name for name in models if name.endswith('nikon-z6.c'))
    model_lines=(ROOT/modelname).read_text(encoding='utf-8').splitlines()
    model_evidence=dict(path=modelname,sha256=sha(ROOT/modelname),
        ranges=[dict(first=lo,last=hi,lines=[dict(number=i,text=model_lines[i-1]) for i in range(lo,hi+1)])
                for lo,hi in ((1371,1425),(1973,2028))],
        limitation='Local model source and diagnostic log, not physical ISP behavior; source comments can use different firmware addresses.')
    (OUT/'model-source-evidence.json').write_text(json.dumps(model_evidence,indent=2),encoding='utf-8')
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);ins_count=0
    for path in OUT.glob('*.json'):
        for span in read(path).get('ranges',[]):
            if 'instructions' not in span:continue
            start,end=int(span['start'],16),int(span['end'],16)
            instructions=list(md.disasm(blob[start-BASE:end-BASE],start))
            assert len(instructions)==len(span['instructions'])
            if path.name=='curated-evidence.json':assert span['decoded_to_end']
            for ins,row in zip(instructions,span['instructions']):
                assert (hex(ins.address),ins.bytes.hex(),ins.mnemonic,ins.op_str)==(row['pc'],row['bytes'],row['mnemonic'],row['operands'])
                if 'literal_address' in row:assert struct.unpack_from('<I',blob,int(row['literal_address'],16)-BASE)[0]==int(row['literal_value'],16)
                ins_count+=1
    assert len(read(OUT/'curated-evidence.json')['ranges'])==20
    scripts=['tools/fw/'+name for name in ('qemu_raw_writeback_probe.py','probe_raw_writeback.py','verify_raw_writeback.py')]
    for name in scripts:ast.parse((ROOT/name).read_text(encoding='utf-8'))
    documents=['README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md','docs/RAW_TARGET_MAP_2026-11-03.md',
               'docs/RAW_WRITEBACK_2026-11-04.md']
    links=0
    for name in documents:
        path=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in link or link.startswith('#'):continue
            target=(path.parent/link.split('#')[0]).resolve()
            if target!=OUT/'verification.json':assert target.exists(),(name,link)
            links+=1
    commands={}
    for path in sorted((OUT/'commands').glob('*/command.json')):
        cmd=read(path)
        if 'exit_code' not in cmd:
            assert any('verify_raw_writeback.py' in str(x) for x in cmd['argv']);continue
        assert cmd['exit_code']==0,(path,cmd['exit_code'])
        commands[path.parent.name]=cmd['exit_code']
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    evidence=dict(still_object=obj['address'],still_handle=handle['address'],pixel_address=hex(address),
        format_id=2,width=width,height=height,stride=stride,payload_bytes=stride*height,
        before_after_sha256=payload_hashes[0],nonzero_bytes=0,
        descriptor_assignment=assignment,model_address_log=writes[0],model_sample_logs=samples,
        stream_count=len(streams),last_stream_line=max(streams),
        limitations=['Zero snapshots do not prove no intervening writes.',
                    'Register replay is segmented original code, not hardware readback.',
                    'No final NEF or physical dark-current/correction/ring effect has been validated.'])
    (OUT/'evidence-summary.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    artifacts={str(path.relative_to(ROOT)):sha(path) for path in OUT.rglob('*')
               if path.is_file() and path.name!='verification.json' and 'commands' not in path.parts}
    artifacts.update({name:sha(ROOT/name) for name in scripts+documents})
    result=dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),firmware_hashes_unchanged=firmware,
        model_sources_unchanged=models,qemu_runs=1,qemu_events=8,static_events=5,
        isolated_cases=10,isolated_segments=segments,full_buffer_snapshots=2,bytes_per_snapshot=stride*height,
        curated_ranges=20,disassembled_instructions_checked=ins_count,local_links_checked=links,
        command_exit_codes=commands,evidence=evidence,artifacts=artifacts,
        limitation='Provenance and software configuration checks only; no successful pixel processing or NEF claim.')
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('ok','qemu_runs','qemu_events','isolated_cases','isolated_segments',
        'full_buffer_snapshots','bytes_per_snapshot','curated_ranges','local_links_checked')}))

if __name__=='__main__':main()

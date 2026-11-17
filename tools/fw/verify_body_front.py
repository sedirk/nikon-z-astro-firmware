"""Recheck body/front evidence, independent contrasts and immutable inputs."""
from pathlib import Path
from datetime import datetime, timezone
import collections, hashlib, json, re, struct
import capstone

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-body-front-2026-11-08'
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def raw(row):return bytes.fromhex(row['bytes'])
def word(row,off):return struct.unpack_from('<I',raw(row),off)[0]
def check_memory(obj):
    if isinstance(obj,dict):
        if {'bytes','size','sha256'}<=obj.keys():
            data=raw(obj);assert len(data)==obj['size'] and hashlib.sha256(data).hexdigest()==obj['sha256']
        for v in obj.values():check_memory(v)
    elif isinstance(obj,list):
        for v in obj:check_memory(v)

def main():
    assert __debug__
    previous=read(ROOT/'analysis/raw-vignette-state-2026-11-08/verification.json')
    firmware=previous['firmware_hashes_unchanged'];models=previous['model_sources_unchanged']
    for path,digest in {**firmware,**models}.items():assert sha(ROOT/path)==digest,path
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    rom_record=blob[0x11f1606c-0x10020000:0x11f1606c-0x10020000+28]
    assert struct.unpack('<7I',rom_record)==(0x38,0,0,0x168000,0,0x18,0)
    sessions=[]
    for folder,count in (('native-body-front',32),('native-stage-gates',42)):
        r=read(OUT/folder/'result.json');events=read(OUT/folder/'events.json')
        assert r['ok'] and r['firmware_unchanged'] and r['event_count']==len(events)==count
        assert r['firmware_sha256']==firmware['firmware/decoded/eg1620_038000.bi']
        assert sha(OUT/folder/'probe-source.py')==r['probe_sha256']
        for path,digest in models.items():assert r['model_sources'][Path(path).name]==digest
        check_memory(r);check_memory(events)
        directory=raw(r['final']['directory_38'])
        assert directory[:8]==rom_record[:8] and directory[12:]==rom_record[12:]
        assert word(r['final']['directory_38'],8)==word(r['final']['calibration_state'],0x14)==0xc9700000
        for e in events:
            for name in ('table32_record','table144_record','table32','table144_a','table144_b',
                         'upload_a','upload_b'):
                if name in e['memory']:assert not any(raw(e['memory'][name])),(folder,e['event'],name)
        static=[e for e in events if e['phase']=='native-settle']
        def hit(event):return next(e for e in static if e['event']==event)
        table32=hit('table32_selected');table144=hit('table144_selected')
        assert table32['registers']['r0']=='0xc97293c0' and table144['registers']['r0']=='0xc972dbd0'
        assert word(table32['memory']['source_context'],0x84)==1
        assert raw(table144['memory']['source_context'])[0x21]==0
        assert hit('front_packet_dispatch')['registers']['r14']=='0x1017d83b'
        handle=r['final']['handle_1f8'];handle_bytes=raw(handle)
        assert handle_bytes[0x24]==2 and struct.unpack_from('<3H',handle_bytes,0x26)==(9168,6104,4222)
        assert word(handle,0x34)==0xa448e000
        assert word(hit('front_geometry_entry')['memory']['front_request'],4)==int(handle['address'],16)
        assert word(hit('front_raw_address_ready')['memory']['front_parameters'],0x24)==0xa448e000
        assert not any(e['event'] in ('still_raw_processing','replacement_raw_address_upload','still_raw_encoding') for e in events)
        stage={}
        if folder=='native-stage-gates':
            assert sha(ROOT/'tools/fw/qemu_body_front_probe.py')==r['probe_sha256']
            ordering=['temporary_front_gate_set','table32_selected','table144_selected','table32_upload',
                      'table144_upload','front_event8_wait','front_event8_return','temporary_front_gate_clear']
            positions=[next(i for i,e in enumerate(static) if e['event']==name) for name in ordering]
            assert positions==sorted(positions)
            assert word(hit('temporary_front_gate_set')['memory']['source_context'],0x84)==0
            assert hit('front_event8_return')['registers']['r0']=='0x00000001'
            assert word(hit('temporary_front_gate_clear')['memory']['source_context'],0x84)==1
            assert word(r['final']['source_context'],0x84)==0
            stage=dict(observed_order=ordering,wait_return=1,final_flag84=0)
        sessions.append(dict(name=folder,events=count,frame=r['final']['still_object']['address'],
            event_counts=dict(collections.Counter(e['event'] for e in events)),stage=stage))
    # Retain and validate the smaller initial run; do not add it to final counts.
    preliminary=read(OUT/'isolated-body-front/result.json')
    assert preliminary['ok'] and preliminary['firmware_unchanged'] and len(preliminary['cases'])==7
    assert sha(OUT/'isolated-body-front/probe-source.py')==preliminary['probe_sha256'];check_memory(preliminary)
    r=read(OUT/'validated-body-front/result.json');check_memory(r)
    assert r['ok'] and r['firmware_unchanged'] and len(r['cases'])==9
    assert sha(ROOT/'tools/fw/probe_body_front.py')==sha(OUT/'validated-body-front/probe-source.py')==r['probe_sha256']
    assert sha(OUT/'native-body-front/events.json')==r['observed_sha256']
    cases={c['name']:c for c in r['cases']};segments=writes=0
    for c in cases.values():
        assert len(c['calls'])==5
        for call in c['calls']:
            assert call['stopped_at']==call['until'] and call['blocks'][0]==call['entry']
            segments+=1;writes+=len(call['writes'])
        a=struct.unpack('<144H',raw(c['table144_a']));b=struct.unpack('<144H',raw(c['table144_b']))
        assert list(a)==c['expected_a'] and list(b)==c['expected_b']
        assert raw(c['registers144'])==raw(c['table144_a'])+raw(c['table144_b'])
        vals=struct.unpack('<128H',raw(c['table32']))
        packed=b''.join(struct.pack('<I',vals[g*4+ch]|vals[(g+1)*4+ch]<<16)
                        for ch in range(4) for g in range(0,32,2))
        assert raw(c['registers32'])==packed
        assert word(c['scalar_registers'],4)&65535==(0 if c['gate5b'] else 300)
        assert len(c['calls'][-1]['writes'])==214
    assert segments==45 and writes==1926
    def mmio(c):return [(x['address'],x['size'],x['value']) for x in c['calls'][-1]['writes']]
    baseline=cases['computed']
    for name,address in (('offset-gate','0x20068808'),('one-table32-value','0x20068a88')):
        before,after=mmio(baseline),mmio(cases[name])
        assert [(x[0],x[1]) for x in before]==[(x[0],x[1]) for x in after]
        differences=[x[0] for x,y in zip(before,after) if x!=y]
        assert differences==[address],differences
    assert cases['captured-selector-reuse']['expected_a']==list(range(200,344))
    assert cases['captured-selector-reuse']['expected_b']==list(range(40000,40144))
    for name in ('threshold','one-second','long-256-seconds','independent-gate74'):
        assert cases[name]['expected_b']==[32768]*144
    assert cases['one-second']['exposure_numeric']==10**9
    assert cases['long-256-seconds']['exposure_numeric']==256*10**9
    assert min(baseline['expected_b'])==38880 and max(baseline['expected_b'])==62000
    assert len(set(baseline['expected_b']))==62
    assert cases['lower-cap']['expected_b']==[35000]*144
    dis=read(OUT/'curated-native.json');md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    instructions=0
    for span in dis['ranges']:
        assert span['decoded_to_end'],span['start']
        for row in span['instructions']:
            pc=int(row['pc'],16);data=bytes.fromhex(row['bytes'])
            assert data==blob[pc-0x10020000:pc-0x10020000+len(data)]
            ins=next(md.disasm(data,pc,count=1));assert ins.mnemonic==row['mnemonic'] and ins.op_str==row['operands']
            instructions+=1
    summary=dict(sessions=sessions,rom_directory=dict(address='0x11f1606c',bytes=rom_record.hex()),
        cases=[dict(name=c['name'],time_ns=c['exposure_numeric'],table_b_min=min(c['expected_b']),
            table_b_max=max(c['expected_b']),distinct_b=len(set(c['expected_b']))) for c in cases.values()],
        final_counts=dict(cases=9,segments=segments,mmio_writes=writes),
        decision='Prioritize the fixed 32x4 table and dark-offset/writeback chain; deprioritize the 144-entry time-dependent recomputation for long exposures, retaining the separate stale-table path.',
        limits='Original-code configuration evidence with artificial calibration; actual front pixel operations, body-specific data origin and final NEF effects remain open.')
    (OUT/'evidence-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    docs=['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_BODY_FRONT_2026-11-08.md']
    links=0
    for name in docs:
        path=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'):continue
            destination=(path.parent/target.split('#')[0]).resolve()
            assert destination.exists() or destination==OUT/'verification.json',(name,target)
            links+=1
    commands={p.parent.name:read(p).get('exit_code','current recorder still open') for p in sorted((OUT/'commands').glob('*/command.json'))}
    files={str(p.relative_to(ROOT)):sha(p) for p in OUT.rglob('*') if p.is_file()
        and p.suffix in ('.json','.txt','.py') and 'commands' not in p.parts and 'session' not in p.parts
        and p.name not in ('verification.json','verification-source.py')}
    files.update({name:sha(ROOT/name) for name in docs})
    result=dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),firmware_hashes_unchanged=firmware,
        model_sources_unchanged=models,qemu_sessions=sessions,isolated_cases=9,isolated_segments=segments,
        mmio_writes=writes,curated_ranges=len(dis['ranges']),checked_instructions=instructions,
        local_links_checked=links,command_exit_codes=commands,evidence_sha256=files)
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('evidence_sha256','firmware_hashes_unchanged','model_sources_unchanged')},indent=2))

if __name__=='__main__':main()

"""Recheck original front-field arithmetic, calls, packets and immutable inputs."""
from pathlib import Path
from datetime import datetime, timezone
import collections, hashlib, json, re, struct
import capstone

ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'analysis/raw-front-field-writers-2026-11-08'
BASE,CAL=0x10020000,0x54000000
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def raw(x):return bytes.fromhex(x['bytes'])
def word(x,off):return struct.unpack_from('<I',raw(x),off)[0]
def reg(e,n):return int(e['registers'][f'r{n}'],16)
def memory_check(obj):
    count=0
    if isinstance(obj,dict):
        if {'bytes','size','sha256'}<=obj.keys():
            assert len(raw(obj))==obj['size'] and hashlib.sha256(raw(obj)).hexdigest()==obj['sha256'];count+=1
        count+=sum(memory_check(x) for x in obj.values())
    elif isinstance(obj,list):count+=sum(memory_check(x) for x in obj)
    return count
def code_to_scale(code):return 10**12//(10**6-code*10**6//4095)
def scale_to_code(scale):return 0 if scale<=10**6 else (10**6-10**12//scale)*4095//10**6
def packets(events):return [raw(e['memory']['payload']) for e in events if e['event']=='command_packet']
def encoded_fields(context):
    pairs=struct.unpack_from('<4H',context,0xb0)
    return [b'\x81\x00\x3d'+struct.pack('<2H',*(x&4095 for x in pairs[:2])),
        b'\x81\x00\x47'+struct.pack('<2H',*(x&4095 for x in pairs[2:])),
        b'\x81\x00\x55'+context[0xc0:0xc1],b'\x81\x04\x1f'+context[0xbc:0xbd],
        b'\x81\x04\x24'+context[0xbf:0xc0],b'\x81\x05\xa6'+context[0xba:0xbb],
        b'\x81\x05\xa8'+context[0xbb:0xbc],b'\x81\x05\xe1'+context[0xb8:0xba],
        b'\x81\x05\xf7'+context[0xbd:0xbf]]

def main():
    assert __debug__
    old=read(ROOT/'analysis/raw-front-continuation-2026-11-08/verification.json')
    firmware=old['firmware_hashes_unchanged'];models=old['model_sources_unchanged']
    for path,digest in {**firmware,**models}.items():assert sha(ROOT/path)==digest,path
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    def rom(pc,n):return blob[pc-BASE:pc-BASE+n]
    assert struct.unpack('<9I',rom(0x11b70474,36))==(15,18,21,24,27,30,33,36,39)
    final_path=OUT/'validated-fields-with-inputs/result.json';isolated=read(final_path)
    assert isolated['ok'] and isolated['firmware_unchanged'] and len(isolated['cases'])==8
    assert sha(ROOT/'tools/fw/probe_front_fields.py')==sha(final_path.parent/'probe-source.py')==isolated['probe_sha256']
    assert isolated['observed_sha256']==sha(OUT/'native-field-writers/events.json')
    checked_memory=memory_check(isolated);segments=writes=0
    for row in isolated['conversions']:
        assert row['scale']==code_to_scale(row['code']) and row['inverse']==scale_to_code(row['scale'])
        for call in row['calls']:
            assert call['stopped_at']==call['until'] and call['blocks'][0]==call['entry'];segments+=1
    cases={c['name']:c for c in isolated['cases']};case_summary=[]
    for case in cases.values():
        context=raw(case['context_after_builder']);input_context=raw(case['input_context'])
        assert struct.unpack_from('<2I',input_context,4)==(192,case['sv']*192)
        expected_pair=case['expected_pair'];expected_coeff=case['expected_coefficients']
        assert list(struct.unpack_from('<4H',context,0xb0))==expected_pair*2
        assert list(struct.unpack_from('<4I',context,0xc4))==expected_coeff
        assert list(context[0xb8:0xc1])==case['expected_controls']
        coeff=raw(case['coefficient_packet']);registers=raw(case['front_registers'])
        assert list(struct.unpack_from('<4I',coeff))==case['expected_published']
        assert registers[:16]==coeff[:16]
        assert registers[16:20]==coeff[16:20] and registers[20:24]==coeff[22:24]+coeff[20:22]
        assert word(case['front_registers'],24)==coeff[24] and registers[28:32]==coeff[28:32]
        calls=case['calls'];assert len(calls)==3
        assert [c['entry'] for c in calls]==['0x10121ede','0x1011e940','0x100bcd86']
        for call in calls:
            assert call['stopped_at']==call['until'] and call['blocks'][0]==call['entry'];segments+=1
            for row in call['calibration_reads']:
                pc=int(row['pc'],16);assert BASE<=pc<BASE+len(blob)
                assert len(bytes.fromhex(row['bytes']))==row['size']
        io=calls[-1]['writes'];assert len(io)==8
        assert [int(w['address'],16) for w in io]==list(range(0x200687d8,0x200687f8,4))
        assert struct.pack('<8I',*(w['value'] for w in io))==registers;writes+=len(io)
        assert any(x['address']=='0x540be821' and x['bytes']=='02' for x in calls[1]['calibration_reads'])
        case_summary.append(dict(name=case['name'],pair=expected_pair,coefficients=expected_coeff,
            controls=case['expected_controls'],uploaded=case['expected_published']))
    assert segments==32 and writes==64
    baseline=cases['baseline']
    for name in ('offset-gate','temporary-stage'):
        assert raw(cases[name]['context_after_builder'])[0xb0:0xd8]==raw(baseline['context_after_builder'])[0xb0:0xd8]
        assert raw(cases[name]['front_registers'])==raw(baseline['front_registers'])
    changed=cases['one-control-byte'];before=raw(baseline['context_after_builder']);after=raw(changed['context_after_builder'])
    assert [i for i,(x,y) in enumerate(zip(before,after)) if x!=y]==[0xc0]
    assert raw(changed['front_registers'])==raw(baseline['front_registers'])
    assert cases['publication-reuses-old-values']['expected_published']==[7001,7002,7003,7004]
    assert word(cases['publication-reuses-old-values']['front_registers'],24)==77
    # Preserve the earlier failed recording and the completed version lacking explicit input snapshots.
    for folder,ok,count in (('isolated-fields-initial',False,1),('validated-fields',True,8)):
        item=read(OUT/folder/'result.json')
        assert item['ok']==ok and item['firmware_unchanged'] and len(item['cases'])==count
        assert sha(OUT/folder/'probe-source.py')==item['probe_sha256'];checked_memory+=memory_check(item)
        if not ok:assert 'multiple values for keyword argument' in item['error']
    sessions=[];serial_pairs=0
    for folder,event_count in (('native-field-writers',64),('native-upload-and-replay',107)):
        location=OUT/folder;r=read(location/'result.json');events=read(location/'events.json')
        assert r['ok'] and r['firmware_unchanged'] and r['event_count']==len(events)==event_count
        assert r['firmware_sha256']==firmware['firmware/decoded/eg1620_038000.bi']
        assert sha(location/'probe-source.py')==r['probe_sha256'] and sha(location/'controller-source.py')==r['controller_sha256']
        for path,digest in models.items():assert r['model_sources'][Path(path).name]==digest
        checked_memory+=memory_check(r)+memory_check(events)
        for w in r['windows']:
            assert not w['saturated'] and w['trace_count']<256
            group=events[w['events_start']:w['events_end']]
            assert len(group)==w['trace_count'] and all(e['window']==w['window'] for e in group)
        assert sum(w['trace_count'] for w in r['windows'])==len(events)
        native=[e for e in events if e['phase']=='native-settle']
        def hit(name):return next(e for e in native if e['event']==name)
        order=['still_front_submit','front_raw_address_ready','still_builder_callsite','field_builder_entry',
            'first_pair_built','four_coefficients_built','control_fields_begin','field_builder_return',
            'positive_scalar_upload','after_temporary_stage','alternating_record_entry']
        positions=[hit(name)['sequence'] for name in order];assert positions==sorted(positions)
        assert reg(hit('field_builder_entry'),14)==0x1017a13b
        assert word(hit('field_builder_entry')['memory']['context'],0x84)==0
        assert word(hit('field_builder_entry')['memory']['context'],4)==192
        assert word(hit('field_builder_entry')['memory']['context'],8)==2688
        assert word(hit('front_raw_address_ready')['memory']['front_parameters'],0x24)==0xa448e000
        assert raw(r['final']['handle_1f8'])[0x24]==2
        assert struct.unpack_from('<3H',raw(r['final']['handle_1f8']),0x26)==(9168,6104,4222)
        assert not any(e['event'] in ('still_raw_processing','replacement_raw_address_upload','still_raw_encoding') for e in events)
        artificial=[e for e in events if e['phase']=='synthetic-field-replay']
        if folder=='native-upload-and-replay':
            assert sha(ROOT/'tools/fw/qemu_front_fields_probe.py')==r['probe_sha256']
            assert reg(hit('coefficient_publisher'),1)==1 and reg(hit('coefficient_publisher'),14)==0x1017d81f
            assert word(hit('coefficient_publisher')['memory']['context'],0x84)==1
            assert reg(hit('coefficient_packet_builder'),0)==0xc97bbe78
            assert reg(hit('front_coefficients_upload'),1)==0xc29a3868
            assert reg(hit('front_coefficients_upload'),14)==0x100bcd4b
            assert raw(hit('front_coefficients_upload')['memory']['coefficient_packet'])==bytes(32)
            replay=r['replay'];assert replay['restored'] and replay['global_context_unchanged']
            assert replay['source_sha256']==sha(final_path)
            assert replay['context']==baseline['context_after_builder']['bytes']
            assert replay['coefficient_packet']==baseline['coefficient_packet']['bytes']
            assert packets(artificial)==encoded_fields(bytes.fromhex(replay['context']))
        for group in (native,artificial):
            for i,e in enumerate(group):
                if e['event']!='command_packet':continue
                nxt=group[i+1];assert nxt['event']=='spi_submission' and nxt['window']==e['window']
                payload=raw(e['memory']['payload']);mem=nxt['memory']
                assert reg(nxt,0)==8 and word(mem['descriptor'],8)==len(payload)
                assert struct.unpack('<'+'H'*len(payload),raw(mem['words']))==tuple(payload);serial_pairs+=1
        log=[]
        for line in (location/'session/qemu-1.log').read_text(errors='replace').splitlines():
            m=re.fullmatch(r'Z6_SPI8_TX words=(\d+) data=([0-9a-f,]+)',line)
            if m:
                values=[int(x,16) for x in m[2].split(',')];assert len(values)==int(m[1])
                log.append(bytes(values))
        tail=packets(native)+packets(artificial);assert log[-len(tail):]==tail
        sessions.append(dict(name=folder,events=len(events),phases=dict(collections.Counter(e['phase'] for e in events)),
            maximum_window_events=max(w['trace_count'] for w in r['windows']),matched_log_tail_packets=len(tail),
            capture_sequence=[dict(sequence=e['sequence'],event=e['event']) for e in native]))
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);dis=read(OUT/'curated-native.json');instructions=0
    for span in dis['ranges']:
        assert span['decoded_to_end'],span['start']
        for row in span['instructions']:
            pc=int(row['pc'],16);data=bytes.fromhex(row['bytes']);assert data==rom(pc,len(data))
            ins=next(md.disasm(data,pc,count=1));assert ins.mnemonic==row['mnemonic'] and ins.op_str==row['operands']
            if 'literal_address' in row:assert struct.unpack('<I',rom(int(row['literal_address'],16),4))[0]==int(row['literal_value'],16)
            instructions+=1
    summary=dict(scope='Original field writers, arithmetic and front upload; synthetic calibration, no physical pixel or NEF validation.',
        cases=case_summary,conversions=[{k:c[k] for k in ('code','scale','inverse')} for c in isolated['conversions']],
        sessions=sessions,counts=dict(final_cases=8,conversions=4,isolated_segments=segments,mmio_writes=writes,serial_pairs=serial_pairs),
        rom_breakpoints=dict(address='0x11b70474',bytes=rom(0x11b70474,36).hex(),values=list(struct.unpack('<9I',rom(0x11b70474,36)))),
        front_coefficients=dict(context='c18fa844+c4..d0',packet='c29a3868',registers='200687d8..200687e4',
            additional_fields='cal+be810 -> ctx+d4 -> packet+18 -> 200687f0; fixed record -> 200687e8/ec/f4'),
        decision='Keep the two-pair code / four-coefficient allocation separate from spatial tables and four negative offsets. Continue hardware control and RAW sampling/writeback tracing; publication flag zero reuses old values.')
    (OUT/'evidence-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    docs=['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_FRONT_FIELDS_2026-11-08.md']
    links=0
    for name in docs:
        path=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'):continue
            destination=(path.parent/target.split('#')[0]).resolve()
            assert destination.exists() or destination==OUT/'verification.json',(name,target)
            links+=1
    commands={p.parent.name:read(p).get('exit_code','current recorder still open') for p in sorted((OUT/'commands').glob('*/command.json'))}
    evidence={str(p.relative_to(ROOT)):sha(p) for p in OUT.rglob('*') if p.is_file()
        and p.name not in ('verification.json','verification-source.py') and 'commands' not in p.parts
        and p.suffix in ('.json','.txt','.py','.log','.jsonl')}
    evidence.update({name:sha(ROOT/name) for name in docs})
    result=dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),firmware_hashes_unchanged=firmware,
        model_sources_unchanged=models,qemu_events=[s['events'] for s in sessions],final_isolated_cases=8,
        conversions=4,isolated_segments=segments,mmio_writes=writes,serial_pairs=serial_pairs,
        checked_memory_records=checked_memory,curated_ranges=len(dis['ranges']),checked_instructions=instructions,
        local_links_checked=links,command_exit_codes=commands,evidence_sha256=evidence)
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('evidence_sha256','firmware_hashes_unchanged','model_sources_unchanged')},indent=2))

if __name__=='__main__':main()

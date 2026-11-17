"""Verify captured front-command evidence against ROM, memory and SPI logs.

Does not execute guest code, infer a sensor register's meaning, or certify pixels.
"""
from pathlib import Path
from datetime import datetime, timezone
import collections, hashlib, json, re, struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'analysis/raw-front-continuation-2026-11-08'
BASE = 0x10020000

def read(path): return json.loads(path.read_text(encoding='utf-8'))
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def raw(row): return bytes.fromhex(row['bytes'])
def word(row, offset): return struct.unpack_from('<I', raw(row), offset)[0]
def reg(event, n): return int(event['registers'][f'r{n}'], 16)

def check_memory(obj):
    count = 0
    if isinstance(obj, dict):
        if {'bytes','size','sha256'} <= obj.keys():
            data = raw(obj)
            assert len(data) == obj['size']
            assert hashlib.sha256(data).hexdigest() == obj['sha256']
            count += 1
        count += sum(check_memory(v) for v in obj.values())
    elif isinstance(obj, list):
        count += sum(check_memory(v) for v in obj)
    return count

def packets(events):
    return [raw(e['memory']['command_payload']) for e in events if e['event']=='front_command_packet']

def check_serial_pairs(events):
    count = 0
    for i, event in enumerate(events):
        if event['event'] != 'front_command_packet': continue
        nxt = events[i+1]
        assert nxt['event']=='front_spi_submission' and nxt['window']==event['window']
        payload = raw(event['memory']['command_payload'])
        mem = nxt['memory']; descriptor = mem['serial_descriptor']
        assert reg(nxt,0)==raw(mem['serial_context'])[0]==8
        assert word(descriptor,0)==int(mem['serial_words']['address'],16)
        assert word(descriptor,4)==0 and word(descriptor,8)==word(descriptor,12)==len(payload)
        assert raw(descriptor)[16]==0
        assert struct.unpack('<'+'H'*len(payload),raw(mem['serial_words']))==tuple(payload)
        count += 1
    assert sum(e['event']=='front_spi_submission' for e in events)==count
    return count

def main():
    assert __debug__, 'Evidence assertions must be enabled.'
    previous = read(ROOT/'analysis/raw-body-front-2026-11-08/verification.json')
    firmware = previous['firmware_hashes_unchanged']; models = previous['model_sources_unchanged']
    for path, digest in {**firmware, **models}.items(): assert sha(ROOT/path)==digest, path
    blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    def rom(pc,n): return blob[pc-BASE:pc-BASE+n]
    directory = rom(0x11f1606c,28); storage = rom(0x11f15a20,44)
    assert struct.unpack('<7I',directory)==(0x38,0,0,0x168000,0,0x18,0)
    assert struct.unpack('<11I',storage)==(0x13e80000,0,0x180000,0x17fffc,1,0,0,0,1,0,1)
    assert 0x13e80000 >= BASE+len(blob)
    jump = rom(0x1011b7fa,21)
    assert jump.hex()=='0e1a1e264bd9dcdff0f4f8fcebeae9e8e7e6e5e4e3'
    assert [0x1011b7fa+2*jump[i] for i in (2,4,5)]==[0x1011b836,0x1011b890,0x1011b9ac]
    assert 0x100d2a70+2*rom(0x100d2a70,1)[0]==0x100d2a76
    expected_native = [bytes.fromhex(s) for s in (
        '8100db0000000000000000','81003d00000000','81004700000000','81005500',
        '81041f00','81042400','8105a600','8105a800','8105e10000','8105f70000')]
    ordering = ['still_front_submit','front_geometry_entry','front_raw_address_ready',
        'temporary_front_gate_set','table32_selected','table144_selected','front_packet_dispatch',
        'positive_scalar_upload','table32_upload','table144_upload','front_event8_wait',
        'front_event8_return','temporary_front_gate_clear','after_temporary_gate','front_stage_return']
    sessions = []; memory_count = serial_pairs = 0; case_summary = []
    for folder, expected_count in (('native-repeated',71),('native-transport-cases',102),('native-storage-descriptor',82)):
        location = OUT/folder; r = read(location/'result.json'); events = read(location/'events.json')
        assert r['ok'] and r['firmware_unchanged'] and r['event_count']==len(events)==expected_count
        assert r['firmware_sha256']==firmware['firmware/decoded/eg1620_038000.bi']
        assert sha(location/'probe-source.py')==r['probe_sha256']
        assert sha(location/'controller-source.py')==r['controller_sha256']
        for path,digest in models.items(): assert r['model_sources'][Path(path).name]==digest
        memory_count += check_memory(r)+check_memory(events)
        for i,e in enumerate(events): assert e['sequence']==i
        assert sum(w['trace_count'] for w in r['windows'])==len(events)
        for w in r['windows']:
            assert not w['saturated'] and w['trace_count']<256
            group = events[w['events_start']:w['events_end']]
            assert len(group)==w['trace_count']
            assert all(e['window']==w['window'] and e['phase']==w['phase'] for e in group)
        native = [e for e in events if e['phase']=='native-settle']
        def hit(name): return next(e for e in native if e['event']==name)
        positions = [hit(name)['sequence'] for name in ordering]
        assert positions==sorted(positions)
        assert len(set(e['window'] for e in native))==1
        window = next(w for w in r['windows'] if w['window']==native[0]['window'])
        assert window['repeat_enabled']
        for pc in (0x1010b330,0x1010b37e,0x1010b2f0,0x1011d548,0x1017e524):
            assert hex(pc) in r['repeat_points']
        assert word(hit('temporary_front_gate_set')['memory']['source_context'],0x84)==0
        assert word(hit('temporary_front_gate_clear')['memory']['source_context'],0x84)==1
        assert word(hit('after_temporary_gate')['memory']['source_context'],0x84)==0
        assert word(r['final']['source_context'],0x84)==0
        assert reg(hit('front_event8_return'),0)==1
        assert reg(hit('front_stage_return'),0)==reg(hit('front_stage_return'),4)==0
        after = [e for e in native if e['sequence']>hit('after_temporary_gate')['sequence']]
        assert not any(e['event'] in ('front_packet_dispatch','table32_upload','table144_upload','positive_scalar_upload') for e in after)
        assert [reg(e,0) for e in after if e['event']=='front_command_selector']==[2,4,5]
        assert [reg(e,0) for e in native if e['event']=='front_stage_operation']==[0,1,2]
        assert packets(native)==expected_native
        batches = [e for e in after if e['event']=='front_command_batch']
        assert [(reg(e,0),reg(e,1)) for e in batches]==[(0xc97bf970,0xc97c1b70),
            (0xc29a3f68,0xc18fa97c),(0xc29a3f28,0xc29a3f54),(0xc97c22d0,0xc97c24d0)]
        assert raw(batches[0]['memory']['command_lengths'])[:2]==bytes(2)
        assert raw(batches[3]['memory']['command_lengths'])[:2]==bytes(2)
        assert struct.unpack('<10H',raw(batches[2]['memory']['command_lengths'])[:20])==(7,7,4,4,4,4,4,5,5,0)
        final_dir = raw(r['final']['directory_38'])
        assert final_dir[:8]==directory[:8] and final_dir[12:]==directory[12:]
        assert word(r['final']['directory_38'],8)==word(r['final']['calibration_state'],0x14)==0xc9700000
        assert reg(hit('table32_selected'),0)==0xc97293c0 and reg(hit('table144_selected'),0)==0xc972dbd0
        handle = r['final']['handle_1f8']
        assert raw(handle)[0x24]==2 and struct.unpack_from('<3H',raw(handle),0x26)==(9168,6104,4222)
        assert word(handle,0x34)==word(hit('front_raw_address_ready')['memory']['front_parameters'],0x24)==0xa448e000
        assert word(hit('front_geometry_entry')['memory']['front_request'],4)==int(handle['address'],16)
        assert not any(e['event'] in ('still_raw_processing','replacement_raw_address_upload','still_raw_encoding') for e in events)
        artificial = [e for e in events if e['phase']=='synthetic-calibration-transport']
        if folder!='native-repeated': serial_pairs += check_serial_pairs(native+artificial)
        if folder=='native-transport-cases':
            fixture = r['transport_fixture']
            assert fixture['restored'] and fixture['front_tables_and_context_unchanged']
            cases = r['transport_cases']; assert len(cases)==8
            patterns = ('1122334455667788','91a2b3c4d5e6f708')
            expected_cases = {}
            for state,mode in ((0,0),(1,0),(0,1),(1,1)):
                expected_cases[f'toggle-{state}-argument-{mode}'] = [] if mode else ['8100db'+patterns[1-state]]
            for kind in (2,5):
                for enabled in (0,1): expected_cases[f'command-{kind}-lengths-{enabled}']=[] if not enabled else ['817a0111','817a022233']
            for case in cases:
                assert case['expected_packets']==expected_cases.pop(case['name'])
                if 'initial_state' in case: assert case['final_state']==1-case['initial_state']
                group = events[case['events_start']:case['events_end']]
                assert all(e['phase']=='synthetic-calibration-transport' for e in group)
                assert [p.hex() for p in packets(group)]==case['expected_packets']
                case_summary.append(case)
            assert not expected_cases and len(packets(artificial))==6
        if folder=='native-storage-descriptor':
            assert sha(ROOT/'tools/fw/qemu_front_continuation_probe.py')==r['probe_sha256']
            assert raw(r['final']['storage_18'])==storage
            query = r['directory_query']; assert int(query['return_r0'],16)==1
            assert struct.unpack('<5I',bytes.fromhex(query['output']))==(0xc9700000,0x13e80000,0,0x168000,0x180000)
        logged = []
        for line in (location/'session/qemu-1.log').read_text(errors='replace').splitlines():
            match = re.fullmatch(r'Z6_SPI8_TX words=(\d+) data=([0-9a-f,]+)',line)
            if match:
                words = [int(x,16) for x in match[2].split(',')]
                assert len(words)==int(match[1]) and all(x<=255 for x in words)
                logged.append(bytes(words))
        tail = packets(native)+packets(artificial)
        assert logged[-len(tail):]==tail,folder
        sessions.append(dict(name=folder,events=len(events),capture_events=len(native),
            artificial_events=len(artificial),maximum_window_events=max(w['trace_count'] for w in r['windows']),
            saturated=False,spi8_log_packets=len(logged),matched_tail_packets=len(tail),
            captured_order=[dict(sequence=e['sequence'],event=e['event']) for e in native]))
    dis = read(OUT/'curated-native.json'); md = capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    instructions = 0
    for span in dis['ranges']:
        assert span['decoded_to_end'],span['start']
        for row in span['instructions']:
            pc = int(row['pc'],16); data = bytes.fromhex(row['bytes'])
            assert data==rom(pc,len(data))
            ins = next(md.disasm(data,pc,count=1))
            assert ins.mnemonic==row['mnemonic'] and ins.op_str==row['operands']
            if 'literal_address' in row:
                assert struct.unpack('<I',rom(int(row['literal_address'],16),4))[0]==int(row['literal_value'],16)
            instructions += 1
    summary = dict(scope='Original-code control and transport evidence; synthetic fixture, not physical NEF pixel validation.',
        sessions=sessions,transport_cases=case_summary,serial_pairs=serial_pairs,
        calibration_storage=dict(directory_id='0x38',storage_id='0x18',ram='0xc9700000',source='0x13e80000',
            length='0x168000',capacity='0x180000',main_image_end=hex(BASE+len(blob)),
            rom_directory=dict(address='0x11f1606c',bytes=directory.hex()),
            rom_storage=dict(address='0x11f15a20',bytes=storage.hex()),
            load_path='101b045e -> 101b03f2 -> 10091882 -> 101c4f62 -> 101c4e98 -> 10068d3c',
            load_path_evidence='Static descriptor and transfer-driver chain; query values observed in QEMU, full loader not invoked.'),
        command_jump_table=dict(address='0x1011b7fa',bytes=jump.hex()),
        next_target='Identify the calibration fields and their actual RAW effects; retain four offsets/0x720, front tables and SPI commands as distinct candidates.')
    (OUT/'evidence-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    docs = ['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_FRONT_CONTINUATION_2026-11-08.md']
    links = 0
    for name in docs:
        path = ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'): continue
            destination = (path.parent/target.split('#')[0]).resolve()
            assert destination.exists() or destination==OUT/'verification.json',(name,target)
            links += 1
    commands = {p.parent.name:read(p).get('exit_code','current recorder still open') for p in sorted((OUT/'commands').glob('*/command.json'))}
    evidence = {str(p.relative_to(ROOT)):sha(p) for p in OUT.rglob('*') if p.is_file()
        and p.name not in ('verification.json','verification-source.py')
        and 'commands' not in p.parts and p.suffix in ('.json','.txt','.py','.log','.jsonl')}
    evidence.update({name:sha(ROOT/name) for name in docs})
    result = dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),firmware_hashes_unchanged=firmware,
        model_sources_unchanged=models,qemu_event_counts=[s['events'] for s in sessions],transport_cases=8,
        artificial_emitted_packets=6,verified_serial_descriptor_pairs=serial_pairs,checked_memory_records=memory_count,
        curated_ranges=len(dis['ranges']),checked_instructions=instructions,local_links_checked=links,
        command_exit_codes=commands,evidence_sha256=evidence)
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('evidence_sha256','firmware_hashes_unchanged','model_sources_unchanged')},indent=2))

if __name__=='__main__': main()

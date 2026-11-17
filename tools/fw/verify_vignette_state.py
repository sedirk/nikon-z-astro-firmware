"""Verify recorded no-lens state, native comparisons, replay and immutable inputs."""
from pathlib import Path
from datetime import datetime, timezone
import collections, hashlib, json, re, struct
import capstone

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-vignette-state-2026-11-08'
BASE=0x10020000
def read(path): return json.loads(path.read_text(encoding='utf-8'))
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def raw(row): return bytes.fromhex(row['bytes'])
def check_memory(obj):
    if isinstance(obj,dict):
        if {'bytes','size','sha256'} <= obj.keys():
            data=raw(obj)
            assert len(data)==obj['size'] and hashlib.sha256(data).hexdigest()==obj['sha256']
        for child in obj.values(): check_memory(child)
    elif isinstance(obj,list):
        for child in obj: check_memory(child)


def main():
    assert __debug__
    prior=read(ROOT/'analysis/raw-controls-2026-11-08/verification.json')
    firmware,models=prior['firmware_hashes_unchanged'],prior['model_sources_unchanged']
    for path,digest in {**firmware,**models}.items(): assert sha(ROOT/path)==digest,path
    unit=struct.pack('<257H',*([1024]*257))
    sessions=[]
    for name in ('native-no-lens','native-selector','native-comparisons'):
        folder=OUT/name; r=read(folder/'result.json'); events=read(folder/'events.json')
        assert r['ok'] and r['firmware_unchanged'] and r['event_count']==len(events)
        assert r['firmware_sha256']==firmware['firmware/decoded/eg1620_038000.bi']
        assert sha(folder/'probe-source.py')==r['probe_sha256']
        for path,digest in models.items(): assert r['model_sources'][Path(path).name]==digest
        check_memory(r); check_memory(events)
        normal=[e for e in events if e['phase']!='property-counterfactual']
        returns=[e for e in normal if e['event']=='curve_generator_return']
        assert returns
        for e in returns:
            m=e['memory']; props=raw(m['properties'])
            assert props[0x62]==0 and props[0x63]==1 and props[0x52]==0
            assert raw(m['curve'])==raw(m['mixed_curve'])==unit
            assert raw(m['coefficients'])==bytes(20)
        owner=raw(r['final']['owner'])
        assert owner[0]==0 and owner[0x25e]==0 and owner[0x25f]==1
        assert owner[0x227c:0x22fc]==bytes(128)
        assert raw(r['final']['main_properties'])==bytes(160)
        assert raw(r['final']['still_curve_properties'])==bytes(108)
        # The static downstream stages were not reached in these bounded runs.
        assert not any(e['event'] in ('still_curve_stage','still_curve_builder','still_main_builder',
            'still_table_stage','still_raw_processing','still_raw_encoding','encoder_descriptor_entry') for e in normal)
        if name!='native-no-lens':
            expected={'neutral_selector_property_138d':0,'neutral_selector_property_1c14':0,
                'neutral_selector_config_3e3':0,'neutral_selector_helper_a8':1,'neutral_selector_helper_2c':1}
            for event,value in expected.items():
                hits=[e for e in normal if e['event']==event]; assert hits
                assert all(int(e['registers']['r0'],16)==value for e in hits)
            assigned=[e for e in normal if e['event']=='still_neutral_flag_assignment']
            assert len(assigned)==1 and int(assigned[0]['registers']['r0'],16)==1
            assert assigned[0]['memory']['assigned_owner']['address']==r['final']['owner']['address']
        sessions.append(dict(name=name,events=len(events),normal_events=len(normal),
            curve_returns=len(returns),event_counts=dict(collections.Counter(e['event'] for e in events)),
            frame=r['final']['still_object']['address'],owner=r['final']['owner']['address']))
    comparisons=read(OUT/'native-comparisons/result.json')
    assert sha(ROOT/'tools/fw/qemu_vignette_state_probe.py')==comparisons['probe_sha256']
    assert comparisons['selector_fixture']['restored']
    cases=comparisons['selector_cases']; assert len(cases)==6
    for c in cases:
        state=c['properties']['0x1c14']; config=c['config_3e3']
        assert c['neutral']==int(state!=3 or config==0)
        assert c['helper_a8']==c['helper_2c']==int(state!=3)
        calls=comparisons['calls'][c['calls_start']:c['calls_end']]
        assert len(calls)==13
        assert calls[-1]['function']=='0x1013c392'
        assert int(calls[-1]['result']['return_r0'],16)==c['neutral']
        getters=[x for x in calls if x['function']=='0x10164bfa']
        assert {x['result']['arguments'][0]:int(x['result']['return_r0'],16) for x in getters}==c['properties']
    replay=read(OUT/'validated-replay/result.json'); check_memory(replay)
    assert replay['ok'] and replay['firmware_unchanged'] and len(replay['cases'])==9
    assert sha(OUT/'validated-replay/probe-source.py')==sha(ROOT/'tools/fw/probe_vignette_state.py')==replay['probe_sha256']
    for name,digest in replay['observed_files'].items(): assert sha(OUT/'native-selector'/name)==digest
    segments=0
    for c in replay['cases']:
        for call in c['calls']:
            assert call['blocks'][0]==call['entry'] and call['stopped_at']==call['until']=='0x53000000'
            segments+=1
        if c['kind']=='snapshot-replay':
            assert raw(c['curve'])==raw(c['mixed_curve'])==unit
            assert raw(c['coefficients'])==bytes(20)
            assert raw(c['main_properties'])[0x7d]==0
            assert struct.unpack_from('<I',raw(c['main_control']),12)[0]==1 and c['main_force_unit']==0
        else:
            assert c['value']=={'mode-selector-observed':0,'mode-selector-numeric-6-sub0':6,
                'mode-selector-numeric-6-sub1':3,'mode-selector-numeric-6-sub2':2,
                'mode-selector-flag88':1,'mode-selector-flag98':4,'mode-selector-numeric-3-sub2':8}[c['name']]
    assert segments==13
    failed=read(OUT/'snapshot-replay/result.json')
    assert not failed['ok'] and failed['failure']['pc']=='0x100361fc'
    assert 'UC_ERR_EXCEPTION' in failed['error'] and failed['last_call']['entry']=='0x1013c392'
    assert sha(OUT/'snapshot-replay/probe-source.py')==failed['probe_sha256']
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    dis=read(OUT/'curated-evidence.json'); instructions=0
    for span in dis['ranges']:
        md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM if span['instruction_set']=='ARM' else capstone.CS_MODE_THUMB)
        for row in span['instructions']:
            pc=int(row['pc'],16); data=bytes.fromhex(row['bytes'])
            assert data==blob[pc-BASE:pc-BASE+len(data)]
            ins=next(md.disasm(data,pc,count=1)); assert ins.mnemonic==row['mnemonic'] and ins.op_str==row['operands']
            instructions+=1
    for d in dis['data']:
        address=int(d['address'],16); assert raw(d)==blob[address-BASE:address-BASE+d['size']]
    summary=dict(sessions=sessions,selector_cases=cases,replay_cases=[dict(name=c['name'],kind=c['kind']) for c in replay['cases']],
        decision='Lower ordinary 257-entry vignette priority for fixed telescope rings; pursue body calibration/front processing and dark-offset route separately.',
        limits='Synthetic no-lens observation and isolated static replay; no final NEF pixel claim.')
    (OUT/'evidence-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    docs=['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_VIGNETTE_STATE_2026-11-08.md']
    links=0
    for filename in docs:
        path=ROOT/filename
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'): continue
            destination=(path.parent/target.split('#')[0]).resolve()
            # This verification report is written below; check its existence after writing.
            assert destination.exists() or destination==OUT/'verification.json',(filename,target)
            links+=1
    commands={p.parent.name:read(p).get('exit_code','running') for p in sorted((OUT/'commands').glob('*/command.json'))}
    evidence_files=[p for p in OUT.rglob('*') if p.is_file() and p.suffix in ('.json','.py','.txt')
        and 'commands' not in p.parts and 'session' not in p.parts and p.name not in ('verification.json','verification-source.py')]
    files={str(p.relative_to(ROOT)):sha(p) for p in evidence_files}
    files.update({name:sha(ROOT/name) for name in docs})
    result=dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),firmware_hashes_unchanged=firmware,
        model_sources_unchanged=models,qemu_sessions=sessions,selector_cases=6,isolated_cases=9,isolated_segments=13,
        curated_ranges=len(dis['ranges']),checked_instructions=instructions,local_links_checked=links,
        command_exit_codes=commands,evidence_sha256=files)
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    assert (OUT/'verification.json').exists()
    print(json.dumps({k:v for k,v in result.items() if k not in ('evidence_sha256','firmware_hashes_unchanged','model_sources_unchanged')},indent=2))


if __name__=='__main__': main()

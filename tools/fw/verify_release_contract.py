"""Read-only independent checks of RAW size-guard evidence and lab containers."""
from pathlib import Path
import argparse, ast, binascii, copy, datetime, hashlib, json, re, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from build_raw_candidates import apply_candidate
from build_raw_container import tables_from, transform, inspect_body, MODULES, SOURCE_SHA

ROOT=Path(__file__).resolve().parents[2]
LAB=ROOT/'analysis/raw-release-contract-2026-11-08'
def sha(b): return hashlib.sha256(b).hexdigest()
def read(p): return json.loads(p.read_text(encoding='utf-8'))
def data(row):
    b=bytes.fromhex(row['bytes']); assert len(b)==row['size'] and sha(b)==row['sha256']; return b


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(); assert __debug__
    if args.output.exists(): raise FileExistsError(args.output)
    baseline=read(ROOT/'analysis/raw-patch-candidates-2026-11-08/verification.json')
    preserved={}
    for name,digest in baseline['inputs_unchanged'].items():
        name=name.replace('\\','/')
        assert sha((ROOT/name).read_bytes())==digest,name
        preserved[name]=digest
    original=(ROOT/'firmware/original/Z_6_0380.bin').read_bytes()
    eg=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    tables=tables_from(original)
    container_reviews=[]
    for folder in ('container','container-fullsize'):
        manifest=read(LAB/folder/'manifest.json'); b=(LAB/folder/manifest['file']).read_bytes()
        assert sha(b)==manifest['output_sha256'] and len(b)==manifest['size']==len(original)
        body=transform(b[32:],tables); modules=inspect_body(body)
        assert modules==manifest['output_modules'] and b[:64]==original[:64]
        for i,row in enumerate(modules):
            start,size=MODULES[i][1:]
            expected=(ROOT/'firmware/decoded'/row['name']).read_bytes() if i!=2 else (
                (LAB/'fullsize-module/still-preserve-fullsize-raw.bi').read_bytes() if folder=='container-fullsize'
                else (ROOT/'analysis/raw-patch-candidates-2026-11-08/modules/still-preserve-front-raw.bi').read_bytes())
            assert body[start:start+size]==expected
        changed=[i for i,(a,c) in enumerate(zip(original,b)) if a!=c]
        assert changed==[int(row['offset'],16) for row in manifest['byte_changes']]
        reverted=bytearray(b)
        for row in manifest['byte_changes']:
            i=int(row['offset'],16); assert b[i]==int(row['after'],16)
            reverted[i]=int(row['before'],16)
        assert bytes(reverted)==original and sha(reverted)==SOURCE_SHA
        assert manifest['byte_exact_reversal_to_original'] and manifest['inputs_preserved']
        assert not any(manifest[k] for k in ('camera_acceptance_verified','camera_recovery_verified','hardware_pixels_verified'))
        assert sha((LAB/folder/'builder-source.py').read_bytes())==manifest['builder_sha256']
        assert sha((LAB/folder/'module-builder-source.py').read_bytes())==manifest['module_builder_sha256']
        container_reviews.append(dict(folder=folder,sha256=sha(b),changed_bytes=len(changed),
            byte_changes=manifest['byte_changes'],body_crc=body[-16:-14].hex(),exact_byte_reversal=True))
    full=(LAB/'fullsize-module/still-preserve-fullsize-raw.bi').read_bytes()
    catalog=read(ROOT/'patches/z6-c380-fullsize-raw-candidate.json')
    generated,patch=apply_candidate(eg,catalog,catalog['candidates'][0]); assert generated==full
    assert patch['changed_byte_offsets']==['0x8e3a6','0x1ff3678','0x1ff3679']
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    decoded=list(md.disasm(full[0x8e3a4:0x8e3a8],0x100ae3a4))
    assert len(decoded)==1 and decoded[0].mnemonic=='bl' and decoded[0].op_str=='#0x101ba4b6'
    assert full[0x1ba474-0x20000:0x1ba4ce-0x20000]==eg[0x1ba474-0x20000:0x1ba4ce-0x20000]
    guard_tests=[]
    wrong=bytearray(eg); wrong[0]^=1
    try: apply_candidate(bytes(wrong),catalog,catalog['candidates'][0])
    except ValueError as e: guard_tests.append(dict(test='wrong firmware',error=str(e)))
    else: raise AssertionError('wrong source accepted')
    recipe=copy.deepcopy(catalog['candidates'][0]); recipe['edits'][0]['before']='00000000'
    try: apply_candidate(eg,catalog,recipe)
    except ValueError as e: guard_tests.append(dict(test='wrong preimage',error=str(e)))
    else: raise AssertionError('wrong preimage accepted')
    # Retain a valid outer CRC while corrupting EG: the module CRC check must fire.
    bad=bytearray(body); bad[MODULES[2][1]+0x800]^=1
    bad[-16:-14]=binascii.crc_hqx(bad[:-16],0).to_bytes(2,'big')
    try: inspect_body(bad)
    except ValueError as e:
        assert 'Module CRC' in str(e); guard_tests.append(dict(test='inner CRC with valid outer CRC',error=str(e)))
    else: raise AssertionError('invalid module accepted')
    bad=bytearray(body); bad[-16]^=1
    try: inspect_body(bad)
    except ValueError as e:
        assert 'Body CRC' in str(e); guard_tests.append(dict(test='body CRC',error=str(e)))
    else: raise AssertionError('invalid body accepted')
    result=read(LAB/'execution-guarded/result.json')
    assert result['ok'] and result['source_unchanged'] and result['candidate_unchanged'] and result['fullsize_candidate_unchanged']
    assert len(result['cases'])==102 and len(result['guard_cases'])==240
    cases={(c['variant'],c['configuration']['name']):c for c in result['cases']}
    memory_count=0
    def visit(value):
        nonlocal memory_count
        if isinstance(value,dict):
            if {'bytes','sha256','size','address'}<=value.keys(): data(value); memory_count+=1
            for v in value.values(): visit(v)
        elif isinstance(value,list):
            for v in value: visit(v)
    visit(result)
    findings=[]
    for (variant,name),c in cases.items():
        cfg=c['configuration']
        assert c['source_bounds']['x'] and c['source_bounds']['y'] and c['source_bounds']['allocation']
        assert not c['pixels_verified']
        assert {c['early_cleanup_selected'],c['release_selected']}=={'0x50017000','0x50017100'}
        assert c['release_selected']==c['selected_handle']
        for call in c['calls']: assert call['stopped_at']==call['until']
        if variant=='still-preserve-fullsize-raw':
            comparator=cases['original' if cfg['size'] else 'still-preserve-front-raw',name]
            for key in ('prepared_request','encoder_packet','codec_registers'):
                assert c[key]==comparator[key],(name,key)
            for key in ('selected_handle','encoder_input_address','encoder_input_stride','early_cleanup_selected','release_selected'):
                assert c[key]==comparator[key],(name,key)
            assert c['geometry_equals_backend']
        if variant=='still-preserve-front-raw' and not c['geometry_equals_backend']:
            findings.append(dict(case=name,issue='unconditional candidate selects different source geometry'))
        if variant=='original' and cfg['mode']==0 and not c['uncompressed_fits_raw_capacity']:
            findings.append(dict(case=name,issue='synthetic wide format over raw capacity already in original',
                required=c['uncompressed_bytes'],capacity=c['output_raw_capacity']))
    original_guards={(c['kind'],c['owner_mode'],c['size'],c['has_output']):c
                     for c in result['guard_cases'] if c['variant']=='original'}
    changed_cases=0
    for c in result['guard_cases']:
        old=original_guards[c['kind'],c['owner_mode'],c['size'],c['has_output']]
        before,after=data(old['request']),data(c['request'])
        changes={i for i,(a,b) in enumerate(zip(before,after)) if a!=b}
        assert changes<={0x1a8,0x1a9,0x1aa,0x1ab}
        if c['variant']=='still-preserve-fullsize-raw':
            expected=old['replacing'] and c['size']!=0
            assert c['replacing']==expected
            assert bool(changes)==(old['replacing'] and c['size']==0)
            changed_cases+=bool(changes)
    assert changed_cases==6
    q=read(LAB/'qemu-fullsize/result.json'); visit(q)
    assert q['ok'] and q['boot_reached_dispatch'] and q['firmware_unchanged'] and len(q['cases'])==8
    assert q['firmware_sha256']==sha(full)
    for name,digest in q['model_sources'].items():
        assert digest==next(v for k,v in preserved.items() if k.endswith('/'+name))
    for c in q['cases']:
        assert c['ok'] and c['restored'] and not c['submitted']
        assert c['events'][-1]['pc']=='0x100b4c78'
        for e in c['events']:
            off=int(e['pc'],16)-0x10020000
            assert data(e['instructions'])==full[off:off+e['instructions']['size']]
    for folder in ('execution-initial','execution','execution-guarded','qemu-fullsize'):
        rr=read(LAB/folder/'result.json')
        assert sha((LAB/folder/'probe-source.py').read_bytes())==rr['probe_sha256']
    scripts=('probe_release_contract.py','build_raw_container.py','qemu_fullsize_probe.py','verify_release_contract.py')
    for filename in scripts: ast.parse((ROOT/'tools/fw'/filename).read_text(encoding='utf-8'))
    curated=read(LAB/'curated-evidence.json')
    assert all(span['decoded_to_end'] for span in curated['ranges'])
    commands={}
    for path in sorted((LAB/'commands').glob('*/command.json')):
        row=read(path); commands[path.parent.name]=row.get('exit_code','recorder still running')
        if 'exit_code' in row:
            expected={'07-transfer-tail':2,'20-verify-release':1}.get(path.parent.name,0)
            assert row['exit_code']==expected,(path,row)
    report=dict(ok=True,verified_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        descriptor_encoder_cases=102,predicate_cases=240,
        segments=sum(len(c['calls']) for c in result['cases'])+len(result['guard_cases']),
        mmio_writes=sum(len(a['writes']) for c in result['cases'] for a in c['calls']),
        qemu_boots=1,qemu_predicate_cases=8,memory_records_checked=memory_count,
        guarded_changes_vs_original=changed_cases,findings=findings,container_reviews=container_reviews,
        malformed_input_rejections=guard_tests,commands=commands,
        firmware_hashes_unchanged={k:v for k,v in preserved.items() if k.startswith('firmware/')},
        model_sources_unchanged={k:v for k,v in preserved.items() if not k.startswith('firmware/')},
        instruction=dict(address='0x100ae3a4',before='bl #0x101ba474',after='bl #0x101ba4b6',
                         changed_code_byte='0x8e3a6',original_helpers_unchanged=True),
        physical_pixels_verified=False,physical_installation_verified=False,
        earlier_56_and_68_case_runs_retained_but_not_counted_again=True)
    args.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('ok','descriptor_encoder_cases','predicate_cases','segments','mmio_writes',
                                          'qemu_predicate_cases','memory_records_checked')},indent=2))


if __name__=='__main__': main()

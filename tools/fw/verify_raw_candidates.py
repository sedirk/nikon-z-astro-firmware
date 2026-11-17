"""Read-only checks of candidate bytes, execution evidence and input preservation.

Writes a new verification record, never rewrites firmware. Deliberately rejects
wrong versions, wrong preimages and overlapping recipes in the build API.
"""
from pathlib import Path
import argparse, ast, binascii, copy, datetime, hashlib, json, re, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from build_raw_candidates import apply_candidate

ROOT=Path(__file__).resolve().parents[2]
LAB=ROOT/'analysis/raw-patch-candidates-2026-11-08'


def sha(data): return hashlib.sha256(data).hexdigest()
def read(path): return json.loads(path.read_text(encoding='utf-8'))
def data(row):
    b=bytes.fromhex(row['bytes'])
    assert len(b)==row['size'] and sha(b)==row['sha256']
    return b


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); assert __debug__
    if args.output.exists(): raise FileExistsError(args.output)
    base=read(ROOT/'analysis/raw-front-field-writers-2026-11-08/verification.json')
    inputs={}
    for group in ('firmware_hashes_unchanged','model_sources_unchanged'):
        for name,expected in base[group].items():
            digest=sha((ROOT/name).read_bytes()); assert digest==expected,(name,digest)
            inputs[name]=digest
    catalog=read(ROOT/'patches/z6-c380-raw-candidates.json')
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    build=read(LAB/'modules/build.json')
    assert build['original_preserved'] and build['source_sha256']==sha(blob)
    assert build['catalog_sha256']==sha((ROOT/'patches/z6-c380-raw-candidates.json').read_bytes())
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    reviews=[]
    for recipe,manifest in zip(catalog['candidates'],build['candidates']):
        assert recipe['id']==manifest['id']
        candidate=(LAB/'modules'/manifest['file']).read_bytes()
        assert len(candidate)==len(blob) and sha(candidate)==manifest['output_sha256']
        assert binascii.crc_hqx(candidate,0)==0
        assert candidate[-2:]==binascii.crc_hqx(candidate[:-2],0).to_bytes(2,'big')
        generated,checked=apply_candidate(blob,catalog,recipe)
        assert generated==candidate
        actual=[i for i,(a,b) in enumerate(zip(blob,candidate)) if a!=b]
        assert actual==[int(x,16) for x in manifest['changed_byte_offsets']]
        restored=bytearray(candidate); locations=set()
        for edit in recipe['edits']:
            address=int(edit['address'],16); offset=address-int(catalog['load_base'],16)
            old,new=bytes.fromhex(edit['before']),bytes.fromhex(edit['after'])
            assert blob[offset:offset+len(old)]==old and candidate[offset:offset+len(new)]==new
            locations.update(range(offset,offset+len(old))); restored[offset:offset+len(old)]=old
            decoded=[]
            for code in (old,new):
                instructions=list(md.disasm(code,address)); assert sum(i.size for i in instructions)==len(code)
                decoded.append([dict(address=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in instructions])
            reviews.append(dict(id=recipe['id'],address=hex(address),file_offset=hex(offset),before=decoded[0],after=decoded[1]))
        locations.update((len(blob)-2,len(blob)-1))
        assert set(actual)<=locations
        restored[-2:]=blob[-2:]; assert restored==blob
        assert checked['exact_rollback_verified'] and not manifest['camera_update_container']
    guarded=[]
    experiments=[]
    wrong=bytearray(blob); wrong[0]^=1
    experiments.append(('wrong-source-hash',bytes(wrong),copy.deepcopy(catalog['candidates'][0])))
    wrong=copy.deepcopy(catalog['candidates'][0]); wrong['edits'][0]['before']='ffff'
    experiments.append(('wrong-instruction-preimage',blob,wrong))
    wrong=copy.deepcopy(catalog['candidates'][0]); wrong['edits']*=2
    experiments.append(('overlapping-edits',blob,wrong))
    wrong=copy.deepcopy(catalog['candidates'][0]); wrong['edits'][0]['after']='00'
    experiments.append(('different-instruction-length',blob,wrong))
    for name,source,recipe in experiments:
        try: apply_candidate(source,catalog,recipe)
        except ValueError as exc: guarded.append(dict(name=name,error=str(exc)))
        else: raise AssertionError(name)
    result=read(LAB/'validated-execution/result.json')
    assert result['ok'] and result['original_preserved'] and len(result['cases'])==32
    cases={(c['variant'],c['configuration']['name']):c for c in result['cases']}
    summaries=[]; memory_count=0
    for (variant,name),c in cases.items():
        cfg=c['configuration']; old=cases['original',name]
        for key in ('properties','parameters','request_before','request','packet','registers','blacklevel_payload','final_frame'):
            data(c[key]); memory_count+=1
        assert struct.unpack_from('<I',data(c['request_before']),0x1a8)[0]==0x5a5a5a5a
        registers=data(c['registers']); original=data(old['registers'])
        changed={i for i in range(0,65536,4) if registers[i:i+4]!=original[i:i+4]}
        assert changed=={int(x,16) for x in c['changed_registers_vs_original']}
        scalar=0 if variant=='still-offset-source-zero' else cfg['scalar']
        negative=0 if variant in ('negative-only','still-offset-source-zero') else (-scalar)&65535
        limit=12345 if cfg['cached'] else min(((16383-scalar)*cfg['gain']+76800+128)//256,32767)
        assert c['negative_halfwords']==[negative]*4 and c['limit']==limit
        assert struct.unpack_from('<I',registers,0x720)[0]==limit
        assert struct.unpack_from('<II',registers,0x710)==((negative&8191)*65537,)*2
        assert data(c['blacklevel_payload'])==struct.pack('<4H',*([cfg['scalar']]*4))
        if variant in ('negative-only','still-offset-source-zero'):
            expected={0x710,0x714} if cfg['scalar'] else set()
            if limit!=old['limit']: expected.add(0x720)
        elif variant=='still-preserve-front-raw':
            expected={0x3e8,0x3ec,0x3f0,0x580,0x67c} if old['replacing'] else set()
        else: expected=set()
        assert changed==expected,(variant,name,changed,expected)
        selected=0x50017100 if c['replacing'] else 0x50017000
        assert int(c['selected_handle'],16)==selected
        if cfg.get('owner_mode',0)==0: assert c['encoder_input']==hex(selected+0x24)
        else: assert c['encoder_input'] is None
        assert not c['hardware_pixels_verified']
        for call in c['calls']:
            assert call['stopped_at']==call['until']
        summaries.append(dict(variant=variant,case=name,negative=negative,limit=limit,
            replacing=c['replacing'],encoder_input=c['encoder_input'],changed_registers=[hex(i) for i in sorted(changed)]))
    qemu=read(LAB/'qemu-copies/result.json')
    retry=read(LAB/'qemu-route-retry/result.json')
    assert not qemu['ok'] and len(qemu['runs'])==4
    failed=qemu['runs'][-1]
    assert failed['id']=='still-preserve-front-raw' and not failed['ok']
    assert failed['boot_reached_dispatch'] and failed['phase']=='native-object-acquisition'
    assert 'TimeoutError' in failed['error']
    assert retry['ok'] and len(retry['runs'])==1 and retry['runs'][0]['id']=='still-preserve-front-raw'
    valid_runs=qemu['runs'][:3]+retry['runs']
    qemu_summary=[]
    hashes={'original':sha(blob),**{c['id']:c['output_sha256'] for c in build['candidates']}}
    for run in valid_runs:
        variant=run['id']; assert run['ok'] and run['firmware_unchanged'] and run['boot_reached_dispatch']
        assert run['firmware_sha256']==hashes[variant]
        assert all(digest==next(v for k,v in base['model_sources_unchanged'].items() if k.endswith(name))
                   for name,digest in run['model_sources'].items())
        assert run['scalar_builder']['expected_scalar']==(0 if variant=='still-offset-source-zero' else 300)
        assert struct.unpack_from('<H',data(run['scalar_builder']['properties']),0x86)[0]==run['scalar_builder']['expected_scalar']
        assert run['negative_builder']['negative_halfwords']==([0]*4 if variant=='negative-only' else [65236]*4)
        bounded=run['raw_request']; assert bounded['restored'] and not bounded['submitted']
        assert [t['pc'] for t in bounded['traces']]==['0x100ae3b0','0x100b4c78']
        req=data(bounded['request']); replacement=struct.unpack_from('<I',req,0x1a8)[0]
        assert replacement==int(bounded['expected_replacement'],16)
        assert replacement==(0 if variant=='still-preserve-front-raw' else int(bounded['scratch'],16)+0x7d00)
        module=blob if variant=='original' else (LAB/'modules'/f'{variant}.bi').read_bytes()
        for event in run['events']:
            instruction=data(event['instructions']); pc=int(event['pc'],16)
            assert instruction==module[pc-BASE:pc-BASE+len(instruction)]
        qemu_summary.append(dict(variant=variant,events=len(run['events']),
            scalar=run['scalar_builder']['expected_scalar'],negative=run['negative_builder']['negative_halfwords'],
            replacement=hex(replacement),bounded_state_restored=True))
    scripts=('build_raw_candidates.py','probe_raw_candidates.py','qemu_raw_candidates_probe.py','verify_raw_candidates.py')
    for name in scripts: ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf-8'))
    assert sha((LAB/'modules/builder-source.py').read_bytes())==build['builder_sha256']
    assert sha((LAB/'validated-execution/probe-source.py').read_bytes())==result['probe_sha256']
    assert sha((LAB/'qemu-copies/probe-source.py').read_bytes())==qemu['probe_sha256']
    assert sha((LAB/'qemu-route-retry/probe-source.py').read_bytes())==retry['probe_sha256']
    commands={}
    for path in sorted((LAB/'commands').glob('*/command.json')):
        row=read(path); commands[path.parent.name]=row.get('exit_code','current recorder still open')
        if 'exit_code' in row:
            assert row['exit_code']==(1 if path.parent.name=='06-qemu-candidate-copies' else 0),(path,row)
    summary=dict(ok=True,cases=32,segments=sum(len(c['calls']) for c in result['cases']),
        mmio_writes=sum(len(call['writes']) for c in result['cases'] for call in c['calls']),
        case_results=summaries,qemu=qemu_summary,patch_review=reviews,
        qemu_timeout_attempts=1,qemu_boot_attempts=5,
        failure_note='First preserve-front-raw run timed out while acquiring a native object, before candidate checks. The separate retry passed; root cause not established.')
    (LAB/'evidence-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    links=[]
    for name in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_PATCH_CANDIDATES_2026-11-08.md'):
        path=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in link or link.startswith('#'): continue
            target=(path.parent/link.split('#')[0]).resolve(); assert target.exists(),(name,link)
            links.append([name,link])
    evidence={}
    for path in LAB.rglob('*'):
        if path.is_file() and path.suffix in ('.json','.py','.txt','.log','.jsonl') and '/commands/' not in path.as_posix():
            evidence[path.relative_to(ROOT).as_posix()]=sha(path.read_bytes())
    for name in scripts:
        path=ROOT/'tools/fw'/name; evidence[path.relative_to(ROOT).as_posix()]=sha(path.read_bytes())
    for name in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_PATCH_CANDIDATES_2026-11-08.md','patches/z6-c380-raw-candidates.json'):
        evidence[name]=sha((ROOT/name).read_bytes())
    verification=dict(ok=True,checked_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        inputs_unchanged=inputs,candidate_hashes=hashes,guard_checks=guarded,
        cases=32,segments=summary['segments'],mmio_writes=summary['mmio_writes'],qemu_boots=5,qemu_variants_verified=4,
        checked_memory_records=memory_count,local_links_checked=len(links),command_exit_codes=commands,
        evidence_sha256=evidence)
    args.output.write_text(json.dumps(verification,indent=2),encoding='utf-8')
    print(json.dumps({k:verification[k] for k in ('ok','cases','segments','mmio_writes','qemu_boots','checked_memory_records','local_links_checked')},indent=2))


BASE=0x10020000
if __name__=='__main__': main()

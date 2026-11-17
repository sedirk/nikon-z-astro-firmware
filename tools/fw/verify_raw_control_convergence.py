"""Cross-check recorded native results, package scope, and immutable inputs."""
from pathlib import Path
import argparse,binascii,json,struct
import capstone
from audit_nef import file_sha
from verify_neighborhood_package import reconstruct

ROOT=Path(__file__).resolve().parents[2]
DIR=ROOT/'analysis/raw-control-convergence-2026-11-09'
PKG=ROOT/'outputs/Z6-C380-neighborhood-candidate-2026-11-09'

def load(p):return json.loads(p.read_text(encoding='utf8'))
def mem(row):
    b=bytes.fromhex(row['bytes']);assert len(b)==row['size']
    import hashlib
    assert hashlib.sha256(b).hexdigest()==row['sha256']
    return b

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert __debug__ and not a.output.exists()
    previous=load(ROOT/'analysis/raw-neighborhood-2026-11-09/verification.json')
    report=dict(ok=False,immutable={},samples={},model_sources={},checks={})
    for section in ('immutable','samples'):
        for path,digest in previous[section].items():
            assert file_sha(ROOT/path)==digest,path
            report[section][path]=digest
    oldclass=ROOT/'analysis/raw-neighborhood-2026-11-09/class-module/still-class-1aec-zero.bi'
    assert file_sha(oldclass)==previous['candidate']['sha256']
    report['immutable'][oldclass.relative_to(ROOT).as_posix()]=file_sha(oldclass)
    models=ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu'
    for name,digest in previous['model_sources'].items():
        assert file_sha(models/name)==digest
        report['model_sources'][name]=digest
    source=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    candidate=(DIR/'module/still-neighborhood-gates-off.bi').read_bytes()
    m=load(DIR/'module/build.json')['candidates'][0]
    assert reconstruct(candidate,m)==source
    changed=[i for i,(x,y) in enumerate(zip(source,candidate)) if x!=y]
    assert changed==[0xa2654,0xa2656,0xa2657,0xa267c,0xa267e,0xa267f,
                     0xa2690,0xa2691,0xa2692,0xa2693,0x1ff3678,0x1ff3679]
    assert binascii.crc_hqx(source,0)==binascii.crc_hqx(candidate,0)==0
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);edits=[]
    for edit in m['edits']:
        pc=int(edit['address'],16);off=pc-0x10020000
        old=next(md.disasm(source[off:off+4],pc,count=1));new=next(md.disasm(candidate[off:off+4],pc,count=1))
        assert old.size==new.size==4
        assert old.bytes.hex()==edit['before'] and new.bytes.hex()==edit['after']
        edits.append(dict(pc=hex(pc),old=old.mnemonic+' '+old.op_str,new=new.mnemonic+' '+new.op_str))
    matrix=load(DIR/'native-matrix/result.json');bridge=load(DIR/'encoder-bridge/result.json')
    assert matrix['ok'] and bridge['ok'] and len(matrix['matrix'])==1296 and len(bridge['chains'])==32
    ids=set()
    for row in matrix['matrix']:
        ids.add(row['case'])
        if row['variant']!='original':assert row['registers']==['0x0','0x0']
    assert len(ids)==648
    for row in bridge['chains']:
        assert row['encoder']==dict(descriptor='0x50017124',destination='0x50017250',raw_base='0x62000000')
        assert row['blacklevel_hex']=='f003f003f003f003'
        regs=mem(row['registers']);props=mem(row['properties'])
        for name in ('parameters','after_packet'):mem(row[name])
        assert struct.unpack_from('<I',regs,0x310)[0]==0x60000000
        assert struct.unpack_from('<I',regs,0x3ec)[0]==0x62000000
        assert struct.unpack_from('<I',regs,0x580)[0]==1
        if row['variant']!='original':
            assert struct.unpack_from('<I',regs,0x584)[0]==struct.unpack_from('<I',regs,0x594)[0]==0
            if not row['fixture']['mode']:assert (props[0x4c],props[0x4e],props[0x4f])==(0,2,2)
        assert [c['entry'] for c in row['calls']]==['0x100c2824','0x100ae33e','0x100b5716','0x100d5c86','0x100ae41e','0x100af648','0x1028a9d8']
    assert len(bridge['comparisons'])==16
    for row in bridge['comparisons']:
        allowed=dict(properties={0x4c,0x4e,0x4f},parameters={0xcc,0xcd,0x17a},after_packet={0xcc,0xcd,0x17a},registers={0x584,0x594})
        for key,offsets in row['changed_offsets'].items():
            assert {int(x,16) for x in offsets}<=allowed[key]
            if row['fixture']['mode']:assert offsets==[]
    route=load(DIR/'eg-preflash-contract/result.json');assert route['ok'] and len(route['cases'])==6
    for row in route['cases']:
        assert row['native_resource_descriptor']=='0000000000000210000000000000000000009402'
        assert not {'0x101b8ae4','0x101c3bba'} & row['visited_entries'].keys()
        if row['label'] in ('original','candidate','candidate_full_display'):
            assert row['discovery_return']==row['integrity_return']==row['component_precheck_return']==0
            assert row['update_pointer']=='0x60000000' and row['update_length']==len(source)-2
            assert not row['preflash']['flash_primitive_executed'] and row['preflash']['end_canary_preserved']
            assert row['preflash']['payload_bytes']+row['preflash']['padding_bytes']==0x2940000
            assert row['loaded_buffer_sha256']==row['sha256']
        elif row['label']=='damaged_crc':
            assert row['discovery_return']==0 and row['integrity_return']==3
            assert row['update_pointer']=='0x0' and row['update_length']==0
        else:assert row['discovery_return']==3
    package=load(PKG/'manifest.json')
    assert (PKG/'candidate/EG162080.BIN').read_bytes()==candidate
    for row in package['files']:
        assert file_sha(PKG/row['path'])==row['sha256'] and (PKG/row['path']).stat().st_size==row['bytes']
    for row in load(PKG/'native_evidence.json'):assert file_sha(ROOT/row['path'])==row['sha256']
    fp=load(ROOT/'analysis/raw-neighborhood-2026-11-09/fingerprint/result.json')
    assert load(PKG/'baseline112.json')['targets']==fp['targets'] and len(fp['targets'])==112
    # Original historic containers remain byte-identical; classify them separately
    # from the newly tested module route rather than rewriting old manifests.
    container_paths=[ROOT/'analysis/raw-release-contract-2026-11-08/container-fullsize/Z6-C380-still-preserve-fullsize-raw-EXPERIMENTAL.bin.lab',
        DIR/'container/Z6-C380-still-neighborhood-gates-off-EXPERIMENTAL.bin.lab']
    outer=(ROOT/'firmware/original/Z_6_0380.bin').read_bytes()
    report['superseded_crc_only_containers']=[]
    for path in container_paths:
        assert path.read_bytes()[:32]==outer[:32]
        report['superseded_crc_only_containers'].append(dict(path=path.relative_to(ROOT).as_posix(),sha256=file_sha(path),
            outer_header_preserved=True,header_digest_repaired=False,installation_candidate=False))
    assert file_sha(container_paths[1])=='66480f680b17f491348d77673abede773562547ab44dd953f223b81af3c55ad1'
    for name in ('should-not-exist-legacy','should-not-exist-neighborhood'):assert not (DIR/name).exists()
    for row in load(ROOT/'references/web/2026-11-09/update-routes/manifest.json'):
        assert file_sha(ROOT/row['path'])==row['sha256']
    commands=[]
    for path in sorted((DIR/'commands').glob('*/command.json')):
        meta=load(path)
        if 'exit_code' not in meta:continue # This verifier's recorder is still active.
        expected={'23-eg-route-smoke':1,'38-reject-crc-only-legacy':2,'39-reject-crc-only-neighborhood':2}.get(path.parent.name,0)
        assert meta['exit_code']==expected,(path,meta)
        commands.append(dict(folder=path.parent.name,exit_code=meta['exit_code'],expected=expected))
    report.update(ok=True,candidate=dict(sha256=file_sha(DIR/'module/still-neighborhood-gates-off.bi'),edits=edits,
        changed_bytes=len(changed),code_changed_bytes=len(changed)-2,exact_original_reconstruction=True),
        checks=dict(control_configuration_pairs=648,matrix_executions=1296,extended_chain_pairs=16,
            extended_chains=32,upgrade_cases=6,native_preflash_buffers=3,package_files=len(package['files']),baseline_targets=112),
        completed_commands=commands,scope='Native controls, module/file checks and bounded preflash preparation only; hardware NEF/installation/recovery pending.')
    a.output.write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(dict(ok=True,checks=report['checks'],changed_bytes=len(changed),immutable_files=len(report['immutable']),samples=len(report['samples'])),indent=2))

if __name__=='__main__':main()

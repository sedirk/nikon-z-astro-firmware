"""Cross-check saved evidence, exact binary scope, source integrity and geometry."""
from pathlib import Path
import argparse, binascii, hashlib, json, struct
import numpy as np
import capstone
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2]
DIR=ROOT/'analysis/raw-neighborhood-2026-11-09'


def load(path):return json.loads(Path(path).read_text(encoding='utf8'))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert not a.output.exists()
    report=dict(ok=False,immutable={},samples={},model_sources={},checks={})
    baseline=load(ROOT/'analysis/real-nef-2026-11-09/verification-final.json')
    for path,digest in baseline['immutable'].items():
        assert file_sha(ROOT/path)==digest;report['immutable'][path]=digest
    for path,digest in baseline['model_sources'].items():
        q=ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu'/path
        assert file_sha(q)==digest;report['model_sources'][path]=digest
    targets=load(DIR/'targets/result.json');fp=load(DIR/'fingerprint/result.json')
    for path,digest in targets['source_sha256'].items():
        assert file_sha(ROOT/path)==digest;report['samples'][path]=digest
    assert fp['ok'] and fp['discovery112']['both_fit']==112
    assert sum(fp['discovery112']['delta_histogram'].values())==224
    coords=[(r['x'],r['y']) for r in fp['targets']]
    minimum=min((max(abs(x-a),abs(y-b)),i,j) for i,(x,y) in enumerate(coords) for j,(a,b) in enumerate(coords) if i<j)
    assert minimum[0]==27
    report['geometry']=dict(minimum_chebyshev_pixels=minimum[0],pair=[coords[minimum[1]],coords[minimum[2]]],
        points=len(coords),native_cluster_records_maximum=50,footprint_width=13,
        single_call_max_targets_covered=50,
        scope='Each pair exceeds a 13x13 footprint. One unchanged 50-record call cannot cover all 112; repeated calls with changed records are outside this bound.')
    assert all(c['both_fit']==0 for c in fp['controls'][:2])
    for r,t in zip(fp['targets'],targets['targets']):
        assert (r['x'],r['y'])==(t['raw_x'],t['raw_y'])
        offsets=fp['kernel_G1_G2'] if r['phase'].startswith('G') else fp['kernel_R_B']
        for j in (0,1):
            patch=t['raw_17x17_patches'][j+3]
            mx=max(patch[8+dy][8+dx] for dy,dx in offsets)
            assert r['nearest_color_max'][j]==mx
            assert patch[8][8]-mx==8*r['k'][j] and 0<=r['k'][j]<=7
    cluster=load(DIR/'native-cluster/result.json');assert cluster['ok']
    assert len(cluster['cases'])==224 and all(len(r['changed_pixels'])==1 for r in cluster['cases'])
    assert cluster['summary']['centre_below_max8']==218 and cluster['summary']['max8_plus_8k_matches']==6
    for p3,p4 in zip(cluster['cases'][::2],cluster['cases'][1::2]):
        assert p3['format']==3 and p4['format']==4
        assert p3['changed_pixels']==p4['changed_pixels']
    assert cluster['write_hook_control']['byte_identical']
    assert all(len(r['changed_pixels'])==int(i==3) for i,r in enumerate(cluster['gates']))
    expo=load(DIR/'native-exposure/result.json');modes=load(DIR/'native-modes-v2/result.json')
    assert expo['ok'] and len(expo['policy_cases'])==33 and len(expo['builder_cases'])==16
    assert modes['ok'] and len(modes['policy_cases'])==128 and len(modes['control_cases'])==28
    constants={0x648:0x70007,0x64c:0x30001,0x654:0x70007,0x658:0x30001}
    for row in modes['control_cases']:
        written={int(w['address'],16)-(0x20380000+row['bank']*0x40000):int(w['value'],16) for w in row['calls'][-1]['writes']}
        assert all(written[k]==v for k,v in constants.items())
    report['constant_register_fields']={hex(k):hex(v) for k,v in constants.items()}
    report['constant_interpretation']='Native 7,7 and 3,1 pairs in the same parameter block. Link to max8+8*k is only a hypothesis; no dither/threshold semantics asserted.'
    build=load(DIR/'class-module/build.json');m=build['candidates'][0]
    source=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();patched=(DIR/'class-module'/m['file']).read_bytes()
    assert len(source)==len(patched)==33502842
    assert file_sha(DIR/'class-module'/m['file'])==m['output_sha256']
    changes=np.flatnonzero(np.frombuffer(source,dtype=np.uint8)!=np.frombuffer(patched,dtype=np.uint8)).tolist()
    assert changes==[0x126f27,0x1ff3678,0x1ff3679]
    assert binascii.crc_hqx(source,0)==binascii.crc_hqx(patched,0)==0
    restored=bytearray(patched)
    for i in changes:restored[i]=source[i]
    assert restored==source
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    instructions={}
    for name,data in (('original',source),('candidate',patched)):
        i=next(md.disasm(data[0x126f24:0x126f28],0x10146f24,count=1))
        instructions[name]=f'{i.mnemonic} {i.op_str}'
    assert instructions==dict(original='strb.w r0, [r1, #0xaec]',candidate='strb.w r7, [r1, #0xaec]')
    pred=next(md.disasm(source[0x126f1e:0x126f20],0x10146f1e,count=1))
    assert pred.mnemonic=='movs' and pred.op_str=='r7, #0'
    cand=load(DIR/'native-class-candidate/result.json')
    assert cand['ok'] and len(cand['comparisons'])==16 and len(cand['cases'])==32
    for row in cand['cases']:
        props=bytes.fromhex(row['properties']['bytes']);par=bytes.fromhex(row['parameters']['bytes']);regs=bytes.fromhex(row['registers']['bytes'])
        if row['variant']!='original':assert props[0x4c]==0 and par[0xcc]==par[0xcd]==0
        assert struct.unpack_from('<I',regs,0x584)[0]==par[0x17a]
        assert struct.unpack_from('<I',regs,0x594)[0]==(par[0xcc]<<2)|(par[0xcd]<<1)|par[0xce]
    report['candidate']=dict(sha256=m['output_sha256'],changed_offsets=[hex(i) for i in changes],
        instructions=instructions,crc=patched[-2:].hex(),rollback_byte_identical=True,
        native_comparison_pairs=16,camera_update_container=False,camera_nef_effect='pending')
    report['checks']=dict(real_target_values=224,nearby_control_positions=224,
        additional_bias_only_positions=60,additional_both_fit=7,
        native_cluster_format_pairs=112,cluster_gates=7,exposure_table_cases=33,
        exposure_builder_cases=16,mode_table_cases=128,mode_control_cases=28,
        producer_chains=2,candidate_original_pairs=16)
    report['ok']=True
    a.output.write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(dict(ok=True,checks=report['checks'],candidate=report['candidate']),indent=2))


if __name__=='__main__':main()

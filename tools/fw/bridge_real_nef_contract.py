"""Bind actual NEF metadata/packing to bounded C3.80 native contracts.

File-derived scalar fields are restored in private objects. Other owner state
remains an explicit lab fixture. This verifies serialization and geometry, not
an inverse RAW pipeline or a physical ISP register readout.
"""
from pathlib import Path
import argparse, binascii, gc, json, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from audit_nef import tiff_inventory
from probe_raw_candidates import Rig,ROOT,BASE,OWNER,TAG,META,PAYLOAD,PACKAGE,sha
from probe_release_contract import run,SOURCE_SHA,FULLSIZE_SHA,CODEC_MMIO

def nefinfo(path,inventory):
    nodes=[n for n in inventory['ifds'] if '0xc7d5' in n['tags']]
    assert len(nodes)==1
    tag=nodes[0]['tags']['0xc7d5']
    with path.open('rb') as f:f.seek(tag['offset']);data=f.read(tag['bytes'])
    assert data.startswith(b'Nikon\0\x01\x01\0\0II*\0')
    base=10;pos=base+struct.unpack_from('<I',data,base+4)[0]
    count=struct.unpack_from('<H',data,pos)[0];assert count<=32
    entries={}
    for i in range(count):
        tagid,typ,n,pointer=struct.unpack_from('<HHII',data,pos+2+12*i)
        assert typ==7 and n<=len(data) and base+pointer+n<=len(data)
        d=data[base+pointer:base+pointer+n]
        entries[hex(tagid)]=dict(file_offset=tag['offset']+base+pointer,bytes=d.hex(),sha256=sha(d),size=n)
    return dict(container=tag,entries=entries)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--samples',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    report=dict(scope=__doc__,script_sha256=sha(Path(__file__).read_bytes()),geometry=[],files=[],ok=False)
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    variants=[('original',ROOT/'firmware/decoded/eg1620_038000.bi',SOURCE_SHA),
        ('still-preserve-fullsize-raw',ROOT/'analysis/raw-release-contract-2026-11-08/fullsize-module/still-preserve-fullsize-raw.bi',FULLSIZE_SHA)]
    for variant,path,digest in variants:
        b=path.read_bytes();assert sha(b)==digest
        rig=Rig(b,snapshots);rig.uc.mem_map(CODEC_MMIO,0x1000)
        result=run(rig,variant,dict(area=0,size=0,mode=0,depth=1,wide=0,readout=0))
        assert result['output_dimensions']==[6064,4040] and result['output_stride']==10624
        assert result['uncompressed_bytes']==42920960 and result['source_bounds']['allocation']
        result['module_sha256']=digest
        result['real_sample_match']={'width':6064,'height':4040,'row_stride':10624,'raw_bytes':42920960,
            'interpretation':'Matching descriptor values; readout=0 is a lab selector, not a live object observation.'}
        report['geometry'].append(result)
        del rig;gc.collect()
    b=variants[0][1].read_bytes();rig=Rig(b,snapshots)
    files=sorted(a.samples.glob('*.NEF'))
    assert len(files)==6
    for path in files:
        inventory=tiff_inventory(path);info=nefinfo(path,inventory);d=bytes.fromhex(info['entries']['0x6']['bytes'])
        assert len(d)==116 and struct.unpack_from('<H',d,114)[0]==binascii.crc_hqx(d[:114],0xffff)
        mn=[n for n in inventory['ifds'] if n['label'].endswith('/Nikon')][0]
        blacks=mn['tags']['0x003d']['value'];assert blacks==[1008]*4
        cfg=dict(scalar=1008,bank=0,cached=0,owner_mode=1)
        rig.reset(cfg);u,p,g=rig.uc,rig.put,rig.get
        # Invert only the direct field-copy serializer; no calibration fit.
        offsets=[0x44,0x34,0x24,0x14]
        coefficients=[struct.unpack_from('<i',d,x)[0] for x in offsets]
        for i,value in enumerate(coefficients):p(OWNER+0x1014+4*i,value,'i')
        blend=struct.unpack_from('<I',d,0x60)[0];assert blend<=65535
        p(OWNER+0x1024,blend,'H')
        assert d[4] in [0,1,2]
        p(OWNER+0x22d6,8 if d[4]==0 else 0,'B');p(OWNER+0x25e,1 if d[4]==1 else 0,'B')
        calls=[rig.call(0x10305628)]
        p(PACKAGE+0x34,OWNER);u.mem_write(TAG,b[0x11536d98-BASE:0x11536da4-BASE])
        p(META+12,TAG);p(META+16,PAYLOAD)
        calls.append(rig.call(0x10289942,[TAG,PACKAGE+0x30,META]))
        generated=bytes(u.mem_read(PAYLOAD,116))
        differing=[i for i,(x,y) in enumerate(zip(d,generated)) if x!=y]
        assert not differing,(path.name,differing)
        u.mem_write(TAG,b[0x11537028-BASE:0x11537034-BASE]);p(META+8,TAG);p(META+16,PAYLOAD+0x100)
        calls.append(rig.call(0x1028a9d8,[TAG,PACKAGE+0x30,META]))
        black_payload=rig.mem(PAYLOAD+0x100,8)
        assert bytes.fromhex(black_payload['bytes'])==struct.pack('<4H',*blacks)
        report['files'].append(dict(name=path.name,file_sha256=sha(path.read_bytes()),info=info,
            owner_fields=dict(black=blacks,coefficients_1014_1020=coefficients,blend_1024=blend,
                flag_22d6=8 if d[4]==0 else 0,setting_25e=1 if d[4]==1 else 0,
                status_note='Representative private fields reproducing output status, not recovered menu state'),
            generated=rig.mem(PAYLOAD,116),black_payload=black_payload,calls=calls,
            exact_vignette_payload_match=True,exact_black_payload_match=True))
        print(path.name,coefficients,blend,'native metadata identical',flush=True)
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);lines=[]
    for start,end in [(0x101bb332,0x101bb37a),(0x10289942,0x102899a0),(0x1028a9d8,0x1028aa20)]:
        lines.append(f'; {start:08x}..{end:08x}')
        lines += ['%08x %-9s %s'%(i.address,i.mnemonic,i.op_str) for i in md.disasm(b[start-BASE:end-BASE],start)]
    (a.output/'native-field-copies.txt').write_text('\n'.join(lines)+'\n',encoding='utf8')
    report['ok']=True
    report['original_preserved']=sha(variants[0][1].read_bytes())==SOURCE_SHA
    report['candidate_preserved']=sha(variants[1][1].read_bytes())==FULLSIZE_SHA
    assert report['original_preserved'] and report['candidate_preserved']
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())

if __name__=='__main__':main()

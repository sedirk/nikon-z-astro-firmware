"""Independently check saved NEF fixtures, native-chain evidence and immutable inputs."""
from pathlib import Path
import argparse,hashlib,json
import numpy as np
import rawpy
from audit_nef import file_sha,tiff_inventory,compare

ROOT=Path(__file__).resolve().parents[2]
EVIDENCE=ROOT/'analysis/raw-nef-save-2026-11-08'
IMMUTABLE={
 'firmware/original/Z_6_0380.bin':'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
 'firmware/decoded/eg1620_038000.bi':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
 'firmware/decoded/ex1620_037000.bi':'72f1fb29e24b36b872eec697a486abeff8bcef77f6020fa89473fd014aa18131',
 'firmware/decoded/_tpj01_v140.bin':'e60998537d46a15c430154aeeb589026aca015256d27e2d5990589d23a59c88e',
 'firmware/decoded/vr1620_010200.bi':'48aaa4d82d709ff6a97b9618cfdbbb706304588642a7f1a73bfc4a525c22a37a',
 'analysis/raw-release-contract-2026-11-08/fullsize-module/still-preserve-fullsize-raw.bi':'7ff43669a82d9def1407056d889db041338dbe12a0bb2867eccfc98527f0875c',
 'analysis/raw-release-contract-2026-11-08/container-fullsize/Z6-C380-still-preserve-fullsize-raw-EXPERIMENTAL.bin.lab':'007df71f8bdfefbc0f26a7ac156f2d6aab0781397d6cad956f8897ff03a013b2',
}
MODELS={
 'nikon-z6.c':'9a92f19510f6730312158079cea39717826648da0d245d766ed39ce412e9091c',
 'nikon-z6-profile.h':'301091acd26b268fd315741a17eed8e8940aa004a9d72ab61eb08b74a06a324a',
 'nikon-functional-isp.h':'d53ebf656d1bb5bf7fba70c749b7caa9f5cca0746344df89dbd46405076181c6',
 'nikon-isp-pixels.h':'327d4535af98bd2aeecbfa2d97a2ac5cd85a9ba56af8338f7ee6400228a6dbaa',
}


def memory_records(value):
    total=0
    if isinstance(value,dict):
        if all(k in value for k in ('bytes','sha256','size')) and isinstance(value['bytes'],str):
            data=bytes.fromhex(value['bytes'])
            assert len(data)==value['size'] and hashlib.sha256(data).hexdigest()==value['sha256']
            total+=1
        total+=sum(memory_records(v) for v in value.values())
    elif isinstance(value,list):total+=sum(memory_records(v) for v in value)
    return total


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert __debug__ and not a.output.exists()
    immutable={name:file_sha(ROOT/name) for name in IMMUTABLE};assert immutable==IMMUTABLE
    models={name:file_sha(ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu'/name) for name in MODELS}
    assert models==MODELS
    runs=[('qemu-original-lsb',12,300),('qemu-nef-lsb',12,300),('qemu-zero-black',12,0),('qemu-14bit',14,300)]
    checked=[];memory_count=0
    for name,depth,black in runs:
        directory=EVIDENCE/name;r=json.loads((directory/'result.json').read_text())
        assert r['ok'] and r['allocation_freed'] and r['firmware_unchanged'] and r['free_return']==1
        assert r['model_sources']==MODELS and r['writer_return']==0
        assert file_sha(directory/'probe-source.py')==r['probe_sha256']
        path=directory/r['file']['name'];assert file_sha(path)==r['file']['sha256']
        assert path.stat().st_size==r['file']['size']
        metadata=tiff_inventory(path);strips=[s for s in metadata['raw_strips'] if s['size']]
        assert len(strips)==1
        strip=strips[0];payload=r['raw_payload']
        assert strip['sha256']==payload['sha256'] and strip['size']==payload['size']
        assert strip['offset']==r['header']['size'] and strip['bits']==[depth]
        assert strip['size']==payload['stride']*payload['height']
        assert strip['size']+strip['offset']==path.stat().st_size
        black_tags=[d['tags']['0x003d']['value'] for d in metadata['ifds'] if '/Nikon' in d['label'] and '0x003d' in d['tags']]
        assert black_tags==[[black]*4],black_tags
        offset=0
        with path.open('rb') as f:
            for wr in r['file_writes']:
                assert wr['offset']==offset
                data=f.read(wr['size']);assert len(data)==wr['size']
                assert hashlib.sha256(data).hexdigest()==wr['sha256']
                offset+=wr['size']
        assert offset==path.stat().st_size
        assert r['file_writes'][-1]['source']==payload['address']
        with rawpy.imread(str(path)) as raw:
            pixels=raw.raw_image
            assert list(pixels.shape)==[payload['height'],payload['width']]
            values=np.array(payload['marker_values'],dtype=np.uint16);xx=np.arange(pixels.shape[1])
            mismatches=sum(int(np.count_nonzero(pixels[y]!=values[(xx+y)%len(values)])) for y in range(pixels.shape[0]))
            assert mismatches==0,(name,mismatches)
            assert raw.white_level==(1<<depth)-1
            assert raw.black_level_per_channel==[black//(4 if depth==12 else 1)]*4
            s=raw.sizes
            assert s.crop_left_margin+s.crop_width<=s.raw_width and s.crop_top_margin+s.crop_height<=s.raw_height
            checked.append(dict(run=name,pixels=int(pixels.size),marker_mismatches=mismatches,depth=depth,
                raw_strip=strip,stored_tag_black=black_tags[0],decoded_black=raw.black_level_per_channel,
                file_sha256=file_sha(path),file_size=path.stat().st_size))
        memory_count+=memory_records(r)
    original_compare=compare(EVIDENCE/runs[0][0]/'serialization-fixture.NEF',EVIDENCE/runs[1][0]/'serialization-fixture.NEF')
    black_compare=compare(EVIDENCE/runs[1][0]/'serialization-fixture.NEF',EVIDENCE/runs[2][0]/'serialization-fixture.NEF')
    assert original_compare['changed_pixels']==black_compare['changed_pixels']==0
    assert original_compare['same_metadata_black'] and not black_compare['same_metadata_black']
    chain=json.loads((EVIDENCE/'length-chain/result.json').read_text());assert chain['ok'] and len(chain['cases'])==28
    for case in chain['cases']:
        assert not case['physical_completion'] and not case['pixels_verified']
        base,length,pad=np.frombuffer(bytes.fromhex(case['chunk']['bytes']),dtype='<u4').tolist()
        assert base==int(case['encoded_address'],16) and length==case['declared_codec_length'] and pad==0
    memory_count+=memory_records(chain)
    result=dict(ok=True,scope='Native serialization/length boundaries and decoder round trips. NOT sensor capture, patch imaging effect, physical card writes or camera installation.',
        immutable=immutable,model_sources=models,fixtures=checked,original_vs_candidate_serialization=original_compare,
        black_metadata_control=black_compare,native_length_cases=len(chain['cases']),native_length_segments=chain['segments'],
        memory_records=memory_count,rawpy=rawpy.__version__,libraw=list(rawpy.libraw_version),numpy=np.__version__)
    a.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=True,fixtures=len(checked),verified_pixels=sum(v['pixels'] for v in checked),
        cases=len(chain['cases']),segments=chain['segments'],memory_records=memory_count)))


if __name__=='__main__':main()

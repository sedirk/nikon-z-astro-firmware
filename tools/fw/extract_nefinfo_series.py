"""Read only NEF header blocks; inventory native NEFInfo6 fields per exposure."""
from pathlib import Path
import argparse, binascii, hashlib, json, struct
from bridge_real_nef_contract import nefinfo

def locate(path):
    size=path.stat().st_size
    with path.open('rb') as f:
        def read(pos,n):
            assert 0<=pos<=size and 0<=n<=min(1024*1024,size-pos)
            f.seek(pos);d=f.read(n);assert len(d)==n;return d
        h=read(0,8);order={b'II':'<',b'MM':'>'}[h[:2]]
        assert struct.unpack_from(order+'H',h,2)[0]==42
        todo=[struct.unpack_from(order+'I',h,4)[0]];seen=set()
        while todo:
            offset=todo.pop();assert offset not in seen;seen.add(offset);assert len(seen)<32
            n=struct.unpack(order+'H',read(offset,2))[0];assert n<512
            d=read(offset+2,n*12)
            for i in range(n):
                tag,typ,count,ptr=struct.unpack_from(order+'HHII',d,i*12)
                if tag==0xc7d5:
                    assert typ==7 and 18<=count<65536
                    return dict(ifds=[dict(tags={'0xc7d5':dict(offset=ptr,bytes=count)})])
                if tag==0x14a:
                    assert typ==4 and 1<=count<32
                    targets=read(ptr,count*4) if count>1 else d[i*12+8:i*12+12]
                    todo.extend(struct.unpack(order+str(count)+'I',targets))
    raise ValueError('no NEFInfo')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--metadata',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
    metadata=json.loads(a.metadata.read_text(encoding='utf8'));rows=[]
    for m in metadata:
        path=Path(m['SourceFile']);info=nefinfo(path,locate(path));d=bytes.fromhex(info['entries']['0x6']['bytes'])
        assert len(d)==116 and binascii.crc_hqx(d[:114],0xffff)==struct.unpack_from('<H',d,114)[0]
        coef=[struct.unpack_from('<i',d,k)[0] for k in (0x44,0x34,0x24,0x14)]
        rows.append(dict(name=m['System:FileName'],source=str(path),iso=m['ExifIFD:ISO'],exposure=m['ExifIFD:ExposureTime'],
            date=m['ExifIFD:DateTimeOriginal'],setting=m['Nikon:VignetteControl'],
            coefficients_1014_1020=coef,L_owner_1024=struct.unpack_from('<I',d,0x60)[0],
            status=d[4],payload=info['entries']['0x6'],container_offset=info['container']['offset']))
    result=dict(scope=__doc__,script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        metadata_sha256=hashlib.sha256(a.metadata.read_bytes()).hexdigest(),files=rows,
        field_interpretation='L is the observed direct output of owner+0x1024; do not assume a physical unit or reconstructed ISP operation.',
        unique_coefficients=sorted({tuple(r['coefficients_1014_1020']) for r in rows}),
        L_values=sorted({r['L_owner_1024'] for r in rows}),ok=True)
    a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps(dict(count=len(rows),unique_coefficients=result['unique_coefficients'],L_values=result['L_values']),indent=2))

if __name__=='__main__':main()

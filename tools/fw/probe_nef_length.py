"""Join native candidate input selection to the NEF encoded-buffer contract.

The codec wait is not executed. Its post-wait length store is a separate segment
with explicit result fixtures. No completion event, codec or ISP pixels are faked.
"""
from pathlib import Path
import argparse,json,gc,struct
import unicorn as un
from probe_raw_candidates import ROOT,RAM,OWNER,ENCODED,STACK,sha,Rig
from probe_release_contract import run,GLOBAL,CODEC_MMIO,SOURCE_SHA,FULLSIZE_SHA


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert __debug__
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    variants=[('original',ROOT/'firmware/decoded/eg1620_038000.bi',SOURCE_SHA),
        ('still-preserve-fullsize-raw',ROOT/'analysis/raw-release-contract-2026-11-08/fullsize-module/still-preserve-fullsize-raw.bi',FULLSIZE_SHA)]
    cases=[]
    for variant,path,digest in variants:
        blob=path.read_bytes();assert sha(blob)==digest
        r=Rig(blob,snapshots);r.uc.mem_map(CODEC_MMIO,0x1000)
        for depth in (0,1):
            for mode in (0,1,2):
                prior=run(r,variant,dict(area=0,size=0,mode=mode,depth=depth,wide=0,readout=1))
                lengths=[prior['uncompressed_bytes']] if mode==0 else [0,4097,1234567]
                for length in lengths:
                    calls=[];pck=RAM+0x30000;hh=RAM+0x32000;ad=RAM+0x32100;preview=RAM+0x33000;chunk=RAM+0x34000
                    # Native post-wait CPU statements only; never return from an intercepted driver.
                    r.put(ENCODED+0x5c,0xdeadbeef)
                    if mode==0:
                        calls.append(r.call(0x100a35a2,until=0x100a35aa,regs={4:GLOBAL+0x6c,5:ENCODED+0x50}))
                    else:
                        r.put(GLOBAL+0x60,0x1234);r.put(GLOBAL+0x64,length)
                        r.put(STACK+0xf008,RAM+0x35000)
                        calls.append(r.call(0x100a3446,until=0x100a3450,regs={4:GLOBAL,7:ENCODED+0x50}))
                        assert r.get(RAM+0x35000)==0x1234
                    assert r.get(ENCODED+0x5c)==length
                    r.put(hh+4,ad);r.put(ad,0x70000000);r.put(preview+8,1)
                    r.put(STACK+0xf000,hh);r.put(STACK+0xf004,pck)
                    calls.append(r.call(0x100b1634,[1,OWNER,ENCODED,preview]))
                    assert r.get(pck+4)==ENCODED+0x50
                    calls.append(r.call(0x1026ddc4,until=0x1026ddce,regs={4:pck+0x30,11:0}))
                    assert r.get(pck+0x5c)==length
                    calls.append(r.call(0x10271226,[1,pck+0x30,3,chunk]))
                    assert r.get(chunk)==r.get(ENCODED+0x58)
                    assert r.get(chunk+4)==length and r.get(chunk+8)==0
                    assert int(calls[-1]['registers']['r0'],16)==int(length==0)
                    cases.append(dict(variant=variant,depth=12 if depth==0 else 14,mode=mode,
                        declared_codec_length=length,input_address=prior['encoder_input_address'],
                        encoded_address=hex(r.get(ENCODED+0x58)),chunk=r.mem(chunk,12),
                        package=r.mem(pck,0x90),encoded_descriptor=r.mem(ENCODED+0x50,16),calls=calls,
                        upstream_contract=prior if length==lengths[0] else None,
                        physical_completion=False,pixels_verified=False))
        assert path.read_bytes()==blob
        del r;gc.collect()
    report=dict(ok=True,scope=__doc__,cases=cases,
        boundary='Original/fullsize candidate select different codec input buffers. Both pass the codec OUTPUT buffer and native declared length to RAW file chunk 3. Hardware production between these boundaries remains a separate validation.',
        segments=sum(len(x['calls'])+len((x['upstream_contract'] or {}).get('calls',[])) for x in cases))
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=True,cases=len(cases),segments=report['segments'])))


if __name__=='__main__':main()

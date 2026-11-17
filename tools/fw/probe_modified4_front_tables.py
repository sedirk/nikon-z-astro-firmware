"""Counterfactual CAL values through the exact delivered modified4 builder.

Observed static context, artificial calibration, original parameter execution.
Dispatch is stopped before hardware actions; MMIO is plain private RAM.
"""
from pathlib import Path
import argparse,json,struct,traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_PC
from probe_raw_candidates import Rig,ROOT,CAL,sha

CTX,PKT=0xc18fa844,0xc29a34c0

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in (Path(__file__).name,'probe_raw_candidates.py'):(a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    fw=ROOT/'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN'
    blob=fw.read_bytes();assert sha(blob)=='bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
    observed=ROOT/'analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json'
    event=next(e for e in json.loads(observed.read_text()) if e['event']=='static_front_builder')
    context=bytes.fromhex(event['memory']['context']['bytes'])
    assert context[0]==1 and context[0x5d]==2 and struct.unpack_from('<I',context,0x84)[0]==1
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    rig=Rig(blob,snapshots);u,p=rig.uc,rig.put
    u.mem_map(CAL+0x100000,0x68000);rig.regions+=((CAL+0x100000,0x68000),)
    selected=[];writes=[]
    def on_select(uc,pc,size,_):selected.append(hex(uc.reg_read(UC_ARM_REG_R0)))
    def on_write(uc,kind,addr,size,value,_):writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
    u.hook_add(un.UC_HOOK_CODE,on_select,begin=0x1011e23e,end=0x1011e23e)
    u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=0x20068000,end=0x20069fff)
    report=dict(ok=False,scope=__doc__,firmware_sha256=sha(blob),observed_sha256=sha(observed.read_bytes()),rows=[],comparisons=[],hardware_pixels_verified=False)
    try:
        baselines={}
        for temp in (0,1):
            for mutation in (False,True):
                cfg=dict(temporary=temp,mutation=mutation);report['current_case']=cfg
                rig.reset(dict(scalar=1008,bank=0,cached=0));u.mem_write(CTX,context);p(CTX+0x84,temp)
                for cat in (0,1):
                    data=bytearray(struct.pack('<150H',*[2000+cat*200+i for i in range(150)]))
                    for off,val in ((0x18,1),(0x1a,2),(0x1c,3),(0x1e,4)):data[off]=val
                    if mutation:struct.pack_into('<H',data,0x24+7*8+2*2,struct.unpack_from('<H',data,0x24+7*8+2*2)[0]+7)
                    u.mem_write(CAL+0x47180+cat*300,bytes(data))
                before=rig.mem(CAL,0x168000)['sha256'];selected.clear();writes.clear()
                build=rig.call(0x1017d7b6,until=0x1011d548)
                assert len(selected)==1
                packet=rig.mem(PKT,0x60);ctx=rig.mem(CTX,0xe4)
                upload=rig.call(0x100bccd0,[PKT]);regs=rig.mem(0x20068000,0x2000)
                assert len(writes)==507,len(writes)
                assert rig.mem(CAL,0x168000)['sha256']==before
                row=dict(configuration=cfg,selected=list(selected),packet=packet,context=ctx,
                    registers=regs,writes=list(writes),calls=[build,upload],cal_unchanged=True)
                report['rows'].append(row)
                if not mutation:baselines[temp]=row
                else:
                    ref=baselines[temp];assert packet==ref['packet'] and ctx==ref['context'] and selected==ref['selected']
                    changed=[(x,y) for x,y in zip(ref['writes'],writes) if x!=y]
                    assert len(changed)==1 and changed[0][0]['address']=='0x20068fd8'
                    x,y=changed[0];assert x['pc']==y['pc'] and x['size']==y['size']==4
                    assert y['value']-x['value']==7<<16
                    b0,b1=bytes.fromhex(ref['registers']['bytes']),bytes.fromhex(regs['bytes'])
                    changes=[i for i,(x,y) in enumerate(zip(b0,b1)) if x!=y]
                    assert all(0xfd8<=i<0xfdc for i in changes)
                    report['comparisons'].append(dict(temporary=temp,one_register_only=True,changed_register='0x20068fd8',packet_and_context_unchanged=True))
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();report['last_call']=rig.last_call;report['last_blocks']=rig.blocks[-30:]
        raise
    finally:
        report['firmware_unchanged']=sha(fw.read_bytes())==report['firmware_sha256']
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],rows=len(report['rows']),comparisons=len(report['comparisons']))))

if __name__=='__main__':main()

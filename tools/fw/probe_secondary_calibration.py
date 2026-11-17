"""Native ID35/ID0b gates and register writes, using private calibration/RAM.

No hardware algorithm or sensor pixels. The global driver segment stops before
its OS lock; selector and small upload routines return normally. ROM is read-only.
"""
from pathlib import Path
import argparse,json,struct,traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC
from probe_raw_candidates import Rig,ROOT,CAL,BASE,sha

CTX,STATE,GLOBAL,PROC,SECONDARY=0xc18fa844,0xc18fa954,0xc29a3230,0xc29a32b4,0x56000000
TABLES=[(0xa6e90,0x5f60),(0xacdf0,0x5f60),(0xa6e90,0x5f60),
        (0xa6e90,0x5f60),(0xacdf0,0x5f60),(0xb2d50,0x5f60),
        (0xb8cb0,0x3e20),(0xbcad0,0x5f60),(0xc2a30,0x1fe0),
        (0xc4a10,0x3e20),(0xc8830,0x1fe0),(0xc8830,0x1fe0),(0xacdf0,0x5f60)]

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in (Path(__file__).name,'probe_raw_candidates.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    fw=ROOT/'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN'
    blob=fw.read_bytes();assert sha(blob)=='bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
    stock=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    for lo,hi in ((0x1011c2a0,0x1011c820),(0x100cd64a,0x100cd77e),(0x100cda0a,0x100cda40)):
        assert blob[lo-BASE:hi-BASE]==stock[lo-BASE:hi-BASE]
    observed=ROOT/'analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json'
    event=next(e for e in json.loads(observed.read_text()) if e['event']=='static_front_builder')
    context=bytes.fromhex(event['memory']['context']['bytes'])
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    rig=Rig(blob,snapshots);u,p,g=rig.uc,rig.put,rig.get
    for address,length in ((0x20061000,0x1000),(SECONDARY,0x100000)):
        u.mem_map(address,length);rig.regions+=((address,length),)
    writes=[]
    def on_write(uc,kind,addr,size,value,_):
        writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
    u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=0x20061000,end=0x20061fff)
    def reset():
        rig.reset(dict(scalar=1008,bank=0,cached=0));u.mem_write(CTX,context)
        p(STATE+0x18,SECONDARY);writes.clear()
    report=dict(ok=False,scope=__doc__,firmware_sha256=sha(blob),hardware_pixels_verified=False,
                id35=[],global_gate=[],processing_gate=[],id0b=[],observed_context_sha256=sha(context))
    try:
        for mode in range(14):
            for enabled in (0,1):
                for present in (False,True):
                    reset();cfg=dict(mode=mode,enabled=enabled,source_present=present);report['current_case']=cfg
                    p(CTX,mode,'B');p(GLOBAL+0x1c,enabled);p(STATE+0x18,SECONDARY if present else 0)
                    # Retained descriptor is deliberate: a skipped upload is not register clearing.
                    p(0x20061264,0x12345670);p(0x20061268,0x100)
                    call=rig.call(0x1011c3f4,[CTX]);ret=int(call['registers']['r0'],16)
                    active=bool(enabled and present and mode<13)
                    assert len(writes)==(2 if active else 0)
                    assert ret==(0 if not enabled or active else 1)
                    if active:
                        off,n=TABLES[mode];assert g(0x20061264)==SECONDARY+off and g(0x20061268)==n
                    else:assert g(0x20061264)==0x12345670 and g(0x20061268)==0x100
                    report['id35'].append(dict(configuration=cfg,call=call,writes=list(writes)))
        for mode in range(13):
            for temporary in (0,1):
                for enabled in (0,1):
                    reset();cfg=dict(mode=mode,temporary=temporary,cal_field=enabled);report['current_case']=cfg
                    p(CTX,mode,'B');p(CTX+0x84,temporary)
                    selected=rig.call(0x1011c64e,[CTX]);index=int(selected['registers']['r0'],16)
                    assert index<28 and blob[0x11b7061e-BASE+index]==index
                    p(CAL+0x540+index*80,enabled,'B');p(CAL+0x541+index*80,3,'B')
                    p(CAL+0x542+index*80,5,'B');p(CAL+0x543+index*80,1,'B')
                    p(GLOBAL+0x1c,9);p(0x2006103c,9)
                    call=rig.call(0x1011c750,[0,CTX],until=0x100cd752)
                    assert g(GLOBAL+0x1c)==enabled and g(0x2006103c)==enabled
                    assert g(0x20061040)==3 and g(0x20061048)==5 and g(0x20061138)==1
                    report['global_gate'].append(dict(configuration=cfg,record_index=index,call=call,writes=list(writes)))
        for temporary in (0,1):
            for policy in (0,1,2):
                for field in (0,1,17):
                    reset();cfg=dict(temporary=temporary,policy_5a=policy,cal_halfword=field);report['current_case']=cfg
                    p(CTX+0x84,temporary);p(CTX+0x5a,policy,'B');record=CAL+0xe50
                    p(record+0x32,field,'H');p(PROC+0x24,99)
                    build=rig.call(0x1011c53c,[record,CTX]);upload=rig.call(0x100cda0a,[0,PROC+0x24])
                    expected=0 if temporary or policy==2 else field
                    assert g(PROC+0x24)==expected and g(0x20061250)==expected and len(writes)==5
                    report['processing_gate'].append(dict(configuration=cfg,calls=[build,upload],writes=list(writes)))
        for enabled in (0,1):
            for pointer in (0,SECONDARY+3):
                for count in (0,13):
                    reset();cfg=dict(enabled=enabled,explicit_pointer=hex(pointer),count=count);report['current_case']=cfg
                    p(CTX+0x50,pointer);p(CTX+0x54,count);p(STATE+0x1c,0);p(PROC+0x24,enabled)
                    call=rig.call(0x1011c2a0,[CTX]);active=bool(enabled and pointer)
                    assert len(writes)==(2 if active else 0)
                    assert int(call['registers']['r0'],16)==(0 if not enabled or active else 1)
                    if active:assert g(0x20061264)==pointer and g(0x20061268)==((3+count*2+15)&~15)
                    report['id0b'].append(dict(configuration=cfg,call=call,writes=list(writes)))
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();report['last_call']=rig.last_call;report['last_blocks']=rig.blocks[-30:]
        raise
    finally:
        report['firmware_unchanged']=sha(fw.read_bytes())==report['firmware_sha256']
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps({k:len(report[k]) for k in ('id35','global_gate','processing_gate','id0b')}))

if __name__=='__main__':main()

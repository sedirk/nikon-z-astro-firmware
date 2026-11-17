"""Follow native service-mode request packing to the interprocessor boundary.

Private RAM only. The registered transport callback is captured, not sent.
This does not establish the recipient processor's physical side effects.
"""
from pathlib import Path
import argparse,json,struct,traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR
from probe_raw_candidates import ROOT,Rig,REGS,RAM,STOP,sha

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    assert sha(b)=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    snaps=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    r=Rig(b,snaps);r.reset(dict(scalar=1008,bank=0,cached=0));u=r.uc
    report=dict(ok=False,scope=__doc__,firmware_sha256=sha(b),cases=[],hardware_access=False)
    try:
        table=r.call(0x10238a08);ptr=u.reg_read(REGS[0]);assert ptr==0xc18fadb4
        row=[hex(x) for x in struct.unpack('<16I',u.mem_read(ptr,64))]
        report['native_device_table']=dict(address=hex(ptr),functions=row,mode_request_at_plus_1c=row[7])
        captured=[];sink=STOP+0x100
        def catch(uc,pc,size,_):
            obj=uc.reg_read(REGS[0]);ctx=uc.reg_read(REGS[1]);sub=r.get(obj,'B');payload=r.get(obj+4)
            captured.append(dict(subcommand=sub,context=hex(ctx),object=r.mem(obj,8),payload=r.mem(payload,8)))
            uc.reg_write(REGS[0],1);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        u.hook_add(un.UC_HOOK_CODE,catch,begin=sink,end=sink)
        r.call(0x10238a1e,[sink|1,0x0f])
        for mode in (0,1):
            captured.clear();call=r.call(0x10238b68,[mode,0x101d8b45])
            assert len(captured)==1 and captured[0]['subcommand']==3
            src=RAM+0x50000;payload=src+0x100;out=src+0x200
            r.put(src,3,'B');r.put(src+4,payload);r.put(payload,mode);r.put(payload+4,0x101d8b45)
            select=r.call(0x10236e56,[src]);wire_code=u.reg_read(REGS[0])
            pack=r.call(0x10236724,[src,out]);assert u.reg_read(REGS[0])==1
            p,n=struct.unpack('<2I',u.mem_read(out,8));assert 0<n<=256
            report['cases'].append(dict(mode=mode,callback_capture=list(captured),request_blocks=call['blocks'],
                selector_blocks=select['blocks'],wire_command=wire_code,packing_blocks=pack['blocks'],
                packet_descriptor=r.mem(out,16),packet=r.mem(p,n)))
        report['ok']=True
    except Exception:report['error']=traceback.format_exc()
    for name in (Path(__file__).name,'probe_raw_candidates.py'):(a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2));return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())

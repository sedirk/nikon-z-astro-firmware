"""Replay the exact native MAIN mode packets into the stock companion receiver.

Native receive instructions and RAM writes only; RTOS event notification is a
captured boundary. No physical USB/SPI, worker scheduling, or flash operation.
"""
from pathlib import Path
import argparse,json,struct,importlib.util,traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_R0,UC_ARM_REG_R1
ROOT=Path(__file__).resolve().parents[2]
ROUND=ROOT/'analysis/raw-calibration-access-2026-11-10'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    source=ROUND/'companion-native-data/shoulder_display.py'
    spec=importlib.util.spec_from_file_location('companion_native',source);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    report=dict(ok=False,scope=__doc__,cases=[])
    try:
        packets=json.loads((ROUND/'native-service-boundary/result.json').read_text())['cases']
        for row in packets:
            h=mod.ShoulderDisplay(ROOT/'firmware/decoded/ex1620_037000.bi');u=h.uc;events=[];writes=[];blocks=[]
            def event(uc,pc,size,_):events.append(dict(entry=hex(pc),owner=hex(uc.reg_read(UC_ARM_REG_R0)),mask=hex(uc.reg_read(UC_ARM_REG_R1))))
            def write(uc,access,addr,size,value,_):
                if addr<0x20030000:writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=hex(value)))
            u.hook_add(un.UC_HOOK_CODE,event,begin=0x0802155a,end=0x0802155a)
            u.hook_add(un.UC_HOOK_MEM_WRITE,write,begin=0x20000000,end=0x2002ffff)
            u.hook_add(un.UC_HOOK_BLOCK,lambda uc,pc,size,_:blocks.append(hex(pc)))
            payload=bytes.fromhex(row['packet']['bytes']);request=0x20031000;data=0x20031100
            assert len(payload)==8 and payload[0]==9
            u.mem_write(data,payload);u.mem_write(request,struct.pack('<HHI',len(payload),0,data))
            # Dispatch pointer recovered from the native decompressed table.
            function=struct.unpack('<I',u.mem_read(0x2000d320+15*8+4,4))[0];assert function==0x0802aff5
            h.call(function&~1,request)
            assert len(events)==1
            report['cases'].append(dict(mode=row['mode'],payload=payload.hex(),entry=hex(function),blocks=blocks,writes=writes,events=events))
        report['ok']=True
    except Exception:report['error']=traceback.format_exc()
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes());(a.output/source.name).write_bytes(source.read_bytes())
    print(json.dumps(report,indent=2));return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())

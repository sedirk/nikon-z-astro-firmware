"""Attempt original NEF header construction from native descriptor fixtures.

This tests the serialization boundary, not physical capture, codec completion,
dark current or spatial corrections. Pixel payloads are deliberately unmapped.
"""
from pathlib import Path
import argparse,json,struct,traceback
from probe_raw_candidates import *
from unicorn.arm_const import UC_ARM_REG_CPSR

HEADER=0x68000000
PACKAGE=RAM+0x30000
HEADER_HANDLE=RAM+0x33000
ALLOC=RAM+0x33100
PREVIEW=RAM+0x34000


class HeaderRig(Rig):
    def __init__(self,blob,snap):
        super().__init__(blob,snap)
        self.uc.mem_map(HEADER,0x100000)
        self.invalid=[]
        self.uc.hook_add(un.UC_HOOK_MEM_INVALID,self.on_invalid)
    def on_invalid(self,uc,access,address,size,value,_):
        self.invalid.append(dict(access=access,address=hex(address),size=size,
            pc=hex(uc.reg_read(UC_ARM_REG_PC)),lr=hex(uc.reg_read(UC_ARM_REG_LR))))
        return False
    def call(self,entry,args=(),until=STOP,regs=None,stack_args=()):
        for i,value in enumerate(stack_args): self.put(STACK+0xf000+i*4,value)
        result=super().call(entry,args,until,regs)
        result['stack_args']=[hex(v) for v in stack_args]
        return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); assert __debug__
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    source=ROOT/'firmware/decoded/eg1620_038000.bi'
    b=source.read_bytes(); assert sha(b)=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    obs=ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json'
    snap=json.loads(obs.read_text())['final']
    r=HeaderRig(b,snap)
    report=dict(ok=False,scope=__doc__,calls=[],firmware_sha256=sha(b),
        probe_sha256=sha(Path(__file__).read_bytes()),observed_sha256=sha(obs.read_bytes()),
        assumptions=['Owner is cloned from the saved QEMU object; fields below are explicit fixtures.',
          'Encoded length is a descriptor fixture, not a hardware completion result.',
          'Header storage is writable private RAM; all image payload addresses are unmapped.'])
    try:
        r.reset(dict(scalar=300,bank=0,cached=0,owner_mode=1))
        for off,val in ((0x170,0),(0x192,0),(0x194,0),(0x195,0),(0x2811,0)):
            r.put(OWNER+off,val,'B')
        r.put(ENCODED+4,ALLOC+0x20);r.put(ALLOC+0x20,0x64000000)
        report['calls'].append(r.call(0x101254bc,[ENCODED,OWNER]))
        r.put(ENCODED+0x5c,36780160)
        r.put(HEADER_HANDLE+4,ALLOC);r.put(ALLOC,HEADER)
        report['calls'].append(r.call(0x100b1634,[1,OWNER,ENCODED,PREVIEW],stack_args=[HEADER_HANDLE,PACKAGE]))
        assert r.get(PACKAGE+4)==ENCODED+0x50
        report['package_before']=r.mem(PACKAGE,0x90)
        report['calls'].append(r.call(0x103269ac,[0,1,PACKAGE+0x30]))
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        report['failure']=dict(pc=hex(r.uc.reg_read(UC_ARM_REG_PC)),
            registers={f'r{i}':hex(r.uc.reg_read(reg)) for i,reg in enumerate(REGS)},
            lr=hex(r.uc.reg_read(UC_ARM_REG_LR)),last_call=r.last_call,
            blocks=list(r.blocks),invalid=r.invalid)
    finally:
        report['final_package']=r.mem(PACKAGE,0x90)
        report['header_prefix']=r.mem(HEADER,4096)
        (a.output/'header-allocation.bin').write_bytes(bytes(r.uc.mem_read(HEADER,0x100000)))
        report['firmware_unchanged']=source.read_bytes()==b
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(dict(ok=report['ok'],calls=len(report['calls']),failure=report.get('failure',{}).get('pc'))))
    return 0 if report['ok'] else 1


if __name__=='__main__': raise SystemExit(main())

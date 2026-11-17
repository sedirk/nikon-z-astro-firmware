"""Replay captured periodic kind1 contexts from the QEMU timeout, in native ROM.

This separates a reproducible dispatch semantic change from a synthetic
scheduler wait. It does not by itself establish the cause of that wait.
CAL is explicitly zero as in QEMU; no pixel or interrupt model is invented.
"""
from pathlib import Path
import argparse,json
import unicorn as un
from unicorn.arm_const import *
from probe_raw_candidates import Rig,CAL
from review_id35_preflash import ROOT,ROUND,SOURCES
from verify_id35_preflash_kit import need,read_module,sha

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);result=dict(ok=False,scope=__doc__,rows=[],comparisons=[])
    snaps=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    for observed in ('m4','m5'):
        j=json.loads((ROUND/f'qemu-{observed}-shooting/result.json').read_text())
        e=next(e for e in reversed(j['events']) if e['event']=='id35_dispatch' and e['registers']['r14']=='0x1017c9cf')
        pair=[]
        for variant in ('modified4','test'):
            r=Rig(read_module(SOURCES[variant],variant),snaps);u=r.uc;writes=[]
            for addr,size in ((0x20061000,0x1000),(0x56000000,0x400000),(CAL+0x100000,0x68000)):
                u.mem_map(addr,size);r.regions+=((addr,size),)
            def mutex(uc,pc,size,data):uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            for pc in (0x10170df0,0x10170dea):u.hook_add(un.UC_HOOK_CODE,mutex,begin=pc,end=pc)
            def on_write(uc,kind,addr,size,value,data):writes.append(dict(address=hex(addr),size=size,value=value))
            u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=0x20061000,end=0x20061fff)
            r.reset(dict(scalar=1008,bank=0,cached=0));u.mem_write(0xc18fa844,bytes.fromhex(e['context']))
            u.mem_write(0xc29a3230,bytes.fromhex(e['global_packet']))
            r.put(0xc18fa954+0x18,0x56000000);r.put(0xc18fa954+0x1c,0x560e0000)
            u.reg_write(UC_ARM_REG_CPSR,int(e['registers']['cpsr'],16));writes.clear()
            before=r.mem(0xc18fa844,0xe4);cal=r.mem(CAL,0x168000)['sha256']
            regs={i:int(e['registers'][f'r{i}'],16) for i in range(13)}
            call=r.call(0x1011c750,regs=regs)
            need(r.mem(CAL,0x168000)['sha256']==cal and r.mem(0xc18fa844,0xe4)==before,'Source changed')
            row=dict(observed=observed,variant=variant,call=call,writes=list(writes),global_packet=r.mem(0xc29a3230,0x180),
                mmio=r.mem(0x20061000,0x1000),context=before,cpsr=hex(u.reg_read(UC_ARM_REG_CPSR)))
            pair.append(row);result['rows'].append(row)
        x,y=pair
        for k in ('writes','global_packet','mmio','context','cpsr'):need(x[k]==y[k],'Divergence '+k)
        for i in (0,*range(4,12)):need(x['call']['registers'][f'r{i}']==y['call']['registers'][f'r{i}'],'Register divergence')
        result['comparisons'].append(dict(observed=observed,equal=True,return_r0=x['call']['registers']['r0']))
    result['ok']=True
    (a.output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True,pairs=len(result['comparisons']))))

if __name__=='__main__':main()

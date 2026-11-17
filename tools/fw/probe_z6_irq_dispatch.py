"""Execute native registration -> IRQ87 dispatch -> event -> still-wait branch.

Private RAM/MMIO and explicitly injected status/RTOS services only. This is not
hardware interrupt generation, an ID35 pixel model, or a physical Err replay.
"""
from pathlib import Path
import argparse, gc, json, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP
from probe_raw_candidates import Rig, ROOT, REGS, STACK, STOP, sha
from verify_modified5_recovery import DIGESTS, REVOKED
from probe_modified5_completion import EVENT, HANDLE, CTX, MUTEX, OS_SET, OS_CLEAR, OS_WAIT

OWNER, STATUS, CALLBACK = 0xc1806d84, 0x20060044, 0x10178de8
NOTIFY, SECOND = STOP+0x100, STOP+0x200

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    p=ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json'
    snaps=json.loads(p.read_text(encoding='utf8'))['final']
    report=dict(ok=False,scope=__doc__,cases=[],source_snapshots_sha256=sha(p.read_bytes()),
        mmio_status_injected=True,rtos_services_injected=True,physical_causality_proven=False)
    variants=[('stock',ROOT/'firmware/decoded/eg1620_038000.bi','1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'),
        ('modified4',ROOT/'outputs/Z6-C380-recovery-from-modified5-2026-11-10/01_RECOVER_MODIFIED4/EG162080.BIN',DIGESTS['modified4']),
        ('recalled_modified5',ROOT/'analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED',REVOKED)]
    try:
        for variant,path,digest in variants:
            blob=path.read_bytes();assert sha(blob)==digest
            r=Rig(blob,snaps);u=r.uc;u.mem_map(0x20060000,0x2000);r.regions+=((0x20060000,0x2000),)
            state=dict(flags=0);services=[];mmio=[];callbacks=[]
            def hook(uc,pc,size,_):
                args=[uc.reg_read(x) for x in REGS[:4]]
                if pc==CALLBACK:
                    callbacks.append(dict(pc=hex(pc),args=[hex(x) for x in args[:2]]));return
                row=dict(pc=hex(pc),args=[hex(x) for x in args]);result=0
                if pc in (OS_SET,OS_CLEAR,OS_WAIT):
                    assert args[0]==HANDLE
                    if pc==OS_SET:state['flags']|=args[1]
                    elif pc==OS_CLEAR:state['flags']&=args[1]
                    else:
                        assert args[1:3]==[8,0]
                        assert r.get(uc.reg_read(UC_ARM_REG_SP))==50
                        got=state['flags']&8;r.put(args[3],got);result=0 if got else 1
                        row.update(observed=hex(got),injected_rtos_result=result)
                row['flags_after']=hex(state['flags']);services.append(row)
                uc.reg_write(UC_ARM_REG_R0,result);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            def memhook(uc,access,address,size,value,_):
                mmio.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),access='write' if access==un.UC_MEM_WRITE else 'read',
                    address=hex(address),size=size,value=hex(value if access==un.UC_MEM_WRITE else r.get(address))))
            for pc in (CALLBACK,NOTIFY,SECOND,*MUTEX,OS_SET,OS_CLEAR,OS_WAIT):u.hook_add(un.UC_HOOK_CODE,hook,begin=pc,end=pc)
            u.hook_add(un.UC_HOOK_MEM_READ|un.UC_HOOK_MEM_WRITE,memhook,begin=STATUS,end=STATUS+3)
            for status in (0,0x10,0x80,0x400,0x40000,0x40490):
                for second_enabled in (False,True):
                    report['current_case']=[variant,hex(status),second_enabled]
                    r.reset(dict(scalar=1008,bank=0,cached=0));services.clear();callbacks.clear();mmio.clear()
                    r.put(0xc180b7a4,OWNER);r.put(OWNER+0x34,0);r.put(OWNER+0x38,0);r.put(OWNER+0x3c,0)
                    # Execute the ROM's table zeroing, literal callback selection,
                    # wrapper and full low-level registration, including native memcpy.
                    reg=r.call(0x10179014,until=0x10179032,regs={1:0,2:STACK+0xf004,4:0xc18fa7a0})
                    assert r.get(OWNER+0x34)==CALLBACK|1
                    assert r.get(OWNER+8)==r.get(OWNER+8+8*4)==0x10178fc3
                    assert r.get(OWNER+0x38)==r.get(OWNER+0x3c)==0
                    registration=r.mem(OWNER,0x40)
                    if second_enabled:r.put(OWNER+0x38,SECOND|1)
                    r.put(EVENT,HANDLE);r.put(0xc18fa7a0+4,NOTIFY|1)
                    state['flags']=0xfff
                    start=r.call(0x10179d82,until=0x10179da4,regs={4:CTX,5:0})
                    assert state['flags']==0xff7
                    state['flags']=0;saved=u.context_save();r.put(STATUS,status)
                    irq=r.call(0x1010c850);flags=state['flags']
                    expected=(8 if status&0x10 else 0)|(4 if status&0x80 else 0)|(32 if status&0x400 else 0)|(16 if status&0x40000 else 0)
                    assert flags==expected
                    assert callbacks==[dict(pc=hex(CALLBACK),args=['0x41080c01',hex(status)])]
                    assert [(x['access'],x['value']) for x in mmio]==[('read',hex(status)),('write',hex(status))]
                    second=[x for x in services if x['pc']==hex(SECOND)]
                    assert len(second)==int(second_enabled)
                    if second:assert second[0]['args'][:2]==['0x41080c01',hex(status)]
                    u.context_restore(saved);r.blocks.clear();u.emu_start(0x10179da5,0x10179dc4,count=10000)
                    assert u.reg_read(UC_ARM_REG_PC)==0x10179dc4
                    after=u.reg_read(REGS[5]);assert after==(0 if status&0x10 else 0x20)
                    report['cases'].append(dict(variant=variant,module_sha256=digest,injected_status=hex(status),
                        second_callback_fixture=second_enabled,registration=registration,registration_blocks=reg['blocks'],
                        native_irq_blocks=irq['blocks'],native_callback_args=list(callbacks),status_register_accesses=list(mmio),
                        services=list(services),native_event_flags=hex(flags),native_wait_status=hex(after),wait_blocks=list(r.blocks)))
            del r,u;gc.collect()
        keys=set(report['cases'][0])-{'variant','module_sha256'}
        for i in range(12):
            for delta in (12,24):
                for key in keys:assert report['cases'][i][key]==report['cases'][i+delta][key],key
        report.update(ok=True,case_count=len(report['cases']),identical_dispatch_for_stock_m4_m5=True)
        report.pop('current_case',None)
    except Exception:report['error']=traceback.format_exc()
    for name in (Path(__file__).name,'probe_raw_candidates.py','verify_modified5_recovery.py','probe_modified5_completion.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    (a.output/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),error=report.get('error'))))
    return 0 if report['ok'] else 1

if __name__=='__main__':raise SystemExit(main())

"""Offline updater control-flow audit, including a RAM-only flash service model.

Filename/CRC and inverse acceptance execute the original or candidate ROM.
The scatter-loaded update scheduler executes native instructions; low-level
erase/program services modify private Unicorn memory only. This tests target
bounds, order, readback comparisons and failure reporting, NOT real flash,
boot, electrical behavior, power-loss recovery or RAW pixels.
"""
from pathlib import Path
import argparse,json,struct,traceback
import unicorn as un
from unicorn.arm_const import *
import probe_eg_update_route as eg

ROOT=eg.ROOT; BASE=eg.BASE; CAP=0x2940000; SECTOR=0x20000
BACKEND={0xc2a10602:'MODEL_erase_sector',0xc2a10616:'MODEL_program_halfwords',
         0xc2a1064a:'MODEL_hardware_setup',0xc2a10cc2:'OBSERVE_completion',
         0xc2a10c00:'MODEL_progress_notification',0xc2a10e94:'MODEL_hardware_handshake'}
eg.SERVICES.update(BACKEND)

def check(test,message):
    if not test:raise ValueError(message)

class AuditRig(eg.Rig):
    def __init__(self,rom):
        super().__init__(rom)
        self.u.mem_map(0x10000000,SECTOR)
        mapped_end=BASE+((len(rom)+4095)&~4095)
        self.u.mem_map(mapped_end,BASE+CAP+4096-mapped_end)
        self.flash_events=[];self.completions=[];self.failure=None

    def adapter(self,pc):
        if pc not in BACKEND:return super().adapter(pc)
        a=[self.u.reg_read(r) for r in eg.REGS[:4]];ret=0
        row=dict(pc=hex(pc),service=BACKEND[pc],args=[hex(x) for x in a])
        if pc==0xc2a10602:
            dest=0x10000000+a[0]*SECTOR
            check(a[1]==1 and BASE<=dest and dest+SECTOR<=BASE+CAP,'Erase outside main region')
            if self.failure=='erase':ret=1
            else:self.u.mem_write(dest,b'\xff'*SECTOR)
            row.update(destination=hex(dest),bytes=SECTOR,modeled=True)
        elif pc==0xc2a10616:
            dest,src,halfwords=a[:3];n=halfwords*2
            check(n==SECTOR and BASE<=dest and dest+n<=BASE+CAP,'Program outside main region')
            check(src-eg.BUFFER==dest-BASE,'Source/destination offset mismatch')
            content=bytes(self.u.mem_read(src,n))
            check(bytes(self.u.mem_read(dest,n))==b'\xff'*n,'Program before erase')
            self.u.mem_write(dest,content)
            if self.failure=='readback':
                self.u.mem_write(dest,bytes([content[0]^1]));row['injected_readback_mismatch']=True
            row.update(destination=hex(dest),source=hex(src),bytes=n,modeled=True)
        elif pc==0xc2a10cc2:self.completions.append(a[0]);row['completion_status']=a[0]
        row['return']=ret;self.flash_events.append(row)
        self.u.reg_write(UC_ARM_REG_R0,ret)
        return self.u.reg_read(UC_ARM_REG_LR)

def schedule(rig,label,data,failure=None):
    rig.reset(data,'EG162080.BIN')
    # RAM-only flash image, with protected prefix and tail canaries. Initial
    # contents use the currently executing module and a non-erased tail.
    rig.u.mem_write(BASE,rig.rom)
    rig.u.mem_write(BASE+len(rig.rom),b'\xa5'*(CAP-len(rig.rom)))
    prefix=bytes((i*17+3)&255 for i in range(SECTOR));tail=b'GUARD-AFTER-EG!!!'
    rig.u.mem_write(0x10000000,prefix);rig.u.mem_write(BASE+CAP,tail)
    rig.u.mem_write(eg.BUFFER,data)
    rig.call(0x101b8f44,[eg.BUFFER,len(data)-2,0,0],until=0x1014a674)
    descriptor=rig.u.reg_read(UC_ARM_REG_R2)
    # The former stop boundary is an ARM veneer to context setup, not an
    # erase primitive. Run its native target; stop hardware services below.
    rig.call(0xc2a10c72,[eg.BUFFER,len(data)-2,descriptor])
    rig.flash_events=[];rig.completions=[];rig.failure=failure
    rig.call(0xc2a10c28,until=0xc2a10bf0)
    check(bytes(rig.u.mem_read(0x10000000,SECTOR))==prefix,'Prefix changed')
    check(bytes(rig.u.mem_read(BASE+CAP,len(tail)))==tail,'Tail canary changed')
    erased=[e for e in rig.flash_events if e['service']=='MODEL_erase_sector']
    written=[e for e in rig.flash_events if e['service']=='MODEL_program_halfwords']
    if failure is None:
        check(rig.completions==[0],'Unexpected completion failure')
        check(len(erased)==len(written)==CAP//SECTOR==330,'Unexpected sector count')
        check([int(x['destination'],16) for x in erased]==list(range(BASE,BASE+CAP,SECTOR)),'Erase order')
        check([int(x['destination'],16) for x in written]==list(range(BASE+SECTOR,BASE+CAP,SECTOR))+[BASE],'Program order')
        expected=data[:-2]+b'\xff'*(CAP-len(data)+2)
        check(bytes(rig.u.mem_read(BASE,CAP))==expected,'Final model buffer differs')
    else:
        check(rig.completions==[1],'Failure reported as success')
        if failure=='erase':check(len(erased)==6 and len(written)==0,'Erase retry policy mismatch')
        if failure=='readback':check(len(written)==6 and all(int(e['destination'],16)==BASE+SECTOR for e in written),'Readback failure escaped')
    return dict(label=label,failure_injection=failure,rom_sha256=eg.sha(rig.rom),input_sha256=eg.sha(data),
        completion=rig.completions,erase_service_calls=len(erased),program_service_calls=len(written),
        prefix_preserved=True,tail_canary_preserved=True,main_start=hex(BASE),main_end_exclusive=hex(BASE+CAP),
        model_final_sha256=eg.sha(bytes(rig.u.mem_read(BASE,CAP))),events=rig.flash_events,calls=rig.calls)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    original=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    candidate=(ROOT/'outputs/Z6-C380-neighborhood-candidate-2026-11-09/candidate/EG162080.BIN').read_bytes()
    check(eg.sha(original)==eg.SOURCE_SHA and eg.sha(candidate)==eg.CANDIDATE_SHA,'Hash mismatch')
    report=dict(ok=False,scope=__doc__,inverse_acceptance=[],scheduler=[],physical_flash_executed=False)
    try:
        # New coverage: candidate ROM accepting the exact original rollback.
        rig=AuditRig(candidate)
        inverse=eg.run(rig,'candidate_ROM_accepts_original_EG',original)
        check(inverse['integrity_return']==0 and inverse['component_precheck_return']==0,'Rollback preflight failed')
        report['inverse_acceptance'].append(inverse)
        for label,rom,data,failure in (
            ('forward',original,candidate,None),('rollback',candidate,original,None),
            ('erase_error',original,candidate,'erase'),('readback_mismatch',original,candidate,'readback')):
            rig=AuditRig(rom);row=schedule(rig,label,data,failure);report['scheduler'].append(row)
            print(json.dumps({k:v for k,v in row.items() if k not in ('events','calls')}),flush=True)
        report['ok']=True
    except Exception:
        report.update(error=traceback.format_exc(),pc=hex(rig.u.reg_read(UC_ARM_REG_PC)),
                      failing_calls=rig.calls,failing_model_events=rig.flash_events)
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        for name in ('probe_preflash_review.py','probe_eg_update_route.py'):
            (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    print(json.dumps(dict(ok=report['ok'],inverse_acceptance=1,scheduler_cases=4)))

if __name__=='__main__':main()

"""Execute the native capture-error consumer with an observed-code input, not a camera fault trace."""
from pathlib import Path
import argparse,gc,json,struct
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_LR,UC_ARM_REG_PC
from probe_raw_candidates import Rig,ROOT,sha
from verify_modified5_recovery import DIGESTS,REVOKED


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    snaps=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    rows=[]
    for name,path,digest in (
        ('modified4',ROOT/'outputs/Z6-C380-recovery-from-modified5-2026-11-10/01_RECOVER_MODIFIED4/EG162080.BIN',DIGESTS['modified4']),
        ('recalled_modified5',ROOT/'analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED',REVOKED)):
        blob=path.read_bytes();assert sha(blob)==digest
        r=Rig(blob,snaps);captured=[]
        def callback(uc,pc,size,_):
            address=uc.reg_read(UC_ARM_REG_R1);data=bytes(uc.mem_read(address,12))
            captured.append(dict(event=hex(uc.reg_read(UC_ARM_REG_R0)),payload=data.hex(),
                                 subtype=data[0],stage=struct.unpack_from('<I',data,4)[0],
                                 status=hex(struct.unpack_from('<I',data,8)[0])))
            uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        r.uc.hook_add(un.UC_HOOK_CODE,callback,begin=0x50058000,end=0x50058000)
        for status,code in ((0,None),(0x20,8),(0x24,8),(0x420,14)):
            r.reset(dict(scalar=1008,bank=0,cached=0));captured.clear()
            r.put(0xc18b7750+0x70,0);r.put(0xc18b7750+0x1c,0x50058001);r.put(0xc18b7750,13,'B')
            call=r.call(0x100f4a32,[status])
            if code is None:assert not captured
            else:
                assert len(captured)==1 and captured[0]['event']=='0x41f0181'
                assert captured[0]['subtype']==code and captured[0]['stage']==13 and captured[0]['status']==hex(status)
            rows.append(dict(variant=name,module_sha256=digest,injected_local_status=hex(status),
                             calls=list(captured),blocks=call['blocks']))
        del r;gc.collect()
    for x,y in zip(rows[:4],rows[4:]):
        for key in ('injected_local_status','calls','blocks'):assert x[key]==y[key]
    result=dict(ok=True,scope=__doc__,cases=rows,callback_is_fixture=True,
        conclusion='0x20 from the earlier completion branch is handled as event 0x041f0181 / payload subtype 8, retaining the full status word. Higher-priority error bits can change the subtype.',
        limits='Subcode 8 is distinct from RTOS event-bit 8. No mapping to the displayed Err/restart cause is asserted; no camera RAM/log was captured.')
    (a.output/'result.json').write_bytes(json.dumps(result,indent=2).encode('utf8'))
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True,cases=len(rows))))


if __name__=='__main__':main()

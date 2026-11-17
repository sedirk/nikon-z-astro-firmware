"""Native static-property ABI/flag audit; no pixel or peripheral model."""
from pathlib import Path
import argparse,json,itertools,traceback
from unicorn.arm_const import UC_ARM_REG_CPSR,UC_ARM_REG_SP
from probe_still_neighborhood_off import setup
from probe_raw_candidates import Rig,ROOT,MAINREQ,MAINOUT,OWNER,REGS,STACK,sha

def require(test,msg):
    if not test:raise ValueError(msg)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    inputs=[('original',ROOT/'firmware/decoded/eg1620_038000.bi'),
            ('candidate',ROOT/'outputs/Z6-C380-neighborhood-candidate-2026-11-09/candidate/EG162080.BIN')]
    expected=['1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
              'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875']
    rows=[];report=dict(ok=False,scope=__doc__,cases=rows);paired={}
    try:
        for (label,path),digest in zip(inputs,expected):
            blob=path.read_bytes();require(sha(blob)==digest,'Input hash changed');rig=Rig(blob,snapshots)
            for cls,o,to,mode in ((2,1,1,0),(0,0,0,0),(1,2,2,0),(255,255,255,0),(3,3,3,0),(2,1,1,1)):
                cfg=dict(cls=cls,table=1,override=o,table_override=to,selector=0,subselector=0,mode=mode,bank=0)
                setup(rig,cfg)
                for flags in range(16):
                    cpsr=rig.uc.reg_read(UC_ARM_REG_CPSR)
                    rig.uc.reg_write(UC_ARM_REG_CPSR,(cpsr&0x0fffffff)|(flags<<28))
                    saved={i:0xa0b00000+i*0x10101 for i in range(4,12)}
                    before=bytes(rig.uc.mem_read(OWNER,0x3000))
                    call=rig.call(0x100c24f2,[MAINREQ,MAINOUT],regs=saved)
                    require(rig.uc.reg_read(UC_ARM_REG_SP)==STACK+0xf000,'Stack not restored')
                    require(all(rig.uc.reg_read(REGS[i])==v for i,v in saved.items()),'Callee-saved register altered')
                    require(bytes(rig.uc.mem_read(OWNER,0x3000))==before,'Input owner changed')
                    prop=bytes(rig.uc.mem_read(rig.get(MAINOUT),0xa0))
                    key=(cls,o,to,mode,flags);paired[(label,key)]=prop
                    rows.append(dict(variant=label,fixture=cfg,nzcv=flags,sp_preserved=True,
                        callee_saved_preserved=True,owner_preserved=True,properties_sha256=sha(prop)))
        for key in [k for label,k in paired if label=='original']:
            x,y=paired[('original',key)],paired[('candidate',key)]
            delta={i for i,(a,b) in enumerate(zip(x,y)) if a!=b}
            require(delta<={0x4c,0x4e,0x4f},'Unexpected property difference')
            if key[3]:require(not delta,'Alternate mode changed')
            require(y==paired[('candidate',(*key[:-1],0))],'Candidate depends on incoming NZCV')
        report.update(ok=True,executions=len(rows),paired_configurations=len(rows)//2)
    except Exception:report['error']=traceback.format_exc();raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        for name in ('probe_preflash_abi.py','probe_still_neighborhood_off.py','probe_raw_candidates.py'):
            (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    print(json.dumps(dict(ok=True,executions=len(rows),pairs=len(rows)//2)))
if __name__=='__main__':main()

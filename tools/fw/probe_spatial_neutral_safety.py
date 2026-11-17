"""ABI, source-access and retained-state checks for the 17-table LAB copy.

Native instructions with private inputs. No hardware completion or image math.
"""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_SP, UC_ARM_REG_PC
from probe_raw_candidates import Rig, ROOT, RAM, STACK, FRAME, OWNER, STAGE, CTX, PROPS, CACHE, A, SPATIAL, sha
from probe_spatial_neutral import inputs, P_CONTEXT, M_CONTEXT

ROUND=ROOT/'analysis/raw-spatial-neutral-2026-11-09'
E,STATE,SOURCE,SCACHE,GRID=[RAM+x for x in (0x3b000,0x3c020,0x3d000,0x3e000,0x35000)]
SENTINELS={i:0x40404040+i*0x1010101 for i in range(4,12)}

def seed(rig,coeffs):
    rig.reset(dict(scalar=1008,bank=0,cached=0))
    u,p=rig.uc,rig.put
    for off,val in ((0,SOURCE),(4,6064*256),(8,4040*256),(16,SCACHE),(28,STATE)):p(E+off,val)
    u.mem_write(SOURCE+9,bytes(range(1,9)));p(SOURCE+0x14,GRID);p(SOURCE+0x1a,16,'H')
    grid=[0]*864
    for knot,c in itertools.product(range(8),range(6)):grid[knot*108+c*18]=coeffs[c]
    u.mem_write(GRID,struct.pack('<864i',*grid))
    u.mem_write(SCACHE+4,struct.pack('<6i',*coeffs))
    u.mem_write(STATE-16,b'\xa3'*16);u.mem_write(STATE+0x6c,b'\x3a'*16)
    u.mem_write(STATE,b'\x7b'*0x6c)

def configure(rig,cfg):
    p,u=rig.put,rig.uc
    p(E+0xd,cfg['cached'],'B');p(E+0x14,cfg['mode'],'B')
    p(E+0x16,cfg['xy'][0],'h');p(E+0x18,cfg['xy'][1],'h')
    p(SOURCE,cfg['source'],'B');p(SOURCE+0x19,cfg['bit2'],'B')
    u.mem_write(SCACHE,bytes(cfg['cache_flags']))

def one(rig,cfg,neutral,flags):
    configure(rig,cfg);u=rig.uc
    frozen=[rig.mem(a,n) for a,n in ((E,32),(SOURCE,32),(SCACHE,28),(GRID,3456))]
    u.reg_write(UC_ARM_REG_CPSR,(u.reg_read(UC_ARM_REG_CPSR)&0x0fffffff)|(flags<<28))
    call=rig.call(0x10197500,[E],regs=SENTINELS)
    assert u.reg_read(UC_ARM_REG_SP)==STACK+0xf000
    for i,v in SENTINELS.items():assert call['registers'][f'r{i}']==hex(v)
    assert bytes(u.mem_read(STATE-16,16))==b'\xa3'*16
    assert bytes(u.mem_read(STATE+0x6c,16))==b'\x3a'*16
    assert frozen==[rig.mem(a,n) for a,n in ((E,32),(SOURCE,32),(SCACHE,28),(GRID,3456))]
    state=bytes(u.mem_read(STATE,0x6c))
    if neutral:
        assert state[0x1d]==0 and state[0x26:0x6a]==bytes(68)
        xy=struct.unpack_from('<2h',state,0x1e)
        assert xy==((0,0) if state[0x1c] else tuple(cfg['xy']))
        assert struct.unpack_from('<6i',state,4)==(16*xy[0],0,0,16*xy[1],0,0)
    return dict(fixture=cfg,initial_NZCV=flags,state_hex=state.hex(),abi_ok=True,
        canaries_ok=True,source_inputs_unchanged=True,call=call)

def guard(rig,coeffs,cached,neutral):
    seed(rig,coeffs)
    cfg=dict(cached=cached,mode=0,source=1,bit2=0,cache_flags=[0,1],xy=[19,-23])
    configure(rig,cfg);u,p=rig.uc,rig.put
    if cached:
        # Cache flags mapped, six coefficient words deliberately unmapped.
        p(E+16,RAM+0x5fffc);u.mem_write(RAM+0x5fffc,b'\0\1\0\0')
        expected_fault=RAM+0x60000
    else:
        p(SOURCE+0x14,0x68000000);expected_fault=0x68000000
    fault=[]
    def invalid(uc,access,addr,size,value,user):
        fault.append(dict(address=hex(addr),pc=hex(uc.reg_read(UC_ARM_REG_PC)),size=size));return False
    hook=u.hook_add(un.UC_HOOK_MEM_READ_UNMAPPED,invalid)
    error=None;call=None
    try:call=rig.call(0x10197500,[E],regs=SENTINELS)
    except un.UcError as exc:error=str(exc)
    finally:u.hook_del(hook)
    if neutral:
        assert not fault and error is None
        assert bytes(u.mem_read(STATE+0x26,68))==bytes(68)
    else:
        assert fault and expected_fault<=int(fault[0]['address'],16)<expected_fault+3456
        assert error is not None
    return dict(cached=cached,expected_baseline_fault=hex(expected_fault),faults=fault,error=error,call=call,
        last_blocks=list(rig.blocks[-30:]),neutral_source_payload_skipped=neutral)

def callers(rig,coefs,spatial,neutral,bank):
    inputs(rig,dict(cached=0,bank=bank),coefs,spatial)
    u,p,g=rig.uc,rig.put,rig.get
    for off in (0x1cc,0x1d0):p(FRAME+off,0)
    calls=[rig.call(0x100ad52e,[STAGE])]
    assert g(FRAME+0x1cc)==1 and '0x100c24d4' in calls[-1]['blocks']
    pre=bytes(u.mem_read(STAGE+0x468,0x6c))
    calls.append(rig.call(0x100ad6f8,[STAGE]))
    assert g(FRAME+0x1d0)==1
    assert '0x100c2824' in calls[-1]['blocks'] and '0x1017206e' in calls[-1]['blocks']
    assert '0x10197500' not in calls[-1]['blocks']
    assert bytes(u.mem_read(M_CONTEXT+0x58,0x6c))==pre
    if neutral:
        assert pre[0x1d]==0 and pre[0x26:0x6a]==bytes(68)
        assert bytes(u.mem_read(STAGE+0x4e8,68))==bytes(68)
        assert g(A+0x180,'B')==0
    after=rig.mem(STAGE+0x3e8,0x190)
    calls.extend([rig.call(0x100ad52e,[STAGE]),rig.call(0x100ad6f8,[STAGE])])
    assert '0x100c24d4' not in calls[-2]['blocks'] and '0x100c2824' not in calls[-1]['blocks']
    assert rig.mem(STAGE+0x3e8,0x190)==after
    return dict(bank=bank,precomputed_hex=pre.hex(),generated_stage=after,
        exported_parameters=rig.mem(A,0x500),repeat_flags_skip=True,calls=calls)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=('safety','callers'),required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    for name in ('probe_spatial_neutral_safety.py','probe_spatial_neutral.py','probe_raw_candidates.py',
                 'probe_still_vignette_neutral.py','probe_still_neighborhood_off.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    fields=json.loads((ROOT/'analysis/modified2-flat-2026-11-09/correction-fields/result.json').read_text())['files'][0]
    coefs=fields['vignette']['coefficients'];spatial=fields['two_table_spatial']['coefficients']
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,mode=a.mode,abi=[],sequence=[],guards=[],callers=[])
    try:
        variants=[('modified2',ROOT/'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN'),
                  ('spatial-neutral-lab',ROUND/'lab-module/neighborhood-vignette-spatial-neutral-lab.bi')]
        for variant,path in variants:
            blob=path.read_bytes();rig=Rig(blob,snap);neutral=variant!='modified2'
            if a.mode=='callers':
                for bank in (0,1):
                    report['current_case']=[variant,'caller',bank]
                    row=callers(rig,coefs,spatial,neutral,bank);row['variant']=variant;report['callers'].append(row)
            else:
                for cached,flags in itertools.product((0,1),([0,1],[1,1],[0,0],[1,0])):
                    reference=None
                    for nzcv in range(16):
                        cfg=dict(cached=cached,mode=0,source=1,bit2=0,cache_flags=flags,xy=[19,-23])
                        report['current_case']=[variant,'abi',cfg,nzcv];seed(rig,spatial)
                        row=one(rig,cfg,neutral,nzcv);row['variant']=variant
                        if reference is None:reference=row['state_hex']
                        assert reference==row['state_hex']
                        report['abi'].append(row)
                seed(rig,spatial)
                # Keep the same output/state across all transitions; seed only once.
                for i,(cached,mode,src,bit2,flags) in enumerate(itertools.product(
                        (0,1),(0,7),(1,0),(0,4),([0,1],[1,1]))):
                    cfg=dict(cached=cached,mode=mode,source=src,bit2=bit2,cache_flags=flags,xy=[i-12,15-i])
                    report['current_case']=[variant,'sequence',i,cfg]
                    row=one(rig,cfg,neutral,i%16);row['variant']=variant;row['step']=i
                    report['sequence'].append(row)
                for cached in (0,1):
                    report['current_case']=[variant,'source-guard',cached]
                    row=guard(rig,spatial,cached,neutral);row['variant']=variant;report['guards'].append(row)
            del rig;gc.collect()
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['last_call']=rig.last_call;report['last_blocks']=rig.blocks[-30:]
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],counts={k:len(report[k]) for k in ('abi','sequence','guards','callers')})))

if __name__=='__main__':main()

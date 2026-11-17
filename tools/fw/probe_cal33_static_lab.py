"""Compare exact LAB bytes with modified4 using real CAL38/ID35 in private RAM.

Native selectors, builder and upload execute; MMIO is storage, not an ISP model.
Synthetic contexts and separately stopped stages do not establish shutter/NEF success.
"""
from pathlib import Path
import argparse,gc,json,struct,traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_R0,UC_ARM_REG_LR
from probe_raw_candidates import Rig,ROOT,CAL,REGS,sha
from prepare_cal33_static_lab import START,END,TARGET,PARENT,PARENT_SHA,ZERO_OR

ROUND=ROOT/'analysis/raw-spatial-controls-2026-11-10'
CTX,STATE,PKT,ID35=0xc18fa844,0xc18fa954,0xc29a34c0,0x56000000
def read(p):return json.loads(p.read_text(encoding='utf8'))
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    for n in (Path(__file__).name,'probe_raw_candidates.py','prepare_cal33_static_lab.py'):(a.output/n).write_bytes((ROOT/'tools/fw'/n).read_bytes())
    man=read(ROUND/'static-cal33-lab/manifest.json')
    cal=(ROOT/'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/CAL38.bin').read_bytes()
    fixed=(ROOT/'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/ID35.bin').read_bytes()
    assert sha(cal)=='914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372'
    assert sha(fixed)=='d52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf'
    snaps=read(ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json')['final']
    ev=read(ROOT/'analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json')
    context=bytes.fromhex(next(e for e in ev if e['event']=='static_front_builder')['memory']['context']['bytes'])
    variants=[('modified4',ROOT/PARENT,PARENT_SHA),('lab',ROUND/'static-cal33-lab'/man['module'],man['sha256'])]
    configs=[dict(mode=1,temp=t,submode=s,category=c,dc=d) for t in (0,1) for s in (0,2) for c in (0,1) for d in (0,1)]
    configs += [dict(mode=m,temp=1,submode=0,category=c,dc=0) for m in range(13) if m!=1 for c in (0,1)]
    report=dict(ok=False,scope=__doc__,cal_sha256=sha(cal),id35_sha256=sha(fixed),context_sha256=sha(context),
        lab_sha256=man['sha256'],rows=[],comparisons=[],zero_return_checks=[],restore_checks=[],error_checks=[],hardware_pixels_verified=False)
    base_rows={};rig=None
    try:
        for variant,path,digest in variants:
            blob=path.read_bytes();assert sha(blob)==digest
            rig=Rig(blob,snaps);u,p,g=rig.uc,rig.put,rig.get
            for addr,size in ((CAL+0x100000,0x68000),(ID35,0x100000),(0x20061000,0x1000)):
                u.mem_map(addr,size);rig.regions+=((addr,size),)
            writes=[];zero_returns=[];zero_entries=set(ZERO_OR.values());return_addresses=set()
            def on_write(uc,kind,addr,size,value,_):writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
            def on_code(uc,pc,size,_):
                if pc in zero_entries:return_addresses.add(uc.reg_read(UC_ARM_REG_LR)&~1)
                if pc in return_addresses:zero_returns.append(dict(pc=hex(pc),r0=uc.reg_read(UC_ARM_REG_R0)))
            for lo,hi in ((0x20061000,0x20061fff),(0x20068000,0x20069fff)):
                u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=lo,end=hi)
            hcode=u.hook_add(un.UC_HOOK_CODE,on_code)
            def setup(cfg):
                rig.reset(dict(scalar=1008,bank=0,cached=0));u.mem_write(CTX,context)
                u.mem_write(CAL,cal);u.mem_write(ID35,fixed);p(STATE+0x18,ID35)
                p(CTX,cfg['mode'],'B');p(CTX+0x84,cfg['temp']);p(CTX+0x21,cfg['submode'],'B')
                p(CTX+4,192,'h');p(CTX+8,1536 if cfg['category'] else 1535,'i');p(CTX+0xdc,cfg['dc'])
                writes.clear();zero_returns.clear();return_addresses.clear()
            for i,cfg in enumerate(configs):
                report['current_case']=dict(variant=variant,index=i,configuration=cfg);setup(cfg)
                # Same separated ID35 setup on both exact modules.
                rig.call(0x1011c750,[0,CTX],until=0x100cd752)
                rig.call(0x1011c3f4,[CTX]);early=list(writes);writes.clear()
                build=rig.call(START,until=0x1011d548)
                assert len(zero_returns)==3 and all(r['r0']==0 for r in zero_returns),zero_returns
                cache=bytes(u.mem_read(0xc29a3230,0x1000));ctx=bytes(u.mem_read(CTX,0xe4))
                packet=bytes(u.mem_read(PKT,0x60))
                rig.call(0x100bccd0,[PKT]);actual=list(writes)
                assert bytes(u.mem_read(CAL,len(cal)))==cal and bytes(u.mem_read(ID35,len(fixed)))==fixed
                row=dict(variant=variant,configuration=cfg,cache_hex=cache.hex(),context_hex=ctx.hex(),packet_hex=packet.hex(),
                    early_writes=early,writes=actual,return_contracts=list(zero_returns),
                    cached_control=g(TARGET,'B'),build_error_accumulator=build['registers']['r4'],
                    descriptor=[hex(g(0x20061264)),hex(g(0x20061268))],id35_gate=g(0x2006103c))
                report['rows'].append(row)
                if variant=='modified4':base_rows[i]=row
                else:
                    ref=base_rows[i];assert early==ref['early_writes'] and packet.hex()==ref['packet_hex'] and ctx.hex()==ref['context_hex']
                    assert row['build_error_accumulator']==ref['build_error_accumulator']
                    assert row['descriptor']==ref['descriptor'] and row['id35_gate']==ref['id35_gate']
                    diffs=[(x,y) for x,y in zip(ref['writes'],actual) if x!=y]
                    assert len(ref['writes'])==len(actual)==507
                    assert len(diffs)==1 and diffs[0][0]['address']==diffs[0][1]['address']=='0x20068700'
                    assert diffs[0][0]['value']==1 and diffs[0][1]['value']==0
                    changes=[k for k,(x,y) in enumerate(zip(bytes.fromhex(ref['cache_hex']),cache)) if x!=y]
                    assert changes==[TARGET-0xc29a3230],changes
                    report['comparisons'].append(dict(configuration=cfg,one_cache_byte_only=True,one_register_only=True,
                        id35_and_packet_context_unchanged=True,write_count=507,changed_register='0x20068700'))
                report['zero_return_checks'].append(dict(variant=variant,configuration=cfg,returns=list(zero_returns)))
            # Shared non-target calls run after a LAB static build, restore original CAL byte.
            sites=read(ROOT/'analysis/raw-spatial-identity-2026-11-09/table33-call-scope.json')['branches']
            sites=[int(r['pc'],16) for r in sites if r['operands']=='#0x1011e2ce' and r['pc']!='0x1017d7f0']
            for pc in sites:
                cfg=dict(mode=1,temp=1,submode=0,category=1,dc=0);setup(cfg)
                rig.call(START,until=0x1011d548);before=g(TARGET,'B')
                p(CTX+0x84,0);writes.clear();zero_returns.clear();return_addresses.clear()
                rig.call(pc,until=pc+4,regs={0:CTX});rig.call(0x100bccd0,[PKT])
                assert g(TARGET,'B')==1 and g(0x20068700)==1
                report['restore_checks'].append(dict(variant=variant,non_target_call=hex(pc),before=before,restored=1))
            # Keep all error-return aggregation except the three proven constant zeros.
            u.hook_del(hcode)
            call_targets=[int(x.removeprefix('#'),16) for x in man['existing_calls']]
            variable=[pc for pc in call_targets if pc not in zero_entries and pc not in (0x1011d540,0x1011d548)]
            errors={};seen=[]
            def stub(uc,pc,size,_):
                seen.append(dict(entry=hex(pc),r0=hex(uc.reg_read(UC_ARM_REG_R0))))
                uc.reg_write(UC_ARM_REG_R0,errors.get(pc,0));uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            for pc in call_targets:
                if pc not in zero_entries:u.hook_add(un.UC_HOOK_CODE,stub,begin=pc,end=pc)
            error_sets=[{}]+[{pc:1<<i} for i,pc in enumerate(variable)]+[{pc:0x80000001 for pc in variable}]
            for err in error_sets:
                setup(dict(mode=1,temp=1,submode=0,category=1,dc=0));errors.clear();errors.update(err);seen.clear()
                call=rig.call(START);expected=0
                for value in err.values():expected|=value
                assert int(call['registers']['r0'],16)==expected
                assert [r['entry'] for r in seen]==[hex(pc) for pc in call_targets if pc not in zero_entries]
                assert seen[-1]==dict(entry='0x1011d548',r0='0x1')
                report['error_checks'].append(dict(variant=variant,injected_returns={hex(k):hex(v) for k,v in err.items()},
                    result=call['registers']['r0'],order_and_dispatch_preserved=True))
            assert sha(path.read_bytes())==digest
            del u,rig;rig=None;gc.collect()
        report['ok']=True;report.pop('current_case',None)
    except Exception:
        report['error']=traceback.format_exc();report['last_call']=getattr(rig,'last_call',None);raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],rows=len(report['rows']),comparisons=len(report['comparisons']),
            restore_checks=len(report['restore_checks']),error_checks=len(report['error_checks']))))
if __name__=='__main__':main()

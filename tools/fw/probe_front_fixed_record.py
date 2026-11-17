"""Trace a fixed body-calibration record through native selection and front MMIO.

Every calibration value is a labelled artificial fixture. Real body calibration
has not been dumped. No pixel algorithm or camera completion is implemented.
"""
from pathlib import Path
import argparse, json, struct, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC
from probe_raw_candidates import Rig,ROOT,BASE,RAM,CAL,sha

CONTEXT=RAM+0x33000
FRONT_PACKET=0xc29a34c0
DATA=0xc29a3754


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for n in (Path(__file__).name,'probe_raw_candidates.py'):
        (a.output/n).write_bytes((ROOT/'tools/fw'/n).read_bytes())
    source=ROOT/'firmware/decoded/eg1620_038000.bi';blob=source.read_bytes()
    assert sha(blob)=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    rig=Rig(blob,snapshots);u,p,g=rig.uc,rig.put,rig.get
    reads,writes=[],[]
    def on_read(uc,kind,address,size,value,data):
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(address),size=size))
    def on_write(uc,kind,address,size,value,data):
        writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(address),size=size,value=value))
    u.hook_add(un.UC_HOOK_MEM_READ,on_read,begin=CAL,end=CAL+0xfffff)
    u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=0x20068000,end=0x20069fff)
    group_bases=struct.unpack_from('<6I',blob,0x1061a624-BASE)
    # Independent decode of the selector's 12-byte TBB; branch bodies are
    # direct constant assignments, recorded in disassembly command 05.
    targets=[0x1011e5a8+2*b for b in blob[0x1011e5a8-BASE:0x1011e5b4-BASE]]
    assign={0x1011e5ca:0,0x1011e5b4:1,0x1011e5b8:2,0x1011e5bc:3,
            0x1011e5c0:4,0x1011e5c4:5,0x1011e5c8:6}
    mode_group=[assign[t] for t in targets]
    report=dict(ok=False,scope=__doc__,source_sha256=sha(blob),mode_group=mode_group,
                group_bases=[hex(x) for x in group_bases],cases=[])
    configs=[dict(mode=m,temporary=t,den=192,num=385) for m in range(13) for t in (0,1)]
    configs += [dict(mode=1,temporary=0,den=d,num=n) for d,n in
                ((192,192),(192,384),(192,385),(192,1152),(192,1153),(-1,0))]
    configs += [dict(mode=1,temporary=0,den=192,num=385,mutation=True)]
    baseline=None
    try:
        for cfg in configs:
            report['current_case']=cfg
            rig.reset(dict(scalar=1008,bank=0,cached=0))
            u.mem_write(FRONT_PACKET,bytes(0x100));u.mem_write(DATA,bytes(0x114))
            # These two groups are owned by 1011e616, not by 10122c20.
            for j in range(6):
                u.mem_write(DATA+4+j*40,struct.pack('<10I',*[900+j*10+i for i in range(10)]))
                p(DATA+0xf4+j,30+j,'B');p(DATA+0xfa+j,40+j,'B')
            before=bytes(u.mem_read(DATA,0x114))
            for group in range(7):
                for category in range(4):
                    ptr=CAL+0x49a70+group*816+category*204
                    words=[1000+group*200+category*51+i for i in range(51)]
                    u.mem_write(ptr,struct.pack('<51I',*words))
            p(CONTEXT,cfg['mode'],'B');p(CONTEXT+0x84,cfg['temporary'])
            p(CONTEXT+0x14,cfg['den'],'h');p(CONTEXT+0x18,cfg['num'],'i')
            group=0 if cfg['mode']==2 or cfg['temporary'] or cfg['mode']>=12 else mode_group[cfg['mode']]
            category=3 if cfg['mode']==2 or cfg['den']==-1 else (0 if cfg['num']<=2*cfg['den'] else 1 if cfg['num']<=6*cfg['den'] else 2)
            selected=CAL+0x49a70+group*816+category*204
            if cfg.get('mutation'): p(selected+8,g(selected+8)+77)
            reads.clear();writes.clear()
            calls=[rig.call(0x1011e58c,[CONTEXT])]
            assert min(int(r['address'],16) for r in reads)==selected
            assert max(int(r['address'],16)+r['size'] for r in reads)==selected+204
            assert g(FRONT_PACKET+0x34)==DATA
            after=bytes(u.mem_read(DATA,0x114))
            for j in (0,3): assert after[4+j*40:44+j*40]==before[4+j*40:44+j*40]
            for k,j in enumerate((1,2,4,5)):
                assert after[4+j*40:44+j*40]==bytes(u.mem_read(selected+8+k*40,40))
            selected_reads=list(reads)
            calls.append(rig.call(0x100bccd0,[FRONT_PACKET]))
            assert len(writes)==48,len(writes)
            registers={w['address']:w['value'] for w in writes}
            assert registers['0x20068718']==g(DATA)
            for j,base in enumerate(group_bases):
                vals=struct.unpack('<10I',after[4+j*40:44+j*40])
                expected=[(vals[k]&65535)|((vals[k+1]&65535)<<16) for k in range(0,8,2)]
                expected += [vals[8],(vals[9]&0x1ffff)|(after[0xf4+j]<<24),after[0xfa+j]]
                assert [registers[hex(base+4*k)] for k in range(7)]==expected
            row=dict(fixture=cfg,selected_group=group,selected_category=category,selected_record=hex(selected),
                     calibration=rig.mem(selected,204),before_hex=before.hex(),after_hex=after.hex(),
                     selected_reads=selected_reads,calls=calls,register_writes=list(writes),registers=registers)
            if cfg==dict(mode=1,temporary=0,den=192,num=385):baseline=registers
            if cfg.get('mutation'):
                assert baseline is not None
                row['changed_registers']={k:[baseline[k],v] for k,v in registers.items() if baseline[k]!=v}
                assert set(row['changed_registers'])=={hex(group_bases[1])}
            report['cases'].append(row)
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();report['failed_call']=getattr(rig,'last_call',None)
        raise
    finally:
        report['original_unchanged']=sha(source.read_bytes())==report['source_sha256']
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']))))


if __name__=='__main__':main()

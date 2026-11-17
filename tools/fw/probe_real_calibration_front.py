"""Run native frontend instructions on read-only copies of real camera CAL/ID35.

Contexts come from the earlier emulator trace, NOT a hardware RAM snapshot.
MMIO is private RAM. Single-field counterfactuals identify upload destinations,
not hardware disable semantics. No camera operation or flash image is produced.
"""
from pathlib import Path
import argparse,json,struct,traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_PC
from probe_raw_candidates import Rig,ROOT,CAL,sha

ROUND=ROOT/'analysis/raw-calibration-access-2026-11-10'
CTX,STATE,PKT,ID35=0xc18fa844,0xc18fa954,0xc29a34c0,0x56000000
BANKS=(0x20068f00,0x20068f44,0x20068fcc,0x20068f88)
FW={
 'stock':('firmware/decoded/eg1620_038000.bi','1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'),
 'modified4':('outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN','bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b')}
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in (Path(__file__).name,'probe_raw_candidates.py'):(a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    cal=(ROUND/'camera-calibration-backup-v3/CAL38.bin').read_bytes()
    fixed=(ROUND/'camera-calibration-backup-v3/ID35.bin').read_bytes()
    assert sha(cal)=='914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372'
    assert sha(fixed)=='d52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf'
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    ev=json.loads((ROOT/'analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json').read_text())
    context=bytes.fromhex(next(e for e in ev if e['event']=='static_front_builder')['memory']['context']['bytes'])
    report=dict(ok=False,scope=__doc__,cal_sha256=sha(cal),id35_sha256=sha(fixed),context_sha256=sha(context),
        rows=[],counterfactuals=[],firmware_comparisons=[],hardware_pixels_verified=False)
    try:
        for fwname,(path,digest) in FW.items():
            blob=(ROOT/path).read_bytes();assert sha(blob)==digest
            rig=Rig(blob,snapshots);u,p,g=rig.uc,rig.put,rig.get
            for address,size in ((CAL+0x100000,0x68000),(ID35,0x100000),(0x20061000,0x1000)):
                u.mem_map(address,size);rig.regions+=((address,size),)
            selected=[];writes=[]
            def on_select(uc,pc,size,_):selected.append(uc.reg_read(UC_ARM_REG_R0))
            def on_write(uc,kind,addr,size,value,_):
                writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
            u.hook_add(un.UC_HOOK_CODE,on_select,begin=0x1011e23e,end=0x1011e23e)
            for lo,hi in ((0x20061000,0x20061fff),(0x20068000,0x20069fff)):
                u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=lo,end=hi)
            configs=[dict(label='observed',temporary=1,num=None),dict(label='observed-normal',temporary=0,num=None)]
            configs += [dict(label=f't{t}-category{cat}',temporary=t,num=1536 if cat else 1535) for t in (0,1) for cat in (0,1)]
            for cfg in configs:
                baseline=None
                # Mutate each one-byte control independently in a private CAL copy.
                for mutation in ('none','header18_zero','header1a_zero'):
                    if fwname=='stock' and mutation!='none':continue
                    report['current_case']=dict(firmware=fwname,**cfg,mutation=mutation)
                    rig.reset(dict(scalar=1008,bank=0,cached=0));u.mem_write(CTX,context)
                    p(CTX+0x84,cfg['temporary']);p(STATE+0x18,ID35)
                    if cfg['num'] is not None:p(CTX+4,192,'h');p(CTX+8,cfg['num'],'i')
                    experiment=bytearray(cal)
                    if mutation!='none':
                        off=baseline['record_offset']+(0x18 if mutation=='header18_zero' else 0x1a)
                        assert experiment[off]==1;experiment[off]=0
                    u.mem_write(CAL,bytes(experiment));u.mem_write(ID35,fixed)
                    p(0x20061264,0x12345670);p(0x20061268,0x100)
                    selected.clear();writes.clear()
                    index=int(rig.call(0x1011c64e,[CTX])['registers']['r0'],16)
                    call0=rig.call(0x1011c750,[0,CTX],until=0x100cd752)
                    call1=rig.call(0x1011c3f4,[CTX])
                    descriptor=[g(0x20061264),g(0x20061268)]
                    gate=cal[0x540+index*80]
                    assert g(0x2006103c)==gate
                    assert descriptor==([ID35+0xacdf0,0x5f60] if gate else [0x12345670,0x100])
                    if cfg['temporary']:assert gate==1
                    before_builder=list(writes);writes.clear()
                    build=rig.call(0x1017d7b6,until=0x1011d548)
                    assert len(selected)==1
                    upload=rig.call(0x100bccd0,[PKT]);regs={w['address']:w['value'] for w in writes}
                    offset=selected[0]-CAL;assert offset in (0x47180,0x472ac)
                    table=bytes(u.mem_read(selected[0]+36,264));vals=struct.unpack('<132H',table)
                    for c,bank in enumerate(BANKS):
                        expected=[vals[i*4+c]+(vals[(i+1)*4+c]<<16) for i in range(0,32,2)]+[vals[128+c]]
                        assert [regs[hex(bank+4*k)] for k in range(17)]==expected
                    assert bytes(u.mem_read(CAL,len(cal)))==experiment
                    assert bytes(u.mem_read(ID35,len(fixed)))==fixed
                    row=dict(firmware=fwname,firmware_sha256=digest,configuration=cfg,mutation=mutation,
                        record_index=index,record_offset=offset,record_offset_hex=hex(offset),
                        id35_descriptor=[hex(x) for x in descriptor],id35_data_sha256=sha(fixed[0xacdf0:0xb2d50]),
                        frontend_gate=g(0x2006103c),early_writes=before_builder,writes=list(writes),
                        registers=regs,table_sha256=sha(table),calls=[call0,call1,build,upload])
                    report['rows'].append(row)
                    if mutation=='none':baseline=row
                    else:
                        changed={k:[baseline['registers'][k],v] for k,v in regs.items() if baseline['registers'][k]!=v}
                        target='0x20068700' if mutation=='header18_zero' else '0x20068704'
                        assert changed=={target:[1,0]},changed
                        assert row['early_writes']==baseline['early_writes'] and row['table_sha256']==baseline['table_sha256']
                        report['counterfactuals'].append(dict(configuration=cfg,mutation=mutation,changed=changed,
                            id35_transfer_preserved=True,table_data_preserved=True,hardware_disable_verified=False))
            del rig,u
        for cfg in configs:
            rows=[r for r in report['rows'] if r['configuration']==cfg and r['mutation']=='none']
            assert len(rows)==2 and rows[0]['writes']==rows[1]['writes'] and rows[0]['early_writes']==rows[1]['early_writes']
            report['firmware_comparisons'].append(dict(configuration=cfg,stock_modified4_frontend_equal=True))
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();report['last_call']=getattr(rig,'last_call',None);raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],rows=len(report['rows']),counterfactuals=len(report['counterfactuals']),comparisons=len(report['firmware_comparisons']))))
if __name__=='__main__':main()

"""Original-code selector/packing tests for frontend 33x4 and 2x48 storage.

Artificial nonzero CAL and stale caches distinguish updating from disabling.
No pixel operator is implemented; table meanings and neutral values are unknown.
"""
from pathlib import Path
import argparse,json,struct,traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_R0,UC_ARM_REG_R1
from probe_raw_candidates import Rig,ROOT,BASE,RAM,CAL,sha

CTX=0xc18fa844;PACKET=0xc29a34c0;T48=0xc29a3664;T33=0xc29a3be0
BANKS=(0x20068f00,0x20068f44,0x20068fcc,0x20068f88)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for n in (Path(__file__).name,'probe_raw_candidates.py'):
        (a.output/n).write_bytes((ROOT/'tools/fw'/n).read_bytes())
    source=ROOT/'firmware/decoded/eg1620_038000.bi';blob=source.read_bytes()
    assert sha(blob)=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    observed=ROOT/'analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json'
    events=json.loads(observed.read_text())
    context=bytes.fromhex(next(e for e in events if e['event']=='static_front_builder')['memory']['context']['bytes'])
    rig=Rig(blob,snapshots);u,p,g=rig.uc,rig.put,rig.get
    writes=[];selected=[]
    def on_write(uc,kind,addr,size,value,_):
        writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
    def on_record(uc,pc,size,_):
        addr=uc.reg_read(UC_ARM_REG_R0)
        selected.append(dict(pc=hex(pc),address=hex(addr),r1=hex(uc.reg_read(UC_ARM_REG_R1))))
    u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=0x20068000,end=0x20069fff)
    for pc in (0x1011e20c,0x1011e23e):u.hook_add(un.UC_HOOK_CODE,on_record,begin=pc,end=pc)
    # Direct branch-body constants, indexed by native TBB bytes. The mode0/1
    # branch depends on ctx+21==2; temporary state overrides mode selection.
    targets=[0x1011e2ea+2*b for b in blob[0x1011e2ea-BASE:0x1011e2f7-BASE]]
    mode_groups={0x1011e2f8:0,0x1011e326:0,0x1011e304:2,0x1011e308:3,0x1011e30c:4,
        0x1011e310:5,0x1011e314:6,0x1011e318:7,0x1011e31c:8,
        0x1011e320:9,0x1011e324:10}
    report=dict(ok=False,scope=__doc__,original_sha256=sha(blob),observed_sha256=sha(observed.read_bytes()),
        modes=[hex(x) for x in targets],cases=[],mutations=[],null_packet=None,hardware_pixels_verified=False)
    cfgs=[dict(mode=m,temp=t,num=n,submode=0,dc=1) for m in range(14) for t in (0,1) for n in (1535,1536)]
    cfgs += [dict(mode=m,temp=0,num=1536,submode=2,dc=d) for m in (0,1) for d in (0,1)]
    def setup(cfg):
        rig.reset(dict(scalar=1008,bank=0,cached=0));u.mem_write(CTX,context)
        p(CTX,cfg['mode'],'B');p(CTX+0x21,cfg['submode'],'B');p(CTX+0x84,cfg['temp'])
        p(CTX+4,192,'h');p(CTX+8,cfg['num'],'i');p(CTX+0xdc,cfg['dc'])
        u.mem_write(PACKET,bytes(0x60));u.mem_write(T48,bytes.fromhex('5aa5')*100)
        for group in range(11):
            for cat in (0,1):
                k=group*2+cat
                r48=struct.pack('<4H4BH2B',101+k,201+k,301+k,401+k,1,0x33,2,0x44,501+k,0x55,0x66)
                u.mem_write(CAL+0x47010+group*32+cat*16,r48)
                r33=bytearray(struct.pack('<150H',*[1000+k*200+i for i in range(150)]))
                for off,v in ((0x18,1),(0x1a,2),(0x1c,3),(0x1e,4)):r33[off]=v
                u.mem_write(CAL+0x47180+group*600+cat*300,bytes(r33))
        selected.clear();writes.clear()
    def run(cfg):
        call48=rig.call(0x1011e150,[CTX]);after48=bytes(u.mem_read(T48,200))
        call33=rig.call(0x1011e2ce,[CTX]);after33=bytes(u.mem_read(T33,264))
        controls33=bytes(u.mem_read(0xc29a372c,40));packet=rig.mem(PACKET,0x60)
        upload=rig.call(0x100bccd0,[PACKET])
        return dict(config=cfg,selected=list(selected),table48_hex=after48.hex(),table33_hex=after33.hex(),
            controls33_hex=controls33.hex(),packet=packet,calls=[call48,call33,upload],writes=list(writes),
            registers={w['address']:w['value'] for w in writes})
    try:
        for cfg in cfgs:
            report['current_case']=cfg;setup(cfg);row=run(cfg);report['pending_case']=row
            m=cfg['mode'];group=0 if cfg['temp'] or m>=13 else mode_groups[targets[m]]
            if not cfg['temp'] and m in (0,1) and cfg['submode']==2:group=1
            cat=int(cfg['num']>=8*192)
            r48=CAL+0x47010+group*32+cat*16;r33=CAL+0x47180+group*600+cat*300
            assert [x['address'] for x in selected]==[hex(r48),hex(r33)],(cfg,selected,group)
            expected48=bytearray(bytes.fromhex('5aa5')*100)
            expected48[0:4]=u.mem_read(r48,4);expected48[0x60:0x64]=u.mem_read(r48+4,4)
            expected48[0xc0]=g(r48+8,'B');expected48[0xc1]=g(r48+10,'B')
            expected48[0xc4:0xc8]=struct.pack('<I',g(r48+12,'H'))
            assert bytes.fromhex(row['table48_hex'])==expected48
            assert bytes.fromhex(row['table33_hex'])==bytes(u.mem_read(r33+0x24,264))
            regs=row['registers'];assert len(writes)==131,len(writes)
            for j,base in enumerate((0x2006861c,0x2006867c)):
                assert [regs[hex(base+4*k)] for k in range(24)]==list(struct.unpack_from('<24I',expected48,j*96))
            assert regs['0x200686dc']==expected48[0xc0]+(expected48[0xc1]<<16)
            assert regs['0x200686e0']==g(r48+12,'H')
            vals=struct.unpack('<132H',bytes.fromhex(row['table33_hex']))
            for c,base in enumerate(BANKS):
                expected=[vals[i*4+c]+(vals[(i+1)*4+c]<<16) for i in range(0,32,2)]+[vals[128+c]]
                assert [regs[hex(base+4*k)] for k in range(17)]==expected
            assert regs['0x20068708']==1 # input+6, initial toggle0 XOR1 or explicit dc1
            row.update(group=group,category=cat,table48_stale_values_retained=92)
            report['cases'].append(row);report.pop('pending_case')
        cfg=dict(mode=1,temp=1,num=1536,submode=0,dc=1)
        setup(cfg);baseline=run(cfg);selected33=int(baseline['selected'][1]['address'],16)
        for index,channel in ((0,0),(7,2),(32,3)):
            setup(cfg);addr=selected33+0x24+index*8+channel*2;p(addr,g(addr,'H')+7,'H')
            changed=run(cfg);diff={k:[baseline['registers'][k],v] for k,v in changed['registers'].items() if baseline['registers'][k]!=v}
            expected_addr=hex(BANKS[channel]+(index//2)*4)
            assert set(diff)=={expected_addr};assert diff[expected_addr][1]-diff[expected_addr][0]==7<<(16*(index%2))
            report['mutations'].append(dict(index=index,channel=channel,source_address=hex(addr),changed_registers=diff))
        # Repeated no-dc calls toggle the control; not an off/on request from dc.
        setup(dict(cfg,dc=0));toggles=[]
        for i in range(4):
            rig.call(0x1011e2ce,[CTX]);rig.call(0x100bccd0,[PACKET]);toggles.append(g(0x20068708))
        assert toggles==[1,0,1,0];report['dc0_control_sequence']=toggles
        before=rig.mem(0x20068000,0x2000);u.mem_write(PACKET,bytes(0x60));writes.clear()
        nullcall=rig.call(0x100bccd0,[PACKET]);after=rig.mem(0x20068000,0x2000)
        assert before==after and not writes
        report['null_packet']=dict(call=nullcall,registers_sha256=after['sha256'],retains_registers=True)
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();report['last_call']=getattr(rig,'last_call',None);report['last_blocks']=rig.blocks[-30:]
        raise
    finally:
        report['original_unchanged']=sha(source.read_bytes())==report['original_sha256']
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),mutations=len(report['mutations']))))

if __name__=='__main__':main()

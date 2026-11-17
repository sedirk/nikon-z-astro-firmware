"""Original calibration-class selector, owner propagation, and control registers.

Synthetic table contents expose each index and switch. This is native control
dataflow, not a physical bad-pixel algorithm or a completed exposure.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC
from probe_raw_candidates import Rig, ROOT, RAM, CAL, OWNER, FRAME, PROPS, CTX, A, DRIVER, MMIO, MAINREQ, MAINOUT

REQUEST, INFO=RAM+0x50000,RAM+0x51000
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'source.py').write_bytes(Path(__file__).read_bytes())
    (a.output/'rig-source.py').write_bytes((ROOT/'tools/fw/probe_raw_candidates.py').read_bytes())
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();assert hashlib.sha256(blob).hexdigest()==SHA
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    rig=Rig(blob,snapshots);u,put,get=rig.uc,rig.put,rig.get
    rig.reset(dict(scalar=1008,bank=0,cached=False))
    reads=[]
    def on_cal(uc,access,addr,size,value,data):
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),offset=hex(addr-CAL),size=size,
            value=bytes(uc.mem_read(addr,size)).hex()))
    u.hook_add(un.UC_HOOK_MEM_READ,on_cal,begin=CAL+0xcdb10,end=CAL+0xcde0f)
    table=bytearray(768)
    for temp in (0,1):
        for mode in range(12):
            for primary in range(4):
                for idx in range(7):table[temp*384+mode*32+primary*7+idx]=(temp+mode+primary+idx)%3
    u.mem_write(CAL+0xcdb10,bytes(table));u.mem_write(CAL+0xbe01c,struct.pack('>h',200))
    report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,
        calibration='Explicit synthetic table at +cdb10 and signed big-endian threshold +be01c. Physical meaning of owner+ec and temperature units not inferred.',
        policy_cases=[],producer_cases=[],control_cases=[])
    try:
        for forced_mode in (False,True):
            mode=2 if forced_mode else 0
            for temp in (199,200):
                for primary_n,bin_id in ((5*192,0),(2*192,1),(0,2),(-192,3)):
                    for tv_n in (-446,10*192,11*192,12*192-1,12*192,13*192,17*192,18*192):
                        u.mem_write(REQUEST,bytes(32));put(REQUEST+0x1c,int(forced_mode))
                        u.mem_write(REQUEST+8,struct.pack('<IiIi',192,primary_n,192,tv_n))
                        put(REQUEST+0x18,temp,'h');reads.clear()
                        call=rig.call(0x1011eef8,[REQUEST])
                        idx=max(11,min(17,int((tv_n+191)/192)))-11
                        off=0xcdb10+(temp>=200)*384+mode*32+bin_id*7+idx
                        value=table[off-0xcdb10]
                        assert int(call['registers']['r0'],16)==value
                        assert reads==[dict(pc='0x1011eff2',offset=hex(off),size=1,value=f'{value:02x}')]
                        report['policy_cases'].append(dict(mode=mode,temp_input=temp,primary_rational=[192,primary_n],
                            tv_rational=[192,tv_n],primary_bin=bin_id,tv_index=idx,cal_read=list(reads),result=value,call=call))
        # Invalid byte value follows the native return-zero branch.
        off=int(reads[0]['offset'],16);saved=get(CAL+off,'B');put(CAL+off,7,'B')
        call=rig.call(0x1011eef8,[REQUEST]);assert int(call['registers']['r0'],16)==0
        report['invalid_class_call']=call;put(CAL+off,saved,'B')
        # Actual still producer segment writes owner+1aec. Its real wrappers and
        # config conversions execute; there are no host-injected return values.
        for numerator in (-446,13*192):
            put(OWNER+0x90,0,'B');put(FRAME+0x3a4,OWNER)
            u.mem_write(OWNER+0xec,struct.pack('<Ii',192,5*192))
            u.mem_write(OWNER+0xcc,struct.pack('<Ii',192,numerator))
            u.mem_write(INFO,bytes(0x260));put(INFO+0x24,200,'H')
            u.mem_write(0xc18b7ec0,bytes(8));reads.clear()
            calls=[rig.call(0x10146efe,until=0x10146f28,regs={4:FRAME,7:INFO})]
            provenance=list(reads);assert len(provenance)==1
            expected=int(provenance[0]['value'],16);assert get(OWNER+0x1aec,'B')==expected
            put(OWNER+0x1aed,0,'B');put(OWNER+0x2810,0,'B');put(OWNER+0x2811,0,'B')
            calls.append(rig.call(0x100c24f2,[MAINREQ,MAINOUT]))
            prop=get(MAINOUT);assert get(prop+0x4c,'B')==expected
            generated=rig.mem(prop,0xa0);u.mem_write(PROPS,bytes.fromhex(generated['bytes']))
            put(CTX,PROPS);put(CTX+0xd0,A)
            calls.append(rig.call(0x10196a3c,[CTX]))
            put(DRIVER+4,0,'B');calls.append(rig.call(0x100d5b9c,[DRIVER,A+0x62]))
            assert get(MMIO+0x584)==get(A+0x17a,'B')
            report['producer_cases'].append(dict(tv_rational=[192,numerator],cal_read=provenance,
                owner1aec=get(OWNER+0x1aec,'B'),properties=generated,
                controls={hex(o):get(A+o,'B') for o in (0xcc,0xcd,0x17a)},
                registers={hex(o):hex(get(MMIO+o)) for o in (0x580,0x584,0x594)},calls=calls))
        # Separate control matrix isolates class, table flag, cache flag, and the
        # three-valued override. These are explicit parameter fixtures.
        cases=[dict(cls=c,static=s,cache=k,override=0) for c in (0,1,2) for s in (0,1) for k in (0,1)]
        cases += [dict(cls=0,static=0,cache=0,override=1),dict(cls=2,static=0,cache=0,override=2)]
        for bank in (0,1):
            for cfg in cases:
                u.mem_write(A,bytes(0x500));u.mem_write(PROPS,bytes(0xa0));u.mem_write(CTX,bytes(0x100))
                put(CTX,PROPS);put(CTX+0xd0,A)
                for off,v in ((0x4c,cfg['cls']),(0x4d,cfg['static']),(0x4e,cfg['override']),(0x96,cfg['cache'])):put(PROPS+off,v,'B')
                calls=[rig.call(0x10196a3c,[CTX])]
                dynamic=(cfg['override']==1) or (cfg['override']==0 and cfg['cls']!=0)
                expected=0 if cfg['cache'] else int(dynamic)+6*cfg['static']
                assert get(A+0x17a,'B')==expected
                assert get(A+0xcc,'B')==get(A+0xcd,'B')==int(cfg['cls']==2)
                put(DRIVER+4,bank,'B');calls.append(rig.call(0x100d5b9c,[DRIVER,A+0x62]))
                mmio=MMIO+bank*0x40000
                assert get(mmio+0x584)==expected
                # +cc is shifted by two; +cd occupies bit one; +ce is bit zero.
                assert get(mmio+0x594)==6*int(cfg['cls']==2)
                report['control_cases'].append(dict(**cfg,bank=bank,
                    controls={hex(o):get(A+o,'B') for o in (0xcc,0xcd,0x17a)},
                    registers={hex(o):hex(get(mmio+o)) for o in (0x580,0x584,0x594)},calls=calls))
        assert hashlib.sha256((ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()).hexdigest()==SHA
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();report['failed_call']=getattr(rig,'last_call',None)
        report['last_blocks']=rig.blocks[-80:];report['pc']=hex(u.reg_read(UC_ARM_REG_PC))
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],policy_cases=len(report['policy_cases']),producer_cases=len(report['producer_cases']),control_cases=len(report['control_cases']))))


if __name__=='__main__':main()

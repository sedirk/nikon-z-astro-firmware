"""Native PTP dispatch and F029 read validation; synthetic calibration bytes.

No USB commands or firmware writes. ROM lookup/validation/read handlers execute
unchanged. Actual resource getter executes against original scatter descriptors;
only resource bases are redirected to private synthetic data for bounded tests.
"""
from pathlib import Path
import argparse,json,struct,traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_R0
from probe_raw_candidates import ROOT,Rig,REGS,RAM,BASE,sha

OUT=ROOT/'analysis/raw-calibration-access-2026-11-10'
PACKET=RAM+0x59000
EXPECTED='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();assert sha(b)==EXPECTED
    snaps=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    r=Rig(b,snaps);u=r.uc;r.reset(dict(scalar=1008,bank=0,cached=0))
    report=dict(ok=False,scope=__doc__,firmware_sha256=EXPECTED,groups=[],dispatch=[],reader_cases=[],read_is_synthetic=True,
        hardware_or_usb_access=False)
    try:
        for group in range(9):
            call=r.call(0x102e9cc4,[group]);base=u.reg_read(REGS[0]);rows=[]
            if base:
                for i in range(1000):
                    w=struct.unpack('<7I',u.mem_read(base+i*28,28))
                    if not w[0]:break
                    assert 0<w[0]<=65535 and w[1] in (0,1)
                    rows.append(dict(address=hex(base+i*28),opcode=hex(w[0]),data_in_flag=w[1],
                        context=hex(w[2]),data_out_buffer_callback=hex(w[3]),validator=hex(w[4]),handler=hex(w[5]),initializer=hex(w[6])))
                else:raise AssertionError('Unterminated table')
            report['groups'].append(dict(group=group,base=hex(base),rows=rows,blocks=call['blocks']))
        subs=[]
        for i in range(1000):
            p=0x1154c3f0+i*28;w=struct.unpack('<7I',u.mem_read(p,28))
            if not w[0]:break
            subs.append(dict(address=hex(p),subcommand=hex(w[0]),words=[hex(x) for x in w]))
        report['extended_subcommands']=subs
        observed=json.loads((ROOT/'analysis/raw-front-completion-2026-11-10/camera-readonly-inventory-v2.json').read_text())['vendor_opcodes']
        for op in [int(x,16) for x in observed]+[0x94fd,0x94fe,0x94ff,0xfc01,0xfe34,0xf029]:
            result=r.call(0x102d9e78,[op]);ptr=u.reg_read(REGS[0])
            assert not ptr or r.get(ptr,'H')==op
            report['dispatch'].append(dict(opcode=hex(op),record=hex(ptr),blocks=result['blocks']))
        assert all(int(x['record'],16) for x in report['dispatch'][:65])
        # Capture two transport sinks; never replace the F029 validator, table
        # selection, resource descriptor getter or its source-pointer math.
        events=[]
        def transport(uc,pc,size,_):
            args=[uc.reg_read(x) for x in REGS[:4]]
            if pc==0x10402230:
                assert args[0]==PACKET and 0<args[2]<=0x4000
                data=bytes(uc.mem_read(args[1],args[2]))
                events.append(dict(kind='data',source=hex(args[1]),length=args[2],bytes=data.hex(),sha256=sha(data),timeout=args[3]))
            else:
                assert args[0]==PACKET and args[2]==5
                events.append(dict(kind='response',ptp_code=hex(args[1]),params=list(struct.unpack('<5I',uc.mem_read(args[3],20))),
                    transport_phase=r.get(uc.reg_read(UC_ARM_REG_SP))))
            uc.reg_write(UC_ARM_REG_R0,1);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        for pc in (0x10402230,0x104022be):u.hook_add(un.UC_HOOK_CODE,transport,begin=pc,end=pc)
        # TBB order in 0x1032e5ce/0x1032e65c: CAL38, ID35, ID34, ID37, ID0b, ID0c.
        ids=[0x38,0x35,0x34,0x37,0x0b,0x0c]
        resources=[]
        # Resource map records are initialized from original ROM. Redirect
        # +8 to a private byte array and +c to its known length; no MMIO/NVM.
        for index,ident in enumerate(ids):
            desc=0xc1880c78+ident*28;before=r.mem(desc,28)
            assert r.get(desc,'B')==ident
            source=0x56000000+index*0x10000;length=0x4000
            u.mem_map(source,0x10000)
            data=bytes(((i*37+ident*11) & 255) for i in range(length))
            u.mem_write(source,data);r.put(desc+8,source);r.put(desc+0xc,length)
            resources.append(dict(id=ident,descriptor=hex(desc),before=before,source=source,length=length,sha256=sha(data)))
        report['synthetic_resources']=resources
        # ID0b/ID0c getters depend on a storage-service runtime not initialized
        # by Rig. Keep that failed attempt in native-cal-reader-v2; scope this
        # run to the four supported synthetic descriptors and invalid selectors.
        report['untested_selectors']={'4':'ID0b storage runtime unmapped in prior run','5':'ID0c same storage runtime not initialized'}
        for select in (0,1,2,3,6,7):
            for offset,length in ((0,32),(0x123,257),(0x3fe0,32),(0x3fe1,32),(0,0)):
                events.clear();u.mem_write(PACKET,bytes(0x40))
                r.put(PACKET,32);r.put(PACKET+4,1,'H');r.put(PACKET+6,0x94ff,'H')
                r.put(PACKET+8,1);r.put(PACKET+0xc,0xf029)
                r.put(PACKET+0x10,offset);r.put(PACKET+0x14,length);r.put(PACKET+0x18,select)
                check=r.call(0x1032e5ce,[0,PACKET]);accepted=u.reg_read(REGS[0]);expected=select<6 and length>0 and offset+length<=0x4000
                assert accepted==int(expected),(select,offset,length,accepted)
                body=None
                if accepted:
                    body=r.call(0x1032e65c,[0,PACKET]);assert u.reg_read(REGS[0])==1
                    sent=[e for e in events if e['kind']=='data'];assert len(sent)==1
                    src=resources[select]['source']+offset
                    assert sent[0]['source']==hex(src) and sent[0]['length']==length
                    assert sent[0]['bytes']==bytes(u.mem_read(src,length)).hex()
                    assert events[-1]['params'][0]==0x2001
                else:
                    assert len(events)==1 and events[0]['kind']=='response' and events[0]['params'][0]==0x201d
                report['reader_cases'].append(dict(selector=select,offset=offset,length=length,accepted=bool(accepted),
                    validation_blocks=check['blocks'],handler_blocks=body['blocks'] if body else [],events=list(events)))
        for row in resources:assert sha(bytes(u.mem_read(row['source'],row['length'])))==row['sha256']
        report['gate_cases']=[]
        r.call(0x102ea6ee,[])
        assert r.get(0xc18e6f48+4)==0x102ea6e9
        for active,selector in ((0,0),(0,1),(1,0),(1,1)):
            events.clear();r.put(0xc18e6f50,active)
            u.mem_write(PACKET,bytes(0x40));r.put(PACKET,32)
            r.put(PACKET+4,1,'H');r.put(PACKET+6,0x94ff,'H')
            r.put(PACKET+8,1);r.put(PACKET+0xc,0xf029)
            r.put(PACKET+0x14,32);r.put(PACKET+0x18,selector)
            result=r.call(0x1032df20,[PACKET]);accepted=u.reg_read(REGS[0])
            assert accepted==active
            if not active:
                assert len(events)==1 and events[0]['ptp_code']=='0xa004'
                assert '0x1032e5ce' not in result['blocks']
            else:
                assert not events and '0x1032e5ce' in result['blocks']
            report['gate_cases'].append(dict(active_in_private_RAM=active,selector=selector,accepted=bool(accepted),
                blocks=result['blocks'],events=list(events)))
        report.update(ok=True,selector_to_resource={str(i):hex(x) for i,x in enumerate(ids)},
            native_resource_getter_executed=True,synthetic_source_bytes_preserved=True,
            host_reader_must_guard_overflow=True,
            limitations='Resource source/base and length are synthetic. Native unsigned offset+length can wrap; host must separately bound offsets/lengths. Service gate uses native callback and a private RAM flag; F001 service entry and physical transport are not exercised here.')
    except Exception:report['error']=traceback.format_exc()
    (a.output/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    for name in (Path(__file__).name,'probe_raw_candidates.py'):(a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    print(json.dumps(dict(ok=report['ok'],groups=len(report['groups']),dispatch=len(report['dispatch']),reader_cases=len(report['reader_cases']),error=report.get('error'))))
    return 0 if report['ok'] else 1

if __name__=='__main__':raise SystemExit(main())

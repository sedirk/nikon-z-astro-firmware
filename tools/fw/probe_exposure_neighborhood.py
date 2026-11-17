"""Execute the original exposure-table -> RAW configuration chain.

Private synthetic calibration makes provenance visible. Registers are plain
RAM; no image, ISP arithmetic, interrupt or sensor is simulated. A zero field
is a verified register value, not a hardware bypass claim.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC
from probe_raw_candidates import Rig, ROOT, BASE, RAM, OWNER, FRAME, A, PACKET, DRIVER, CAL, MMIO, REQ, OUTPUT

EXPECTED = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
REQUEST, ANSWER = RAM + 0x50000, RAM + 0x50100


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'source.py').write_bytes(Path(__file__).read_bytes())
    (a.output / 'rig-source.py').write_bytes((ROOT / 'tools/fw/probe_raw_candidates.py').read_bytes())
    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED
    snapshots = json.loads((ROOT / 'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    rig = Rig(blob, snapshots); u, put, get = rig.uc, rig.put, rig.get
    cal_reads = []
    def read_cal(uc, access, addr, size, value, data):
        cal_reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)), offset=hex(addr-CAL), size=size,
            value=bytes(uc.mem_read(addr, size)).hex()))
    u.hook_add(un.UC_HOOK_MEM_READ, read_cal, begin=CAL+0xcde30, end=CAL+0xcdf70)
    report = dict(ok=False, scope=__doc__, firmware_sha256=EXPECTED,
        calibration='Synthetic 0xcde30 + mode*80; resource-list flag=0; no real factory calibration supplied',
        policy_cases=[], builder_cases=[], source_unchanged=False)
    try:
        rig.reset(dict(scalar=1008, bank=0, cached=False))
        for mode in (0, 2, 3):
            off = CAL + 0xcde30 + mode * 80
            u.mem_write(off, struct.pack('<5H', 0, 2, 1, 301+mode, 401+mode))
            u.mem_write(off+10, struct.pack('<13H', *[501+mode*100+i for i in range(13)]))
            u.mem_write(off+36, struct.pack('<13H', *[601+mode*100+i for i in range(13)]))
            put(off+62, 701+mode, 'H')
        # First word is rational denominator (s16), second is signed numerator.
        # 1011c14a is executed for exact power-of-two exposure conversion.
        # Index truncates toward zero, clamps Tv to [4,16], then subtracts 4.
        numerators = [-1536, -446, 0, 3*192, 4*192-1, 4*192, 5*192-1, 5*192, 13*192, 16*192, 17*192]
        for mode in (0, 2, 3):
            for numerator in numerators:
                u.mem_write(REQUEST, bytes(24)); u.mem_write(ANSWER, bytes(20))
                put(REQUEST+8, int(mode==3), 'B'); put(REQUEST+20, int(mode==2))
                u.mem_write(REQUEST+12, struct.pack('<Ii', 192, numerator))
                index = max(4, min(16, int(numerator/192))) - 4
                cal_reads.clear()
                call = rig.call(0x1011f0b8, [REQUEST, ANSWER])
                expected = struct.pack('<I8H', 0, 2, 1, 301+mode, 401+mode,
                    501+mode*100+index, 601+mode*100+index, 701+mode, 0)
                assert bytes(u.mem_read(ANSWER,20)) == expected
                reads = list(cal_reads)
                assert {int(x['offset'],16) for x in reads} == {
                    0xcde30+mode*80+i for i in (0,2,4,6,8,10+index*2,36+index*2,62)}
                conversion = None
                if numerator % 192 == 0 and -8 <= numerator//192 <= 13:
                    conversion = rig.call(0x1011c14a, [REQUEST+12])
                    got = int(conversion['registers']['r0'],16) + (int(conversion['registers']['r1'],16)<<32)
                    power = numerator//192
                    ns = 10**9//(2**power) if power >= 0 else 10**9*(2**(-power))
                    assert got == ns, (got,ns)
                report['policy_cases'].append(dict(mode=mode, rational=[192,numerator], index=index,
                    result=rig.mem(ANSWER,20), cal_reads=reads, call=call, duration_conversion=conversion))
        # Still builder and driver execute without substituting helper results.
        # The resource-list flag is zero, so no external resource allocator runs.
        # Test output routing independently of the exposure parameters.
        for bank in (0,1):
            for numerator in (-446,13*192):
                for raw_output in (False,True):
                    for mode_byte in (1,0):
                        u.mem_write(A,bytes(0x500));u.mem_write(REQ,bytes(0x390))
                        u.mem_write(MMIO,bytes(0x10000));u.mem_write(MMIO+0x40000,bytes(0x10000))
                        put(CAL+0xcde34,mode_byte,'H')
                        put(PACKET+0x28,A+0x44);put(PACKET+0x30,A+0x62)
                        put(REQ+0x380,FRAME);put(FRAME+0x3a4,OWNER)
                        put(REQ+0x1a8,OUTPUT if raw_output else 0)
                        u.mem_write(OWNER+0xcc,struct.pack('<Ii',192,numerator))
                        put(A+0x122,9,'B')  # stale list count must be cleared
                        cal_reads.clear()
                        calls = [rig.call(0x100b33bc,[REQ,PACKET])]
                        reads = list(cal_reads)
                        index=max(4,min(16,int(numerator/192)))-4
                        assert get(A+0x118,'B')==mode_byte
                        assert get(A+0x122,'B')==0 and get(A+0x123,'B')==2
                        assert [get(A+off,'H') for off in (0x11a,0x11c,0x11e,0x120)]==[601+index,501+index,401,301]
                        assert get(A+0x17b,'B')==int(raw_output)
                        put(DRIVER+4,bank,'B')
                        calls.append(rig.call(0x100d5b9c,[DRIVER,A+0x62]))
                        mmio=MMIO+bank*0x40000
                        assert get(mmio+0x5f4)==(2<<8)|mode_byte
                        assert get(mmio+0x5f8)==((501+index)<<16)|(601+index)
                        assert get(mmio+0x5fc)==(301<<16)|401
                        assert get(mmio+0x580)==int(raw_output)
                        assert bytes(u.mem_read(MMIO+(1-bank)*0x40000,0x10000))==bytes(0x10000)
                        report['builder_cases'].append(dict(bank=bank, rational=[192,numerator], index=index,
                            raw_output=raw_output, cal_cde34=mode_byte, cal_cde30=0,
                            cal_reads=reads, parameters=rig.mem(A,0x180), calls=calls,
                            registers={hex(off):hex(get(mmio+off)) for off in (0x500,0x580,0x5f4,0x5f8,0x5fc)}))
        # The same exposure path while its frame/context pointer is absent clears
        # the fields, rather than preserving the prior synthetic calibration.
        put(REQ+0x380,0);put(REQ+0x37c,0);cal_reads.clear()
        report['absent_context_call']=rig.call(0x100b33bc,[REQ,PACKET])
        assert not cal_reads
        assert bytes(u.mem_read(A+0x118,1))==b'\0'
        assert bytes(u.mem_read(A+0x11a,10))==bytes(10)
        report['absent_context_parameters']=rig.mem(A+0x118,12)
        report['source_unchanged']=hashlib.sha256((ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()).hexdigest()==EXPECTED
        assert report['source_unchanged']; report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        report['failed_call']=getattr(rig,'last_call',None)
        report['last_blocks']=rig.blocks[-100:]
        report['pc']=hex(u.reg_read(UC_ARM_REG_PC))
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],policy_cases=len(report['policy_cases']),builder_cases=len(report['builder_cases']))))


if __name__=='__main__':main()

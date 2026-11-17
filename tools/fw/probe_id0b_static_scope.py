"""Trace real config3df request bytes to ID0b gate in bounded native stages.

Modified4 code is read-only. Nonzero body calibration and MMIO are artificial.
Calls are segmented at OS/hardware boundaries; no real pixel effect is asserted.
"""
from pathlib import Path
import argparse,json,struct,traceback
from probe_raw_candidates import Rig,ROOT,CAL,STACK,MAINREQ,sha
from probe_front_control_sources import initialize,CTX,INPUT,OUTPUT

SOURCE=0xc236f620;DEST=0xc236d378;CONFIG=0xc20aa7c8
GLOBAL=0xc29a3230;PROC=0xc29a32b4;STATE=0xc18fa954;RESOURCE=0x56000000
ROUND=ROOT/'analysis/raw-spatial-identity-2026-11-09'

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in (Path(__file__).name,'probe_raw_candidates.py','probe_front_control_sources.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    events=json.loads((ROOT/'analysis/raw-front-owner-2026-11-09/native-request-watch/events.json').read_text())
    source=bytes.fromhex(next(e for e in events if e['event']=='request_block_copy')['memory']['copy_source']['bytes'])
    inp=bytes.fromhex(next(e for e in events if e['event']=='static_input')['memory']['input']['bytes'])
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    fw=ROOT/'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN'
    blob=fw.read_bytes();assert sha(blob)=='bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
    payload=(ROUND/'id0b-mode0/generated.bin').read_bytes()
    rig=Rig(blob,snap);u,p,g=rig.uc,rig.put,rig.get
    for addr,n in ((RESOURCE,0x260000),(0x20061000,0x1000)):
        u.mem_map(addr,n);rig.regions+=((addr,n),)
    report=dict(ok=False,scope=__doc__,firmware_sha256=sha(blob),generated_list_sha256=sha(payload),rows=[],
                stages='Producer; observed request copy; static extraction; context; global gate; list gate/selector; small uploader.',
                explicit_list_fixture='After context construction, +50 points to generated mode0 stream and +54=5. This isolates the gate from mode-list classification using unavailable body data.',
                hardware_pixels_verified=False)
    try:
        for policy in (0,1,2,255):
            for temporary in (0,1):
                initialize(rig,inp);u.mem_write(SOURCE,source)
                p(CONFIG+0x3df,policy,'B');cfg=rig.mem(CONFIG,0x500)
                calls=[rig.call(0x1013f0b2,[SOURCE+0x255])]
                assert g(SOURCE+0x256,'B')==policy
                calls.append(rig.call(0x101e30ac,until=0x101e30ba,regs={5:SOURCE}))
                assert bytes(u.mem_read(SOURCE,0x260))==bytes(u.mem_read(DEST,0x260))
                p(MAINREQ,DEST);u.mem_write(STACK+0xf000,inp)
                calls.append(rig.call(0x100f6494,until=0x100f64bc,regs={7:MAINREQ}))
                request=bytes(u.mem_read(STACK+0xf000,0x50));assert request[0x47]==policy
                u.mem_write(INPUT,request);calls.append(rig.call(0x10179962,[INPUT,OUTPUT]))
                assert g(CTX+0x5a,'B')==policy and g(CTX+0x5d,'B')==2
                p(CTX+0x84,temporary);p(CTX+0x50,RESOURCE+0x60);p(CTX+0x54,5)
                before=rig.mem(CTX,0xe4)
                p(STATE+0x18,RESOURCE);p(STATE+0x1c,RESOURCE);u.mem_write(RESOURCE,payload)
                # Both sources are deliberately nonzero so a native off branch
                # cannot pass merely because the emulator starts with empty CAL.
                for idx in range(28):
                    p(CAL+0x540+idx*80,1,'B');p(CAL+0xe50+idx*80+0x32,1,'H')
                index=int(rig.call(0x1011c64e,[CTX])['registers']['r0'],16)
                assert index<28
                calls.append(rig.call(0x1011c750,[0,CTX],until=0x100cd752))
                assert g(GLOBAL+0x1c)==g(0x2006103c)==1
                calls.append(rig.call(0x1011c53c,[CAL+0xe50+index*80,CTX]))
                gate=0 if temporary or policy==2 else 1
                assert g(PROC+0x24)==gate
                p(0x20061264,0x12345670);p(0x20061268,0x100)
                selector=0x1011c3f4 if temporary else 0x1011c2a0
                calls.append(rig.call(selector,[CTX]))
                descriptor=[g(0x20061264),g(0x20061268)]
                if temporary:assert descriptor==[RESOURCE+0xacdf0,24416]
                elif not gate:assert descriptor==[0x12345670,0x100]
                else:assert descriptor==[RESOURCE+0x60,16]
                p(0x20061250,0xdeadbeef)
                calls.append(rig.call(0x100cda0a,[0,PROC+0x24]));assert g(0x20061250)==gate
                assert cfg==rig.mem(CONFIG,0x500)
                report['rows'].append(dict(policy=policy,temporary=temporary,record_index=index,
                    mode=g(CTX,'B'),request=request.hex(),context_before=before,context_after=rig.mem(CTX,0xe4),
                    id35_gate=1,id0b_gate=gate,descriptor=[hex(v) for v in descriptor],
                    selector=hex(selector),config_unchanged=True,calls=calls))
        normal=next(r for r in report['rows'] if r['temporary']==1 and r['policy']==0)
        forced=next(r for r in report['rows'] if r['temporary']==1 and r['policy']==2)
        assert normal['id0b_gate']==forced['id0b_gate']==0 and normal['descriptor']==forced['descriptor']
        report.update(ok=True,temporary_policy2_has_no_additional_gate_effect=True,
                      firmware_unchanged=sha(fw.read_bytes())==sha(blob))
    except Exception:
        report.update(error=traceback.format_exc(),last_call=rig.last_call,last_blocks=rig.blocks[-20:]);raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],rows=len(report['rows']))))

if __name__=='__main__':main()

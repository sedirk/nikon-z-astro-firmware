"""Run original CPU coordinate/mask repair on private small RAW copies.

Artificial factory records select a single pixel. Actual recorded bias patches
provide neighbours, not a pre-ISP capture. This identifies native writes and
branch gates; it does not attribute the observed dark fingerprint to this path.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import numpy as np
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC
from probe_raw_candidates import Rig, ROOT, RAM, CAL, FRAME, OWNER, INPUT, STAGE

RAW = 0x60000000
REQUEST = RAM + 0x50000
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'


def pack14(image):
    return b''.join(sum(int(v) << (14*i) for i,v in enumerate(row)).to_bytes(56,'little') for row in image)


def unpack14(data):
    return np.array([[(int.from_bytes(data[y*56:(y+1)*56],'little') >> (14*x)) & 16383 for x in range(32)] for y in range(32)], dtype=np.uint16)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'source.py').write_bytes(Path(__file__).read_bytes())
    (a.output/'rig-source.py').write_bytes((ROOT/'tools/fw/probe_raw_candidates.py').read_bytes())
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    assert hashlib.sha256(blob).hexdigest()==SHA
    targets=json.loads((ROOT/'analysis/raw-neighborhood-2026-11-09/targets/result.json').read_text())['targets']
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    rig=Rig(blob,snapshots);u,put,get=rig.uc,rig.put,rig.get
    rig.reset(dict(scalar=1008,bank=0,cached=False));u.mem_map(RAW,0x1000)
    writes=[]
    def trace_write(uc,access,addr,size,value,data):
        writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),offset=addr-RAW,size=size,value=value))
    report=dict(ok=False,scope=__doc__,firmware_sha256=SHA, cases=[], gates=[])
    def run(target,fmt=3,record_count=1,mask=True,entry=0x1024db3c,enable=1,skip=0,already=0):
        image=np.full((32,32),1008,dtype=np.uint16)
        px,py=target['raw_x']%2,target['raw_y']%2
        image[8+py:25+py,8+px:25+px]=np.array(target['raw_17x17_patches'][0],dtype=np.uint16)
        cy,cx=16+py,16+px
        data=image.astype('<u2').tobytes() if fmt==3 else pack14(image)
        stride=64 if fmt==3 else 56
        u.mem_write(RAW,bytes(4096));u.mem_write(RAW,data)
        u.mem_write(0xc2854db8,bytes(0x500))
        put(INPUT+0x14,already);put(INPUT+0x24,fmt,'B')
        u.mem_write(INPUT+0x26,struct.pack('<7H',stride,32,32,32,32,0,0));put(INPUT+0x34,RAW)
        put(FRAME+0x1f8,INPUT);put(FRAME+0x3a4,OWNER);put(STAGE+0xc,FRAME)
        put(OWNER+0x268,enable,'B');put(OWNER+0x281b,skip,'B');put(OWNER+0x252,0,'B')
        put(OWNER+0x26c,CAL)
        put(CAL+0xa6860,record_count,'H')
        u.mem_write(CAL+0xa6862,struct.pack('<2H',cx-2,cy-2)+bytes(26))
        if mask:put(CAL+0xa6866+12,1,'B')
        u.mem_write(REQUEST,struct.pack('<I4HI',INPUT+0x24,0,0,0,0,CAL))
        writes.clear()
        call=rig.call(entry,[STAGE if entry==0x100adbbe else REQUEST])
        after=bytes(u.mem_read(RAW,len(data)))
        output=np.frombuffer(after,dtype='<u2').reshape(32,32) if fmt==3 else unpack14(after)
        ys,xs=np.nonzero(image!=output)
        offsets=[(-2,0),(2,0),(0,-2),(0,2),(-1,-1),(-1,1),(1,-1),(1,1)] if (cx+cy)%2 else [(dy,dx) for dy in (-2,0,2) for dx in (-2,0,2) if dy or dx]
        max8=max(int(image[cy+dy,cx+dx]) for dy,dx in offsets)
        row=dict(x=target['raw_x'],y=target['raw_y'],phase=target['phase'],format=fmt,
            record_count=record_count,mask=mask,owner268=enable,owner281b=skip,handle14=already,
            centre_before=int(image[cy,cx]),centre_after=int(output[cy,cx]),nearest_color_max=max8,
            delta=int(output[cy,cx])-max8,
            changed_pixels=[dict(x=int(x),y=int(y),before=int(image[y,x]),after=int(output[y,x])) for y,x in zip(ys,xs)],
            raw_write_pcs=sorted(set(w['pc'] for w in writes)),raw_write_count=len(writes),
            call=call,input_sha256=hashlib.sha256(data).hexdigest(),output_sha256=hashlib.sha256(after).hexdigest())
        return row,after
    try:
        # Isolated write hook validated against the same unhooked native run.
        first,plain=run(targets[0]);hook=u.hook_add(un.UC_HOOK_MEM_WRITE,trace_write,begin=RAW,end=RAW+4095)
        traced,check=run(targets[0]);assert plain==check
        report['write_hook_control']=dict(unhooked=first,hooked=traced,byte_identical=True)
        # Both raw formats must agree, including neighbouring pixels.
        for target in targets:
            r3,b3=run(target,3);r4,b4=run(target,4)
            assert np.array_equal(np.frombuffer(b3,dtype='<u2').reshape(32,32),unpack14(b4))
            assert r3['changed_pixels'] and r4['changed_pixels']
            report['cases'].extend([r3,r4])
        for params in (dict(record_count=0),dict(record_count=51),dict(mask=False),
                       dict(entry=0x100adbbe),dict(entry=0x100adbbe,enable=0),
                       dict(entry=0x100adbbe,skip=1),dict(entry=0x100adbbe,already=1)):
            row,out=run(targets[0],**params)
            enabled=params==dict(entry=0x100adbbe)
            assert bool(row['changed_pixels'])==enabled,params
            report['gates'].append(row)
        report['summary']=dict(native_patch_cases=len(report['cases']),format_pairs=len(targets),
            max8_plus_8k_matches=sum(0<=r['delta']<=56 and r['delta']%8==0 for r in report['cases']),
            centre_below_max8=sum(r['delta']<0 for r in report['cases']),
            raw_write_pcs=sorted({pc for r in report['cases'] for pc in r['raw_write_pcs']}),
            no_record_mask_or_gate_cases=len(report['gates']))
        assert hashlib.sha256((ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()).hexdigest()==SHA
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();report['failed_call']=getattr(rig,'last_call',None)
        report['last_blocks']=rig.blocks[-80:];report['pc']=hex(u.reg_read(UC_ARM_REG_PC))
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],summary=report.get('summary'),cases=len(report['cases']))))


if __name__=='__main__':main()

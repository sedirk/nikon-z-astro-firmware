"""Native descriptor, encoder submission and release-selection contracts.

Private object copies and unmapped pixel addresses; no hardware completion,
sensor sample, codec output, actual resource free or saved NEF is supplied.
The handle handoff is an explicitly separate post-processing segment.
"""
from pathlib import Path
import argparse, gc, json, struct, traceback
from probe_raw_candidates import (Rig, ROOT, BASE, RAM, OWNER, FRAME, INPUT,
    OUTPUT, ENCODED, STAGE, REQ, STOP, sha, UC_ARM_REG_PC)
import unicorn as un

SOURCE_SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
PATCH_SHA = 'c77b4a700d87b0cd1ced828591891ac676a1f7f300ec48d132c80b9dd57a8f53'
FULLSIZE_SHA = '7ff43669a82d9def1407056d889db041338dbe12a0bb2867eccfc98527f0875c'
GLOBAL, CONTEXT, CODEC_MMIO = 0xc23234c8, 0xc180b704, 0x20204000
ALLOC, MAPPED, CODEC_CTX = RAM+0x45000, RAM+0x46000, RAM+0x47000


def descriptor(rig, h):
    g = rig.get
    return dict(handle=hex(h), format=g(h+0x24,'B'), stride=g(h+0x26,'H'),
        full=[g(h+0x28,'H'),g(h+0x2a,'H')], active=[g(h+0x2c,'H'),g(h+0x2e,'H')],
        crop=[g(h+0x30,'H'),g(h+0x32,'H')], base=hex(g(h+0x34)), raw=rig.mem(h,0x38))


def run(rig, variant, cfg):
    rig.reset(dict(scalar=300,bank=0,cached=0,owner_mode=1))
    u,p,g=rig.uc,rig.put,rig.get
    calls=[]
    def call(*args,**kw):
        row=rig.call(*args,**kw); calls.append(row); return row
    # Explicit mode fixtures on a copied owner. These are numeric internal IDs;
    # no camera menu interpretation is needed to exercise native contracts.
    for off,value in ((0x88,0),(0x170,cfg['area']),(0x190,1),(0x192,cfg['size']),
                      (0x194,cfg['mode']),(0x195,cfg['depth']),
                      (0x252,cfg['wide']),(0x2811,cfg.get('readout',0))):
        p(OWNER+off,value,'B')
    p(OWNER+0x1af0,0)
    # Start after the OS resource-availability check; stop before allocation.
    pre=call(0x10124196,until=0x100d8868,regs={4:OWNER,5:2,6:RAM+0x48000})
    fmt=int(pre['registers']['r5'],16)
    capacity=int(pre['registers']['r2'],16)
    assert fmt==({(0,0):2,(1,0):4,(1,1):3}[(cfg['depth'],cfg['wide'])])
    for h,ad,base in ((INPUT,ALLOC,0x60000000),(OUTPUT,ALLOC+0x20,0x64000000),
                      (ENCODED,ALLOC+0x40,0x68000000)):
        p(h+4,ad); p(ad,base); p(ad+4,capacity)
    call(0x10123e70,[INPUT,OWNER,fmt])
    call(0x10124224,[OUTPUT,OWNER])
    call(0x101254bc,[ENCODED,OWNER])
    front,backend=descriptor(rig,INPUT),descriptor(rig,OUTPUT)
    assert front['format']==backend['format']==fmt
    encoded=rig.mem(ENCODED,0x120)
    out_w,out_h=g(ENCODED+0x52,'H'),g(ENCODED+0x54,'H')
    assert g(ENCODED+0x50,'B')==cfg['mode']
    # Execute the actual module bytes, including request memset and candidate.
    p(REQ+0x1a8,0x5a5a5a5a)
    call(0x100ae33e,[STAGE],until=0x100b4c78)
    request=rig.mem(REQ,0x390)
    replacement=(variant=='original' or (variant=='still-preserve-fullsize-raw' and cfg['size']!=0))
    assert g(REQ+8)==INPUT and g(REQ+0x1a8)==(OUTPUT if replacement else 0)
    call(0x100ae41e,until=0x100ae438,regs={4:FRAME,5:REQ})
    chosen=OUTPUT if replacement else INPUT
    assert g(FRAME+0x1f8)==chosen
    # The surrounding processing callback selects +1fc for early cleanup.
    # Stop before freeing it; do not manufacture an allocator return.
    p(FRAME+0x1a0,0)
    early=call(0x100ae494,until=0x101241e0,regs={4:FRAME})
    other=INPUT if replacement else OUTPUT
    assert int(early['registers']['r0'],16)==other and other!=chosen
    d=backend if replacement else front
    queue=0x101cab2e if cfg['mode']==0 else 0x101caad8
    call(0x100af648,[STAGE],until=queue)
    gp=GLOBAL+0x6c if cfg['mode']==0 else GLOBAL
    packet=rig.mem(gp,0x38 if cfg['mode']==0 else 0x68)
    addr_off,stride_off,dest_off,out_stride_off=(0x20,0x24,0x28,0x2c) if cfg['mode']==0 else (0x40,0x44,0x48,0x4c)
    numerator,denominator={2:(3,2),3:(2,1),4:(7,4)}[fmt]
    cropx,cropy=d['crop']; stride=d['stride']
    expected=int(d['base'],16)+cropy*stride+cropx*numerator//denominator
    expected_stride=((out_w*numerator//denominator)+15)&~15
    assert g(gp+addr_off)==expected and g(gp+stride_off,'H')==stride
    assert g(gp+dest_off)==g(ENCODED+0x58)
    assert g(gp+out_stride_off,'H')==expected_stride
    assert [g(gp+4),g(gp+8)]==[out_w,out_h]
    assert g(gp+2,'B')=={2:2,3:0,4:1}[fmt]
    # Byte bounds of the requested rows, not verification of valid image data.
    last=(cropy+out_h-1)*stride+(cropx+out_w)*numerator//denominator
    bounds=dict(x=cropx+out_w<=d['full'][0], y=cropy+out_h<=d['full'][1],
                allocation=last<=capacity, last_relative_byte_exclusive=last,
                supplied_allocation_size=capacity)
    assert bounds['x'] and bounds['y'] and bounds['allocation']
    regs=None
    if cfg['mode']!=0:
        u.mem_write(CODEC_MMIO,bytes(4096))
        p(CONTEXT+0xc,GLOBAL)
        call(0x101ca6c6,[MAPPED])
        call(0x10108f8a,[CODEC_CTX,MAPPED])
        assert g(CODEC_MMIO+0x400)==expected
        assert g(CODEC_MMIO+0x404)==stride and g(CODEC_MMIO+0x424)==expected_stride
        assert [g(CODEC_MMIO+0x4c),g(CODEC_MMIO+0x50)]==[out_w,out_h]
        regs=rig.mem(CODEC_MMIO,0x428)
    # Independently invoke release selection. The real free itself is not run;
    # doing so would require OS locks/allocator state and actual completion.
    release=call(0x100af780,[STAGE],until=0x101241e0)
    assert int(release['registers']['r0'],16)==chosen
    assert g(FRAME+0x1fc)==(INPUT if replacement else OUTPUT)
    return dict(variant=variant,configuration=cfg,calls=calls,
        front=front,backend=backend,encoded_handle=encoded,prepared_request=request,
        encoder_packet=packet,codec_registers=regs,selected_handle=hex(chosen),
        encoder_input_address=hex(expected),encoder_input_stride=stride,
        output_dimensions=[out_w,out_h],output_stride=expected_stride,
        output_raw_capacity=g(ENCODED+0x4c),source_bounds=bounds,
        uncompressed_bytes=expected_stride*out_h,
        uncompressed_fits_raw_capacity=(expected_stride*out_h<=g(ENCODED+0x4c)),
        early_cleanup_selected=early['registers']['r0'],
        release_selected=release['registers']['r0'],
        other_handle=hex(g(FRAME+0x1fc)),
        geometry_equals_backend=(d['full']==backend['full'] and d['active']==backend['active'] and d['crop']==backend['crop']),
        pixels_verified=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); assert __debug__
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    (args.output/'rig-source.py').write_bytes((ROOT/'tools/fw/probe_raw_candidates.py').read_bytes())
    observed=ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json'
    snap=json.loads(observed.read_text())['final']
    original=ROOT/'firmware/decoded/eg1620_038000.bi'
    candidate=ROOT/'analysis/raw-patch-candidates-2026-11-08/modules/still-preserve-front-raw.bi'
    fullsize=ROOT/'analysis/raw-release-contract-2026-11-08/fullsize-module/still-preserve-fullsize-raw.bi'
    configs=[dict(name=f'f{depth}{wide}-m{mode}-s{size}-a0',depth=depth,wide=wide,mode=mode,size=size,area=0)
             for depth,wide in ((0,0),(1,0),(1,1)) for mode in (0,1,2) for size in (0,1,2)]
    configs.append(dict(name='f10-m1-s0-a1',depth=1,wide=0,mode=1,size=0,area=1))
    configs.extend(dict(name=f'observed-readout-f{depth}0-m{mode}',depth=depth,wide=0,
                        mode=mode,size=0,area=0,readout=1)
                   for depth in (0,1) for mode in (0,1,2))
    report=dict(ok=False,scope=__doc__,cases=[],guard_cases=[],probe_sha256=sha(Path(__file__).read_bytes()),
        rig_sha256=sha((ROOT/'tools/fw/probe_raw_candidates.py').read_bytes()),
        observed_sha256=sha(observed.read_bytes()),unicorn=un.__version__,
        assumptions=['Owner numeric fields are explicit test inputs, not a physical exposure.',
          'Both RAW descriptor initializers and encoded descriptor initializer are native complete functions.',
          'Source allocation-selection segment starts after OS availability check and stops before allocation.',
          'Main-request construction and handle swap are separate bounded segments.',
          'Encoder stops before synchronous queue submission; mapper/register packer are separate segments.',
          'Release callback stops before actual free; no free return or encoder completion is invented.',
          'Pixels at 0x60000000, 0x64000000 and 0x68000000 are unmapped.'])
    rig=None
    try:
        for name,path,digest in (('original',original,SOURCE_SHA),('still-preserve-front-raw',candidate,PATCH_SHA),
                                 ('still-preserve-fullsize-raw',fullsize,FULLSIZE_SHA)):
            blob=path.read_bytes(); assert sha(blob)==digest
            rig=Rig(blob,snap); rig.uc.mem_map(CODEC_MMIO,4096)
            rig.uc.hook_add(un.UC_HOOK_MEM_WRITE,rig.on_write,begin=CODEC_MMIO,end=CODEC_MMIO+4095)
            for cfg in configs:
                report['current_case']=[name,cfg]
                result=run(rig,name,cfg); result['module_sha256']=digest
                report['cases'].append(result)
            if name!='still-preserve-front-raw':
                for kind in (0,2,3,6,7):
                    for mode in (0,1,2,3):
                        for size in (0,1,2):
                            for has_output in (False,True):
                                cfg=dict(scalar=300,bank=0,cached=0,owner_mode=mode,kind=kind,output=has_output)
                                rig.reset(cfg); rig.put(OWNER+0x192,size,'B'); rig.put(REQ+0x1a8,0x5a5a5a5a)
                                call=rig.call(0x100ae33e,[STAGE],until=0x100b4c78)
                                expected=has_output and mode in (0,1) and kind not in (3,4,5,6)
                                if name=='still-preserve-fullsize-raw': expected=expected and size!=0
                                assert rig.get(REQ+0x1a8)==(OUTPUT if expected else 0)
                                report['guard_cases'].append(dict(variant=name,kind=kind,owner_mode=mode,
                                    size=size,has_output=has_output,replacing=bool(expected),
                                    request=rig.mem(REQ,0x390),call=call))
            rig.uc=None; rig=None; gc.collect()
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if rig:
            report['failure_pc']=hex(rig.uc.reg_read(UC_ARM_REG_PC))
            report['failure_call']=rig.last_call
            report['failure_blocks']=list(rig.blocks)
        raise
    finally:
        report['source_unchanged']=sha(original.read_bytes())==SOURCE_SHA
        report['candidate_unchanged']=sha(candidate.read_bytes())==PATCH_SHA
        report['fullsize_candidate_unchanged']=sha(fullsize.read_bytes())==FULLSIZE_SHA
        (args.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),guard_cases=len(report['guard_cases']),current=report.get('current_case'))))


if __name__=='__main__': main()

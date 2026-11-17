"""Replay real NEF six-coefficient values through original C3.80 spatial code.

Private cached/grid inputs are reconstructed fixtures, not recovered camera RAM.
The native generator, packer, configuration-only driver and tag callback run.
No image payload, ISP arithmetic, capture completion or modified NEF is supplied.
"""
from pathlib import Path
import argparse, binascii, itertools, json, struct, traceback
from probe_raw_candidates import (Rig, ROOT, BASE, RAM, OWNER, FRAME, PROPS,
    CTX, A, DRIVER, MMIO, CACHE, SPATIAL, FLAGS, TABLES, REQ, PACKET,
    STORAGE, INPUT, OUTPUT, TAG, META, PAYLOAD, PACKAGE, sha)

ORIGINAL_SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
TABLECTX, GRID = RAM+0x30000, RAM+0x35000


def run(rig, cfg, coefficients, actual_tag):
    rig.reset(dict(scalar=1008, bank=cfg['bank'], cached=0))
    u, p, g = rig.uc, rig.put, rig.get
    # Isolate the spatial module from the observed object's unrelated state.
    u.mem_write(PROPS, bytes(0xa0)); u.mem_write(CTX, bytes(0x600))
    u.mem_write(A, bytes(0x500))
    for off, value in ((0,PROPS),(4,CACHE),(0xd0,A),(0xd8,SPATIAL),(0xe4,OWNER+0xff8)):
        p(CTX+off,value)
    p(PROPS+0x58,6064*256); p(PROPS+0x5c,4040*256)
    p(PROPS+0x96,int(cfg['cached']),'B');p(PROPS+0x70,0,'B')
    p(CTX+0x33,cfg['mode'],'B')
    p(CTX+0x46,cfg['xy'][0],'h');p(CTX+0x48,cfg['xy'][1],'h')
    p(PROPS+0x2c,cfg['source'],'B');p(PROPS+0x45,cfg['bit2'],'B')
    u.mem_write(PROPS+0x35,bytes(range(1,9)));p(PROPS+0x46,16,'H')
    p(PROPS+0x40,GRID)
    grid=[0]*864
    for knot,coefficient in itertools.product(range(8),range(6)):
        grid[knot*108+coefficient*18]=coefficients[coefficient]
    u.mem_write(GRID,struct.pack('<864i',*grid))
    u.mem_write(CACHE+0x70,struct.pack('<4B6i',*cfg['cache_flags'],0,0,*coefficients))
    # Dirty previous contents: accepted off cases must actively replace them.
    u.mem_write(SPATIAL,b'\x6b'*68)
    u.mem_write(TABLES+0x2578,b'\x6b'*72)
    p(TABLECTX,SPATIAL);p(TABLECTX+0x10,TABLES);p(TABLECTX+0x1c,RAM+0x31000)
    # Keep the four offset words/ceiling explicit and constant across cases.
    for i in range(4):
        p(A+0x184+6*i,256,'H');p(A+0x186+6*i,(-1008)&0xffff,'H');p(A+0x188+6*i,300,'H')
    p(A+0x19c,32466,'H')
    calls=[]
    for entry,arg in ((0x10196fe4,CTX),(0x10197500,CTX+0x160),
                      (0x101975be,CTX),(0x10197678,CTX)):
        calls.append(rig.call(entry,[arg]))
    calls.append(rig.call(0x10198640,[TABLECTX],until=0x101986c6))
    generated=list(struct.unpack('<6i',u.mem_read(CTX+0x5c,24)))
    exported=list(struct.unpack('<6i',u.mem_read(OWNER+0xffc,24)))
    table=list(struct.unpack('<34h',u.mem_read(SPATIAL,68)))
    for off,value in ((4,1),(8,INPUT),(0x1a8,OUTPUT),(0x35c,A),
                      (0x360,TABLES),(0x364,FLAGS),(0x378,1),(0x380,FRAME)):
        p(REQ+off,value)
    bank=MMIO+cfg['bank']*0x40000
    u.mem_write(bank+0x1200,b'\x5a'*72)
    calls.append(rig.call(0x100b5716,[REQ,PACKET,STORAGE]))
    calls.append(rig.call(0x100d5c86,[DRIVER,PACKET,0,0]))
    regs={hex(int(w['address'],16)-bank):w['value'] for w in calls[-1]['writes']}
    assert g(bank+0x310)==0x60000000 and g(bank+0x3ec)==0x62000000
    assert g(bank+0x710)==g(bank+0x714)==(((-1008)&8191)*0x10001)
    assert g(bank+0x720)==32466
    assert all(hex(x) in regs for x in range(0x1200,0x1248,4))
    calls.append(rig.call(0x10305628))
    p(PACKAGE+0x34,OWNER)
    u.mem_write(TAG,rig.blob[0x11536da8-BASE:0x11536db4-BASE])
    p(META+0xc,TAG);p(META+0x10,PAYLOAD)
    calls.append(rig.call(0x102899a0,[TAG,PACKAGE+0x30,META]))
    payload=bytes(u.mem_read(PAYLOAD,104))
    assert struct.unpack_from('<H',payload,102)[0]==binascii.crc_hqx(payload[:102],0xffff)
    assert [struct.unpack_from('<i',payload,o)[0] for o in (0x2c,0x1c,0x14,0x50,0x40,0x38)]==exported
    return dict(fixture=cfg,generated_coefficients=generated,exported_coefficients=exported,
        parameter_flags=[g(A+0x182,'B'),g(A+0x180,'B')],table=table,
        state=rig.mem(CTX+0x58,0x6a),parameters=rig.mem(A,0x500),
        packed_tables=rig.mem(TABLES+0x2578,72),registers=regs,
        tag_hex=payload.hex(),tag_flags=[payload[4],payload[0x5a]],
        tag_difference_offsets_vs_actual=[i for i,(a,b) in enumerate(zip(payload,actual_tag)) if a!=b],
        calls=calls)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fields',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    for filename in (Path(__file__).name,'probe_raw_candidates.py'):
        (args.output/filename).write_bytes((ROOT/'tools/fw'/filename).read_bytes())
    fields=json.loads(args.fields.read_text())['files']
    coefficients=fields[0]['two_table_spatial']['coefficients']
    assert all(f['two_table_spatial']==fields[0]['two_table_spatial'] for f in fields)
    actual_tag=bytes.fromhex(fields[0]['nefinfo']['entries']['0x7']['bytes'])
    source=ROOT/'firmware/decoded/eg1620_038000.bi';blob=source.read_bytes()
    assert sha(blob)==ORIGINAL_SHA
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,original_sha256=sha(blob),source_fields_sha256=sha(args.fields.read_bytes()),
        real_coefficients=coefficients,cases=[],limitations=[
            'Coefficient values are read from real NEFs; cache/grid, geometry and mode are explicitly supplied fixtures.',
            'Index 0 is chosen for unit coefficient export scaling, not recovered from camera RAM.',
            'MMIO is a recording buffer, not a hardware ISP pixel model.',
            'These native parameter controls are not a demonstrated removal of rings in a physical NEF.'])
    rig=Rig(blob,snapshots)
    variants=[
        ('cached-active',dict()),
        ('cached-mode7',dict(mode=7)),
        ('cached-inhibit-only',dict(cache_flags=[1,1])),
        ('cached-neutral',dict(cache_flags=[1,0],xy=[19,-23])),
        ('cached-inactive-coordinate',dict(cache_flags=[0,0],xy=[19,-23])),
        ('ordinary-active',dict(cached=False)),
        ('ordinary-bit2-off',dict(cached=False,bit2=4,xy=[19,-23])),
        ('ordinary-mode7-off',dict(cached=False,mode=7,xy=[19,-23])),
        ('ordinary-mode18-off',dict(cached=False,mode=18,xy=[19,-23])),
        ('ordinary-source-absent',dict(cached=False,source=0)),
        ('ordinary-source-absent-coordinate',dict(cached=False,source=0,xy=[19,-23])),
    ]
    try:
        for bank in (0,1):
            baseline=None
            for name,extra in variants:
                cfg=dict(name=name,bank=bank,cached=True,mode=0,source=1,bit2=0,cache_flags=[0,1],xy=[0,0]);cfg.update(extra)
                report['current_case']=cfg
                row=run(rig,cfg,coefficients,actual_tag)
                if baseline is None: baseline=row
                row['changed_registers_vs_cached_active']={k:[baseline['registers'].get(k),row['registers'].get(k)]
                    for k in set(baseline['registers'])|set(row['registers'])
                    if baseline['registers'].get(k)!=row['registers'].get(k)}
                report['cases'].append(row)
                if name in ('cached-active','cached-mode7','ordinary-active'):
                    assert row['exported_coefficients']==coefficients,(name,row['exported_coefficients'])
                    assert row['tag_flags']==[1,1]
                if name in ('cached-neutral','ordinary-bit2-off','ordinary-mode7-off','ordinary-mode18-off'):
                    assert row['generated_coefficients']==[0]*6 and row['table']==[0]*34
                    assert row['parameter_flags']==[1,0] and row['tag_flags']==[0,0]
                    assert all(int(row['registers'][hex(x)],16)==0 for x in range(0x1200,0x1248,4))
                assert not ({'0x710','0x714','0x720','0x310','0x3ec','0x580'}&set(row['changed_registers_vs_cached_active']))
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();report['failed_call']=getattr(rig,'last_call',None);report['last_blocks']=rig.blocks[-50:]
        raise
    finally:
        report['original_unchanged']=sha(source.read_bytes())==ORIGINAL_SHA
        (args.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']))))


if __name__=='__main__':main()

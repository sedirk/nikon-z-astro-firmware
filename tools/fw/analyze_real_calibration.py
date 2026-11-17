"""Profile the twice-verified camera resources without modifying source data.

Integer views are descriptions, not inferred ISP operations or unity values.
"""
from pathlib import Path
import argparse, hashlib, json, struct
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
BACKUP=ROOT/'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3'
TABLES=[(0xa6e90,0x5f60),(0xacdf0,0x5f60),(0xb2d50,0x5f60),
        (0xb8cb0,0x3e20),(0xbcad0,0x5f60),(0xc2a30,0x1fe0),
        (0xc4a10,0x3e20),(0xc8830,0x1fe0)]
def sha(b):return hashlib.sha256(b).hexdigest()
def stats(x):
    v,n=np.unique(x,return_counts=True);order=np.argsort(-n)[:12]
    return dict(min=int(x.min()),max=int(x.max()),unique=int(len(v)),nonzero=int(np.count_nonzero(x)),
        most_common=[dict(value=int(v[i]),count=int(n[i])) for i in order],
        percentiles=np.percentile(x,[0,1,25,50,75,99,100]).tolist())
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    session=json.loads((BACKUP/'result.json').read_text());assert session['ok'] and session['gate_closed']
    cal=(BACKUP/'CAL38.bin').read_bytes();id35=(BACKUP/'ID35.bin').read_bytes()
    assert len(cal)==0x168000 and len(id35)==0xd8000
    result=dict(ok=False,scope=__doc__,origin='Runtime resources loaded by native F001; read by F029 in two matching passes per chunk.',
        resources={n:dict(bytes=len(b),sha256=sha(b)) for n,b in [('CAL38',cal),('ID35',id35)]},
        global_control_records=[],id35_fixed=[],table33_records=[],hardware_pixels_verified=False)
    for index in range(28):
        b=cal[0x540+index*80:0x540+(index+1)*80]
        result['global_control_records'].append(dict(index=index,offset=hex(0x540+index*80),bytes_hex=b.hex(),first_four=list(b[:4])))
    for offset,length in TABLES:
        b=id35[offset:offset+length];w=np.frombuffer(b,dtype='<u4');h=np.frombuffer(b,dtype='<u2').reshape(-1,2)
        result['id35_fixed'].append(dict(offset=hex(offset),bytes=length,sha256=sha(b),
            word_count=len(w),u32=stats(w),halfword_lanes=[stats(h[:,c]) for c in range(2)],
            first_32_words=[hex(int(x)) for x in w[:32]],
            nonzero_word_indices=np.flatnonzero(w).tolist(),
            change_indices=(np.flatnonzero(w[1:]!=w[:-1])+1).tolist()))
        (a.output/f'ID35-{offset:05x}.bin').write_bytes(b)
    for group in range(11):
        for category in range(2):
            offset=0x47180+group*600+category*300;b=cal[offset:offset+300]
            vals=np.frombuffer(b[36:],dtype='<u2').reshape(33,4)
            result['table33_records'].append(dict(group=group,category=category,offset=hex(offset),
                sha256=sha(b),header_hex=b[:36].hex(),header_u16=list(struct.unpack('<18H',b[:36])),
                values_u16=vals.tolist(),lanes=[stats(vals[:,c]) for c in range(4)],
                adjacent_differences=[np.diff(vals[:,c].astype(np.int32)).tolist() for c in range(4)]))
    result['ok']=True
    (a.output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps(dict(resources=result['resources'],static_control=result['global_control_records'][2]['first_four'],
        fixed=[dict(offset=r['offset'],min=r['u32']['min'],max=r['u32']['max'],unique=r['u32']['unique'],nonzero=r['u32']['nonzero'],common=r['u32']['most_common'][:4]) for r in result['id35_fixed']],
        table33=[dict(group=r['group'],category=r['category'],header=r['header_u16'],first=r['values_u16'][0],middle=r['values_u16'][16],last=r['values_u16'][32]) for r in result['table33_records']]),indent=2))
if __name__=='__main__':main()

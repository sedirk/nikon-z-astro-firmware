"""Summarize hardware backup integrity and measured table structure; no writes to camera."""
from pathlib import Path
import argparse,hashlib,json,struct
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'analysis/raw-calibration-access-2026-11-10'
def read(p):return json.loads(p.read_text(encoding='utf8'))
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    backup=OUT/'camera-calibration-backup-v3';profile=read(OUT/'real-calibration-profile/result.json')
    native=read(OUT/'real-calibration-native-front-v2/result.json');assert native['ok']
    events=[json.loads(s) for s in (backup/'events.jsonl').read_text().splitlines()]
    reqs=[r for r in events if 'request' in r];assert len(reqs)==291
    assert reqs[0]==dict(request='0x94fd',params=[0xf001,0,0,0,0])
    assert reqs[-2]==dict(request='0x94fd',params=[0xf002,0,0,0,0])
    assert reqs[-1]==dict(request='0x94ff',params=[0xf029,0,32,0,0])
    resources=[]
    for selector,name,size in ((0,'CAL38',0x168000),(1,'ID35',0xd8000)):
        chunks=[r for r in events if r.get('verified_chunk') and r['selector']==selector]
        assert [r['offset'] for r in chunks]==list(range(0,size,16384))
        assert all(r['length']==16384 for r in chunks)
        actual=[r['params'] for r in reqs[1:-2] if r['params'][3]==selector]
        expected=[p for off in range(0,size,16384) for p in ([0xf029,off,16384,selector,0],)*2]
        assert actual==expected
        b=(backup/(name+'.bin')).read_bytes();assert len(b)==size
        resources.append(dict(name=name,bytes=size,sha256=sha(b),twice_verified_chunks=len(chunks)))
    assert len([r for r in events if r.get('stage')=='end' and r['ptp_response']=='0x2001'])==288
    assert len([r for r in events if r.get('stage')=='end' and r['ptp_response']=='0xa004'])==1
    assert read(backup/'result.json')['exit_succeeded'] and read(backup/'result.json')['gate_closed']
    inv=read(OUT/'camera-after-backup-inventory.json');assert inv['ok'] and len(inv['vendor_opcodes'])==65
    shape=[]
    for rec in profile['table33_records']:
        v=np.array(rec['values_u16']);nonzero=np.flatnonzero(np.any(v!=0,axis=1))
        shape.append(dict(group=rec['group'],category=rec['category'],header_hex=rec['header_hex'],
            nonzero_row_indices=nonzero.tolist(),all_16384=bool(np.all(v==16384)),
            min_nonzero=int(v[v!=0].min()),max_nonzero=int(v[v!=0].max()),
            first17_tail_duplicate=bool(np.array_equal(v[15],v[16])),last16_zero=bool(np.all(v[17:]==0))))
    for group in (0,1,2,3,10):
        for cat in (0,1):
            r=shape[group*2+cat];assert r['nonzero_row_indices']==list(range(17)) and r['last16_zero']
            assert profile['table33_records'][group*2+cat]['sha256']==profile['table33_records'][cat]['sha256']
    assert all(shape[g*2+c]['all_16384'] for g in (4,5,6,7,8,9) for c in (0,1))
    fixed=np.frombuffer((backup/'ID35.bin').read_bytes()[0xacdf0:0xb2d50],dtype='<u2').reshape(6104,2)
    fig,axs=plt.subplots(2,2,figsize=(12,7),layout='constrained')
    for c in range(2):
        axs[0,0].plot(np.arange(6104),fixed[:,c],lw=.35,alpha=.65,label=f'Halfword lane {c}')
        axs[0,1].hist(fixed[:,c],bins=np.arange(595.5,604.5),alpha=.5,label=f'Lane {c}')
    axs[0,0].set(title='ID35 + 0xacdf0: 6104 pairs',xlabel='Stored pair index (spatial mapping pending)',ylabel='Unsigned 16-bit value')
    axs[0,1].set(title='ID35 value distribution',xlabel='Unsigned 16-bit value',ylabel='Count')
    for cat in (0,1):
        vals=np.array(profile['table33_records'][cat]['values_u16'])
        ax=axs[1,cat]
        for lane in range(4):ax.plot(range(17),vals[:17,lane],marker='.',lw=1,label=f'Stored lane {lane}')
        ax.axhline(16384,color='black',lw=.8,ls='--',label='16384 reference')
        ax.set(title=f'CAL38 group 0 / category {cat}: nonzero rows 0–16',xlabel='Table row index (not radius)',ylabel='Unsigned 16-bit value')
        ax.text(.02,.03,'Rows 17–32 are all zero; omitted here.',transform=ax.transAxes,fontsize=8)
    for ax in axs.flat:ax.legend(fontsize=7);ax.grid(alpha=.2)
    fig.suptitle('Real Z6 calibration resources — numeric profiles, not an ISP simulation')
    fig.savefig(a.output/'real-calibration-profiles.png',dpi=150);plt.close(fig)
    result=dict(ok=True,resources=resources,request_count=len(reqs),chunks=144,successful_data_reads=288,
        post_exit_gate='A004',post_exit_inventory_count=65,table33_structure=shape,
        native_cases=len(native['rows']),single_field_comparisons=len(native['counterfactuals']),
        original_and_modified4_comparisons=len(native['firmware_comparisons']),
        actual_pixel_or_shutter_test=False,calibration_write_command_sent=False,new_firmware=False,
        findings=['The actual static record byte CAL38+0x5e0 is 1; normal record +0x630 is 0.',
          'ID35 fixed mode1 data consists numerically of 6104 little-endian u16 pairs near 600.',
          'CAL38 33x4 groups0,1,2,3,10 share two tables:17 nonzero rows,16 zero rows.',
          'Groups4–9 store16384 throughout table body and use0 at header+18/+1a.',
          'Original native code maps those two header bytes independently to20068700 and20068704.',
          'Both isolated zero-field comparisons preserve ID35 gate, descriptor and table upload.'],
        hypotheses=['A Q14 scale near16384 is suggested by natural constant tables, not verified hardware unity.',
          'ID35 near600 pairs could be column baseline data; pixel arithmetic and spatial mapping are unconfirmed.',
          'Header+18/+1a are narrower candidate controls; hardware enable/disable meaning remains to be identified.'])
    (a.output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('table33_structure','findings','hypotheses')},indent=2))
if __name__=='__main__':main()

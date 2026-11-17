"""Export all 112 original selections and compare exploratory local kernels.

All values are stored NEF codes. Kernel comparisons do not identify a firmware
algorithm; the old 1.3 s dark is a different-date reference only.
"""
from pathlib import Path
import argparse, json, hashlib
import numpy as np
import rawpy
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    paths=[ROOT/'samples/11.9'/f'Z61_{i}.NEF' for i in range(4851,4856)]
    paths.append(ROOT/'samples/nas-2026-11-09/Z61_4850.NEF')
    hashes={str(q.relative_to(ROOT)):file_sha(q) for q in paths};images=[]
    for path in paths:
        with rawpy.imread(str(path)) as r:
            assert r.raw_image.shape==(4040,6064)
            images.append(r.raw_image.copy())
    b0,b1,b2,d0,d1=images[:5]
    bias_sum=b0.astype(np.int32)+b1+b2
    selected=(np.minimum.reduce(images[:3])>1108)&(np.maximum(d0,d1)<1080)&(3*np.maximum(d0,d1).astype(np.int32)<bias_sum-150)
    selected[:10,:]=False;selected[4030:,:]=False;selected[:,:10]=False;selected[:,6054:]=False
    ys,xs=np.nonzero(selected);assert len(xs)==112
    kernels={
        'same_phase_8':[(dy,dx) for dy in (-2,0,2) for dx in (-2,0,2) if dy or dx],
        'same_phase_cross4':[(-2,0),(2,0),(0,-2),(0,2)],
        'same_phase_24':[(dy,dx) for dy in (-4,-2,0,2,4) for dx in (-4,-2,0,2,4) if dy or dx],
        'all_same_color_radius2':[(dy,dx) for dy in range(-2,3) for dx in range(-2,3) if (dy or dx) and (dy+dx)%2==0],
    }
    def maximum(im,y,x,label):
        offsets=kernels[label]
        # R and B remain their own phase; only green uses diagonal other-green.
        if label=='all_same_color_radius2' and (y+x)%2==0:offsets=kernels['same_phase_8']
        return int(max(im[y+dy,x+dx] for dy,dx in offsets))
    rows=[]; labels={(0,0):'R',(0,1):'G1',(1,0):'G2',(1,1):'B'}
    for y,x in zip(ys.tolist(),xs.tolist()):
        values=[int(im[y,x]) for im in images]
        maxima={k:[maximum(im,y,x,k) for im in images] for k in kernels}
        rows.append(dict(raw_x=x,raw_y=y,phase=labels[(y%2,x%2)],centres=values,
            maxima=maxima,both_dark_equal_max8=all(values[i]==maxima['same_phase_8'][i] for i in (3,4)),
            raw_17x17_patches=[im[y-8:y+9,x-8:x+9].tolist() for im in images]))
    summaries={}
    for k in kernels:
        diff=np.array([[r['centres'][i]-r['maxima'][k][i] for i in (3,4)] for r in rows])
        summaries[k]=dict(both_dark_exact=int(np.all(diff==0,axis=1).sum()),
            either_dark_exact=int(np.any(diff==0,axis=1).sum()),
            both_within_1DN=int(np.all(abs(diff)<=1,axis=1).sum()),
            both_within_2DN=int(np.all(abs(diff)<=2,axis=1).sum()),
            per_dark_difference_histogram=[{str(v):int(c) for v,c in zip(*np.unique(diff[:,i],return_counts=True))} for i in range(2)])
    assert summaries['same_phase_8']['both_dark_exact']==31
    # Nearby positions with same CFA, 32 sensor columns away; selection independent
    # of their code/equality. Counts are a local reference, not a formal p-value.
    controls=[]
    for shift in (-32,32):
        mask=[all(int(images[i][r['raw_y'],r['raw_x']+shift])==maximum(images[i],r['raw_y'],r['raw_x']+shift,'same_phase_8') for i in (3,4)) for r in rows]
        controls.append(dict(shift_x=shift,positions=len(mask),both_dark_exact=sum(mask)))
    assert all(file_sha(ROOT/q)==s for q,s in hashes.items())
    report=dict(scope=__doc__,source_sha256=hashes,files=[p.name for p in paths],coordinates='zero-based full 6064x4040 stored CFA',
        selection='all bias >1108; both dark <1080 and < mean bias -50DN; previous recommended-crop interior',
        count=len(rows),kernels=kernels,exploratory_kernel_summary=summaries,nearby_controls=controls,targets=rows,source_unchanged=True,ok=True)
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/'source.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(count=len(rows),kernels=summaries,controls=controls),indent=2))

if __name__=='__main__':main()

"""Test a specific saved-pixel fingerprint: centre capped at neighbour maximum.

Compare each CFA phase's eight neighbours at sensor offsets +/-2 pixels.
Selection of bright-bias sites does not use neighbour equality. Counts are
observations of decoded NEFs, not a claim that a particular firmware routine
or shutter threshold has already been identified.
"""
from pathlib import Path
import argparse, hashlib, json
import numpy as np
import rawpy
from audit_nef import file_sha

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    names=[f'Z61_{i}.NEF' for i in range(4851,4856)];arrays=[];hashes={}
    for name in names:
        path=a.input/name;hashes[name]=file_sha(path)
        with rawpy.imread(str(path)) as r:
            assert r.raw_pattern.tolist()==[[0,1],[3,2]] and r.raw_image.shape==(4040,6064)
            arrays.append(r.raw_image[8:4032,8:6056].copy())
    report=dict(scope=__doc__,script_sha256=file_sha(__file__),input_hashes=hashes,
        rawpy=rawpy.__version__,libraw=rawpy.libraw_version,
        phases=[],total_selected=0,selected_dark_both_equal_max=0,selected_bias_all_strict_max=0)
    for label,(dy,dx) in zip(['R','G1','G2','B'],[(0,0),(0,1),(1,0),(1,1)]):
        planes=[x[dy::2,dx::2] for x in arrays];h,w=planes[0].shape
        centre=[x[1:-1,1:-1] for x in planes]
        maxima=[np.maximum.reduce([x[1+yy:h-1+yy,1+xx:w-1+xx] for yy in [-1,0,1] for xx in [-1,0,1] if yy or xx]) for x in planes]
        bavg=sum(x.astype(np.int32) for x in centre[:3])/3
        selected=(np.minimum.reduce(centre[:3])>1108)&(np.maximum.reduce(centre[3:])<1080)&(np.maximum.reduce(centre[3:])<bavg-50)
        both=(centre[3]==maxima[3])&(centre[4]==maxima[4])
        bias_all=(centre[0]>maxima[0])&(centre[1]>maxima[1])&(centre[2]>maxima[2])
        row=dict(channel=label,compared_pixels=int(selected.size),selected_sites=int(selected.sum()),
            selected_both_dark_equal_max=int((selected&both).sum()),selected_all_bias_strict_max=int((selected&bias_all).sum()),
            files=[],examples=[])
        for name,c,m in zip(names,centre,maxima):
            row['files'].append(dict(name=name,strict_local_max=int((c>m).sum()),equal_neighbor_max=int((c==m).sum()),
                strict_local_max_fraction=float(np.mean(c>m)),equal_neighbor_max_fraction=float(np.mean(c==m)),
                selected_equal_max=int((selected&(c==m)).sum()),selected_greater_max=int((selected&(c>m)).sum())))
        ys,xs=np.nonzero(selected)
        for i in np.argsort(bavg[ys,xs])[::-1][:8]:
            y,x=int(ys[i]),int(xs[i]);row['examples'].append(dict(raw_y=8+2*(y+1)+dy,raw_x=8+2*(x+1)+dx,
                centres=[int(c[y,x]) for c in centre],neighbor_maxima=[int(m[y,x]) for m in maxima],
                same_cfa_patches=[q[y:y+3,x:x+3].tolist() for q in planes]))
        report['phases'].append(row);report['total_selected']+=row['selected_sites']
        report['selected_dark_both_equal_max']+=row['selected_both_dark_equal_max']
        report['selected_bias_all_strict_max']+=row['selected_all_bias_strict_max']
        print(label,'selected',row['selected_sites'],'both_equal',row['selected_both_dark_equal_max'],
              [(r['name'],r['strict_local_max'],r['equal_neighbor_max']) for r in row['files']],flush=True)
    assert all(file_sha(a.input/n)==digest for n,digest in hashes.items())
    report['source_unchanged']=True;report['ok']=True
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')

if __name__=='__main__':main()

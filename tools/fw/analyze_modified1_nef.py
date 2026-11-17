"""First physical candidate NEFs: locked-site and stored-code comparisons.

Inputs are read-only. No demosaic, postprocess, black subtraction, simulated
ISP or edited NEF is used. The 112 sites were frozen before these captures.
Two f/1.8 darks are the primary group; the f/20 dark is a separate check.
"""
from pathlib import Path
import argparse,collections,hashlib,json,math,traceback
import numpy as np
import rawpy
from audit_nef import file_sha,stats,tiff_inventory

ROOT=Path(__file__).resolve().parents[2]
OLD=ROOT/'samples/11.9';NEW=ROOT/'samples/11.9_modified1'
LOCK=ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json'
PHASES=[('R',0,0),('G1',0,1),('G2',1,0),('B',1,1)]
KR=[(dy,dx) for dy in (-2,0,2) for dx in (-2,0,2) if dy or dx]
KG=[(-2,0),(2,0),(0,-2),(0,2),(-1,-1),(-1,1),(1,-1),(1,1)]
GROUPS={'stock_bias':[4851,4852,4853],'stock_dark':[4854,4855],
        'modified_bias':[4857,4858,4859],'modified_dark':[4860,4861],
        'modified_dark_f20':[4862],'modified_light':[4856]}

def need(value,message):
    if not value:raise ValueError(message)
def hist(v):
    k,c=np.unique(v,return_counts=True);return {str(int(x)):int(n) for x,n in zip(k,c)}
def maximum(a,y,x):
    rb=np.maximum.reduce([a[y+dy,x+dx] for dy,dx in KR])
    g=np.maximum.reduce([a[y+dy,x+dx] for dy,dx in KG])
    return np.where((y+x)%2,g,rb).astype(np.int32)
def simple(v):
    return dict(mean=float(np.mean(v,dtype=np.float64)),median=float(np.median(v)),
                minimum=float(np.min(v)),maximum=float(np.max(v)))
def pair_noise(a,b):
    d=a.astype(np.int32)-b.astype(np.int32)
    q=np.percentile(d,[15.8655,84.1345])
    return dict(mean_delta=float(d.mean(dtype=np.float64)),std_over_sqrt2=float(d.std(dtype=np.float64)/math.sqrt(2)),
                central68_over_sqrt2=float((q[1]-q[0])/(2*math.sqrt(2))))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--metadata',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    locked=json.loads(LOCK.read_text());need(len(locked['targets'])==112,'Locked cohort changed')
    oldmeta=json.loads((ROOT/'analysis/real-nef-2026-11-09/bias-dark/result.json').read_text())['files']
    meta={Path(m['metadata']['SourceFile']).name:m['metadata'] for m in oldmeta}
    meta.update({m['System:FileName']:m for m in json.loads(a.metadata.read_text(encoding='utf8'))})
    y=np.array([t['y'] for t in locked['targets']]);x=np.array([t['x'] for t in locked['targets']])
    ids=list(range(4851,4863));images={};frame={};before={};all_hist=[]
    report=dict(ok=False,scope=__doc__,firmware_provenance='User confirmed 01_TEST/EG162080.BIN installed; NEF version remains 3.80 and alone cannot attest firmware bytes.',
        capture_confirmation='User confirmed 4857-4859 capped bias, 4860-4862 capped 5s dark, 4856 ordinary scene; f/20 intentionally changed.',
        groups=GROUPS,locked_targets_sha256=file_sha(LOCK),coordinates='zero-based full stored 6064x4040 RGGB',
        primary_dark_selection='4860 and 4861; 4862 f/20 separately',files=[],locked_target_results={},shifted_controls=[],pairs=[])
    try:
        for ident in ids:
            path=(OLD if ident<=4855 else NEW)/f'Z61_{ident}.NEF';m=meta[path.name]
            before[ident]=file_sha(path)
            if ident<=4855:need(before[ident]==locked['source_sha256'][str(path.relative_to(ROOT))],'Stock sample changed')
            need(str(m['Nikon:SerialNumber'])=='8006677','Different camera body')
            need(m['ExifIFD:ISO']==1600 and m['Nikon:NEFCompression']=='Lossless','Unsupported capture settings')
            kind=next(g for g,n in GROUPS.items() if ident in n)
            if 'bias' in kind:need(m['ExifIFD:ExposureTime']=='1/8000','Unexpected bias time')
            elif 'dark' in kind:need(m['ExifIFD:ExposureTime']==5,'Unexpected dark time')
            need(m['Nikon:NoiseReduction']==m['Nikon:HighISONoiseReduction']=='Off','NR setting differs')
            with rawpy.imread(str(path)) as r:
                raw=r.raw_image.copy();s=r.sizes
                need(raw.shape==(4040,6064),'Wrong shape')
                need((s.crop_left_margin,s.crop_top_margin,s.crop_width,s.crop_height)==(8,8,6048,4024),'Crop differs')
                need(r.raw_pattern.tolist()==[[0,1],[3,2]],'CFA differs')
                need(r.black_level_per_channel==[1008]*4 and r.white_level==16383,'Black/white differs')
                row=dict(id=ident,name=path.name,path=str(path),group=kind,sha256=before[ident],bytes=path.stat().st_size,
                    metadata=m,raw_shape=list(raw.shape),sizes=s._asdict(),cfa=r.raw_pattern.tolist(),
                    black_level=list(r.black_level_per_channel),white_level=int(r.white_level),
                    stored_pixels_sha256=hashlib.sha256(raw.astype('<u2',copy=False).tobytes()).hexdigest(),
                    tiff=tiff_inventory(path),phases=[])
            need(np.max(raw)<=16383,'Out-of-range stored code')
            channels=[]
            for name,dy,dx in PHASES:
                v=raw[8+dy:4032:2,8+dx:6056:2];h=np.bincount(v.ravel(),minlength=65536).astype(np.uint32)
                q=stats(v,1008);q.update(channel=name,white_count=int(h[16383]))
                row['phases'].append(q);channels.append(h)
            images[ident]=raw;frame[ident]=row;report['files'].append(row);all_hist.append(channels)
            print(json.dumps(dict(file=path.name,group=kind,mean=float(np.mean([z['mean'] for z in row['phases']])),
                dark_fnumber=m.get('ExifIFD:FNumber'),pixels_sha256=row['stored_pixels_sha256'])),flush=True)
        raw_patches=np.stack([images[i][y[:,None,None]+np.arange(-4,5)[None,:,None],
                                          x[:,None,None]+np.arange(-4,5)[None,None,:]] for i in ids])
        point_arrays={}
        for group,seq in GROUPS.items():
            centre=np.stack([images[i][y,x].astype(np.int32) for i in seq],axis=1)
            mx=np.stack([maximum(images[i],y,x) for i in seq],axis=1)
            d=centre-mx;fit=(d>=0)&(d<=56)&(d%8==0)
            point_arrays[group]=(centre,mx,d,fit)
            report['locked_target_results'][group]=dict(n=112,frames=seq,frame_fit_counts=fit.sum(axis=0).tolist(),
                all_frames_fit=int(fit.all(axis=1).sum()),all_frames_exact_max=int((d==0).all(axis=1).sum()),
                all_frames_above_max56=int((d>56).all(axis=1).sum()),delta_histogram=hist(d),
                delta_summary=simple(d),centre_summary=simple(centre),remainder_mod8_histogram=hist(d%8),
                per_phase={name:dict(sites=int(((y%2==dy)&(x%2==dx)).sum()),
                    all_fit=int(fit[(y%2==dy)&(x%2==dx)].all(axis=1).sum())) for name,dy,dx in PHASES})
            for shift in (-32,32):
                q=np.stack([images[i][y,x+shift].astype(np.int32)-maximum(images[i],y,x+shift) for i in seq],axis=1)
                f=(q>=0)&(q<=56)&(q%8==0)
                report['shifted_controls'].append(dict(group=group,shift_x=shift,sites=112,
                    per_frame_fit=f.sum(axis=0).tolist(),all_fit=int(f.all(axis=1).sum()),delta_summary=simple(q)))
        for j,t in enumerate(locked['targets']):
            need(point_arrays['stock_dark'][0][j].tolist()==t['dark_centres'],'Locked value does not reproduce')
            need(point_arrays['stock_dark'][1][j].tolist()==t['nearest_color_max'],'Locked neighborhood does not reproduce')
        report['targets']=[dict(x=int(x[j]),y=int(y[j]),phase=locked['targets'][j]['phase'],
            groups={g:dict(centres=v[0][j].tolist(),max8=v[1][j].tolist(),delta=v[2][j].tolist(),fit=v[3][j].tolist())
                    for g,v in point_arrays.items()}) for j in range(112)]
        report['group_signal']={}
        for prefix in ('stock','modified'):
            bseq=GROUPS[prefix+'_bias'];dseq=GROUPS[prefix+'_dark'];channels=[]
            for name,dy,dx in PHASES:
                bs=[images[i][8+dy:4032:2,8+dx:6056:2] for i in bseq]
                ds=[images[i][8+dy:4032:2,8+dx:6056:2] for i in dseq]
                bsum=sum(v.astype(np.int32) for v in bs);dsum=sum(v.astype(np.int32) for v in ds)
                delta6=3*dsum-2*bsum
                reduced=(np.minimum.reduce(bs)>1108)&(np.maximum.reduce(ds)<1080)&(3*np.maximum.reduce(ds).astype(np.int32)<bsum-150)
                channels.append(dict(channel=name,bias_mean=float(bsum.mean(dtype=np.float64)/3),
                    dark_mean=float(dsum.mean(dtype=np.float64)/2),dark_minus_bias=float(delta6.mean(dtype=np.float64)/6),
                    bias_noise=pair_noise(bs[0],bs[1]),dark_noise=pair_noise(ds[0],ds[1]),
                    original_selection_rule_sites=int(reduced.sum())))
            report['group_signal'][prefix]=dict(phases=channels,
                overall_dark_minus_bias=float(np.mean([v['dark_minus_bias'] for v in channels])),
                original_selection_rule_sites=sum(v['original_selection_rule_sites'] for v in channels))
        old=point_arrays['stock_dark'][0].mean(axis=1);new=point_arrays['modified_dark'][0].mean(axis=1)
        bnew=point_arrays['modified_bias'][0].mean(axis=1)
        report['target_change']=dict(mean_dark_increase=simple(new-old),
            modified_dark_minus_modified_bias=simple(new-bnew),
            increased_over_50=int((new-old>50).sum()),increased_over_100=int((new-old>100).sum()),
            decreased_over_50=int((new-old< -50).sum()))
        for f in report['files']:need(file_sha(Path(f['path']))==f['sha256'],'Source changed during read')
        np.savez_compressed(a.output/'arrays.npz',ids=ids,histograms=np.asarray(all_hist),
                            target_x=x,target_y=y,target_patches_9x9=raw_patches)
        report.update(ok=True,sources_unchanged=True,rawpy=rawpy.__version__,libraw=list(rawpy.libraw_version),numpy=np.__version__)
    except Exception:report['error']=traceback.format_exc();raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
        for name in ('analyze_modified1_nef.py','audit_nef.py'):(a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    print(json.dumps(dict(ok=report['ok'],locked_target_results=report['locked_target_results'],
                         target_change=report['target_change'],group_signal=report['group_signal']),indent=2))
if __name__=='__main__':main()

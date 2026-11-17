"""Read-only CFA comparison of two earlier A and two new B physical flats.

Exposure settings match; placement/focus may have changed. Descriptive changes
are not firmware-only causal estimates. No demosaic or lens metadata application.
"""
from pathlib import Path
import argparse,datetime,json
import numpy as np
import rawpy
import scipy
from scipy.ndimage import gaussian_filter
from audit_nef import file_sha
from analyze_modified1_flats import (PHASES,bin_raw,register,ratios,normalize,centre,radial,stats)

ROOT=Path(__file__).resolve().parents[2]
ROUND=ROOT/'analysis/modified2-flat-2026-11-09'


def need(v,msg):
    if not v:raise ValueError(msg)


def read(p):return json.loads(p.read_text(encoding='utf8'))


def finite_stats(v):return stats(np.asarray(v)[np.isfinite(v)])


def profile_stats(v,r):
    values=v[(r>=.15)&(r<=.9)]
    return dict(min=float(values.min()),max=float(values.max()),peak_to_peak=float(np.ptp(values)),
                rms=float(np.sqrt(np.mean(values**2))))


def coordinates(size,shape):
    yy,xx=np.mgrid[:shape[0],:shape[1]]
    x=xx*size+(size-1)/2;y=yy*size+(size-1)/2
    rr=np.hypot(x-(6048-1)/2,y-(4024-1)/2)/2012
    theta=(np.arctan2(y-(4024-1)/2,x-(6048-1)/2)+2*np.pi)%(2*np.pi)
    return rr,theta


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    inputs=read(ROUND/'inputs.json');files=inputs['files'];need(len(files)==4,'Four frames required')
    report=dict(ok=False,scope=__doc__,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        input_contract_sha256=file_sha(ROUND/'inputs.json'),conditions=inputs['design'],
        user_confirmation=inputs['user_confirmation'],versions=dict(rawpy=rawpy.__version__,libraw=list(rawpy.libraw_version),numpy=np.__version__,scipy=scipy.__version__),
        method=dict(bin=16,float_mean=True,phase_alignment='bilinear +/-0.5 sensor pixel to common block centre',
            normalization='each frame/ratio divided by its central-third rectangular mean',
            radius_unit='2012 sensor pixels; geometric centre only',radial_bin=.02,
            descriptive_radius_interval=[.15,.9],signal_unit='saved DN minus metadata black',
            no_postprocess=True,no_warp_or_image_registration=True,no_formal_p_value=True),
        files=[],scalar_block_checks=0,scale_controls=[],black_controls=[],within_group=[],cross_pairs=[])
    maps={size:[] for size in (16,32,64)}
    for row in files:
        path=Path(row['path']);need(file_sha(path)==row['sha256'],'Input changed')
        with rawpy.imread(str(path)) as r:
            raw=r.raw_image
            need(raw.shape==(4040,6064) and r.raw_pattern.tolist()==[[0,1],[3,2]],'Geometry/CFA changed')
            need(r.black_level_per_channel==[1008]*4 and r.white_level==16383,'Black/white level changed')
            for size in maps:maps[size].append(bin_raw(raw,size))
            active=raw[8:4032,8:6056];phase=[]
            for k,(name,dy,dx) in enumerate(PHASES):
                plane=active[dy::2,dx::2]
                phase.append(dict(name=name,pixels=int(plane.size),min=int(plane.min()),max=int(plane.max()),
                    zero=int(np.count_nonzero(plane==0)),saturated=int(np.count_nonzero(plane>=16383)),
                    mean_signal=float(plane.mean(dtype=np.float64)-1008),
                    centre_mean_signal=float(centre(maps[16][-1][k]).mean()-1008),
                    percentiles_signal=(np.percentile(plane,[1,50,99,99.9])-1008).tolist()))
            # Independent scalar summation, not the reshape/mean implementation.
            for by,bx in ((0,0),(1,1),(50,70),(120,180),(200,300),(250,377)):
                for k,(_,dy,dx) in enumerate(PHASES):
                    s=sum(int(raw[8+by*16+y,8+bx*16+x]) for y in range(dy,16,2) for x in range(dx,16,2))
                    need(maps[16][-1][k,by,bx]==s/64,'Block sum mismatch')
                    report['scalar_block_checks']+=1
        report['files'].append(dict(id=row['id'],group=row['group'],path=str(path),sha256=row['sha256'],
            capture_time=row['capture_time'],phases=phase))
    codes=np.stack(maps[16]);signals=codes-1008
    aligned=np.stack([register(v) for v in signals]);rats=np.stack([ratios(v) for v in aligned])
    unreg=np.stack([ratios(v) for v in signals])
    green=aligned[:,1:3].mean(axis=1);gn=normalize(green)
    rr,theta=coordinates(16,green.shape[1:]);core=(rr>=.15)&(rr<=.9)
    edges=np.arange(0,1.821,.02);radii=(edges[:-1]+edges[1:])/2
    profiles=np.stack([[radial(100*(v-1),rr,edges)[0] for v in frame] for frame in rats])
    sectors=np.stack([[[radial(100*(v-1),rr,edges,(theta>=s*np.pi/4)&(theta<(s+1)*np.pi/4))[0]
                       for s in range(8)] for v in frame] for frame in rats])
    gprofiles=np.stack([radial(v,rr,edges)[0] for v in gn])
    groups_r=np.stack([rats[:2].mean(axis=0),rats[2:].mean(axis=0)])
    groups_g=np.stack([gn[:2].mean(axis=0),gn[2:].mean(axis=0)])
    difference=100*(groups_r[1]/groups_r[0]-1)
    gdiff=100*(groups_g[1]/groups_g[0]-1)
    report['radial_profiles']=[dict(id=row['id'],metrics={name:profile_stats(profiles[j,k],radii) for k,name in enumerate(('R/G','B/G','G1/G2'))}) for j,row in enumerate(files)]
    report['group_radial_metrics']=[dict(group=label,metrics={name:profile_stats(profiles[sl,k].mean(axis=0),radii)
        for k,name in enumerate(('R/G','B/G','G1/G2'))}) for label,sl in (('A_modified1',slice(0,2)),('B_modified2',slice(2,4)))]
    report['ratio_group_difference_percent']={name:finite_stats(difference[k][core]) for k,name in enumerate(('R/G','B/G','G1/G2'))}
    report['green_group_difference_percent']=finite_stats(gdiff[core])
    report['centre_signal_by_phase']=np.array([[v['centre_mean_signal'] for v in r['phases']] for r in report['files']]).tolist()
    report['centre_green_signals']=centre(green).mean(axis=(1,2)).tolist()
    report['centre_B_over_A_by_phase']=(np.array(report['centre_signal_by_phase'])[2:].mean(axis=0)/np.array(report['centre_signal_by_phase'])[:2].mean(axis=0)).tolist()
    for first,second in ((0,1),(2,3)):
        report['within_group'].append(dict(ids=[files[first]['id'],files[second]['id']],
            normalized_green_difference_percent=finite_stats(100*(gn[second][core]/gn[first][core]-1)),
            ratios={name:finite_stats(100*(rats[second,k][core]/rats[first,k][core]-1)) for k,name in enumerate(('R/G','B/G','G1/G2'))},
            radial_correlation={name:float(np.corrcoef(profiles[first,k,(radii>=.15)&(radii<=.9)],profiles[second,k,(radii>=.15)&(radii<=.9)])[0,1]) for k,name in enumerate(('R/G','B/G','G1/G2'))}))
    for old in (0,1):
        for new in (2,3):
            report['cross_pairs'].append(dict(ids=[files[old]['id'],files[new]['id']],
                centre_signal_ratio=(np.array(report['centre_signal_by_phase'][new])/np.array(report['centre_signal_by_phase'][old])).tolist(),
                ratios={name:finite_stats(100*(rats[new,k][core]/rats[old,k][core]-1)) for k,name in enumerate(('R/G','B/G','G1/G2'))}))
    for size in (32,64):
        arr=np.stack([ratios(register(v-1008,size)) for v in maps[size]])
        radius,_=coordinates(size,arr.shape[-2:]);p=np.stack([[radial(100*(v-1),radius,edges)[0] for v in frame] for frame in arr])
        report['scale_controls'].append(dict(bin=size,radial_peak_to_peak={str(files[j]['id']):{
            name:float(np.nanmax(p[j,k,(radii>=.15)&(radii<=.9)])-np.nanmin(p[j,k,(radii>=.15)&(radii<=.9)]))
            for k,name in enumerate(('R/G','B/G','G1/G2'))} for j in range(4)}))
    for black in (1004,1012):
        other=np.stack([ratios(register(v-black)) for v in codes])
        report['black_controls'].append(dict(black=black,delta_from_1008_percent={str(files[j]['id']):{
            name:finite_stats(100*(other[j,k][core]/rats[j,k][core]-1)) for k,name in enumerate(('R/G','B/G','G1/G2'))} for j in range(4)}))
    report['phase_alignment_control']={str(files[j]['id']):{name:finite_stats(100*(rats[j,k][core]/unreg[j,k][core]-1))
        for k,name in enumerate(('R/G','B/G','G1/G2'))} for j in range(4)}
    # Display-only local residuals: no row/column subtraction or residual-based
    # declaration of ring disappearance. Different scales are all retained.
    hp=np.stack([[[100*(v/gaussian_filter(v,sigma=s,mode='reflect')-1) for v in frame] for frame in rats] for s in (3,6,12)])
    oldmaps=np.load(ROOT/'analysis/modified1-flat-2026-11-09/spatial/maps.npz')
    need(np.array_equal(codes[:2],oldmaps['codes']),'Frozen A block means not reproduced')
    need(np.array_equal(rats[:2],oldmaps['ratios']),'Frozen A ratios not reproduced')
    report['frozen_A_arrays_exactly_reproduced']=True
    np.savez_compressed(a.output/'maps.npz',ids=np.array([r['id'] for r in files]),codes=codes,
        signals=signals,aligned=aligned,ratios=rats,unregistered_ratios=unreg,green=green,green_normalized=gn,
        radius=rr,radial_edges=edges,radial_centres=radii,profiles=profiles,sectors=sectors,green_profiles=gprofiles,
        group_ratios=groups_r,group_green=groups_g,ratio_group_difference_percent=difference,green_group_difference_percent=gdiff,
        highpass_percent=hp)
    need(all(file_sha(r['path'])==r['sha256'] for r in files),'Source changed after analysis')
    report['ok']=True
    (a.output/'result.json').write_text(json.dumps(report,indent=2,ensure_ascii=False,allow_nan=False),encoding='utf8')
    for name in (Path(__file__).name,'analyze_modified1_flats.py','audit_nef.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    print(json.dumps(dict(ok=True,centre_green=report['centre_green_signals'],radial=report['radial_profiles'],
        green_difference=report['green_group_difference_percent'],scalar_block_checks=report['scalar_block_checks']),indent=2))


if __name__=='__main__':main()

"""Compare real modified2/modified3 flats in undemosaiced, uncorrected CFA codes.

Placement/focus may differ. Metrics describe these images, not a firmware-only
causal estimate. Earlier modified2 repeats provide context, not paired controls.
"""
import itertools, json
from pathlib import Path
import numpy as np
import rawpy, scipy
from scipy.ndimage import gaussian_filter
from audit_nef import file_sha
from modified3_study_common import ROOT,ROUND,GROUPS,read,write,need
from analyze_modified1_flats import PHASES,bin_raw,register,ratios,normalize,centre,radial,stats
from analyze_modified2_flats import coordinates,profile_stats

RN=('R/G','B/G','G1/G2')

def main():
    out=ROUND/'flats';out.mkdir(exist_ok=False)
    inputs=read(ROUND/'inputs.json');lookup={r['id']:r for r in inputs['files']}
    names=('modified2_flat','modified3_flat','modified2_earlier_flat')
    ids=[i for g in names for i in GROUPS[g]]
    group_indices=[np.array([ids.index(i) for i in GROUPS[g]]) for g in names]
    arrays={size:[] for size in (16,32,64)}
    result=dict(ok=False,scope=__doc__,inputs_sha256=file_sha(ROUND/'inputs.json'),ids=ids,
                groups={g:GROUPS[g] for g in names},setup_confirmation=inputs['setup_confirmation'],
                versions=dict(rawpy=rawpy.__version__,libraw=list(rawpy.libraw_version),numpy=np.__version__,scipy=scipy.__version__),
                method=dict(bin_size=16,statistic='float64 mean of 64 CFA samples per colour phase',black=1008,
                  active_crop=[8,8,6048,4024],map_area=[6048,4016],bottom_rows_excluded_from_maps=8,
                  normalization='per-frame per-ratio central-third rectangular mean',phase_alignment='bilinear +/- 0.5 sensor pixel',
                  centre='fixed geometric centre',radius_unit=2012,radial_bin=.02,metrics_radius_interval=[.15,.9],
                  main_profiles_unfiltered=True,postprocess=False,warped_between_frames=False),
                files=[],scalar_checks=0,within_group=[],scale_controls=[],black_controls=[])
    for ident in ids:
        row=lookup[ident];path=Path(row['path']);need(file_sha(path)==row['sha256'],'Source changed')
        with rawpy.imread(str(path)) as raw:
            v=raw.raw_image
            need(v.shape==(4040,6064) and raw.raw_pattern.tolist()==[[0,1],[3,2]],'Geometry/CFA changed')
            need(raw.black_level_per_channel==[1008]*4 and raw.white_level==16383,'Black/white changed')
            for size in arrays:arrays[size].append(bin_raw(v,size))
            phases=[]
            for k,(name,dy,dx) in enumerate(PHASES):
                plane=v[8+dy:4032:2,8+dx:6056:2]
                phases.append(dict(name=name,pixels=int(plane.size),min=int(plane.min()),max=int(plane.max()),
                  saturated=int((plane>=16383).sum()),zero=int((plane==0).sum()),below_black=int((plane<1008).sum()),
                  mean_signal=float(plane.mean(dtype=np.float64)-1008),centre_signal=float(centre(arrays[16][-1][k]).mean()-1008)))
            for by,bx in ((0,0),(1,1),(50,70),(120,180),(200,300),(250,377)):
                for k,(_,dy,dx) in enumerate(PHASES):
                    total=sum(int(v[8+by*16+y,8+bx*16+x]) for y in range(dy,16,2) for x in range(dx,16,2))
                    need(arrays[16][-1][k,by,bx]==total/64,'Scalar block mismatch')
                    result['scalar_checks']+=1
        result['files'].append(dict(id=ident,group=row['group'],path=str(path),sha256=row['sha256'],phases=phases))
    codes=np.stack(arrays[16]);signals=codes-1008
    aligned=np.stack([register(v) for v in signals]);rs=np.stack([ratios(v) for v in aligned])
    unregistered=np.stack([ratios(v) for v in signals]);green=aligned[:,1:3].mean(axis=1);gn=normalize(green)
    rr,theta=coordinates(16,green.shape[-2:]);core=(rr>=.15)&(rr<=.9)
    edges=np.arange(0,1.821,.02);r=(edges[1:]+edges[:-1])/2;interval=(r>=.15)&(r<=.9)
    profiles=np.stack([[radial(100*(v-1),rr,edges)[0] for v in frame] for frame in rs])
    sectors=np.stack([[[radial(100*(v-1),rr,edges,(theta>=s*np.pi/4)&(theta<(s+1)*np.pi/4))[0]
                       for s in range(8)] for v in frame] for frame in rs])
    gr=np.stack([rs[idx].mean(axis=0) for idx in group_indices]);gg=np.stack([gn[idx].mean(axis=0) for idx in group_indices])
    gp=np.stack([profiles[idx].mean(axis=0) for idx in group_indices])
    difference=100*(gr[1]/gr[0]-1);gdiff=100*(gg[1]/gg[0]-1)
    result['frame_radial']=[dict(id=ident,metrics={name:profile_stats(profiles[j,k],r) for k,name in enumerate(RN)}) for j,ident in enumerate(ids)]
    result['group_radial']=[dict(group=g,metrics={name:profile_stats(gp[j,k],r) for k,name in enumerate(RN)}) for j,g in enumerate(names)]
    result['centre_green_signals']=centre(green).mean(axis=(1,2)).tolist()
    result['centre_signal_by_phase']=[[p['centre_signal'] for p in f['phases']] for f in result['files']]
    result['ratio_group_difference_percent']={name:stats(difference[k][core]) for k,name in enumerate(RN)}
    result['green_group_difference_percent']=stats(gdiff[core])
    result['relative_peak_to_peak_change_percent']={name:float(100*(np.ptp(gp[1,k,interval])/np.ptp(gp[0,k,interval])-1)) for k,name in enumerate(RN)}
    result['profile_rms_difference_pp']={name:float(np.sqrt(np.mean((gp[1,k,interval]-gp[0,k,interval])**2))) for k,name in enumerate(RN)}
    result['phase_alignment_delta_percent']={str(ident):{name:stats(100*(rs[j,k][core]/unregistered[j,k][core]-1)) for k,name in enumerate(RN)} for j,ident in enumerate(ids)}
    for g,idx in zip(names,group_indices):
        for aa,bb in itertools.combinations(idx,2):
            result['within_group'].append(dict(group=g,ids=[ids[aa],ids[bb]],green_percent=stats(100*(gn[bb][core]/gn[aa][core]-1)),
              ratios_percent={name:stats(100*(rs[bb,k][core]/rs[aa,k][core]-1)) for k,name in enumerate(RN)},
              profile_rms_difference_pp={name:float(np.sqrt(np.mean((profiles[bb,k,interval]-profiles[aa,k,interval])**2))) for k,name in enumerate(RN)}))
    for size in (32,64):
        ratios_other=np.stack([ratios(register(v-1008,size)) for v in arrays[size]])
        radius,_=coordinates(size,ratios_other.shape[-2:])
        pp=np.stack([[radial(100*(v-1),radius,edges)[0] for v in frame] for frame in ratios_other])
        result['scale_controls'].append(dict(bin_size=size,group_peak_to_peak_pp={g:{name:float(np.nanmax(pp[idx,k][:,interval].mean(axis=0))-np.nanmin(pp[idx,k][:,interval].mean(axis=0)))
                        for k,name in enumerate(RN)} for g,idx in zip(names,group_indices)}))
    for black in (1004,1012):
        other=np.stack([ratios(register(v-black)) for v in codes])
        result['black_controls'].append(dict(black=black,delta_percent={str(ident):{name:stats(100*(other[j,k][core]/rs[j,k][core]-1)) for k,name in enumerate(RN)} for j,ident in enumerate(ids)}))
    # Secondary fine-structure diagnostics. No detrending is applied to the main result.
    hp=np.stack([[[100*(v/gaussian_filter(v,sigma=s,mode='reflect')-1) for v in frame] for frame in rs] for s in (3,6,12)])
    result['local_residual_controls']=[dict(sigma_sensor_pixels=s*16,group_rms_percent={g:{name:float(np.sqrt(np.mean(hp[z,idx,k][:,core]**2))) for k,name in enumerate(RN)} for g,idx in zip(names,group_indices)}) for z,s in enumerate((3,6,12))]
    old=np.load(ROOT/'analysis/modified2-flat-2026-11-09/cfa-comparison/maps.npz')
    need(np.array_equal(codes[-2:],old['codes'][2:4]),'Earlier modified2 codes not reproduced')
    need(np.array_equal(rs[-2:],old['ratios'][2:4]),'Earlier modified2 ratios not reproduced')
    result['earlier_frozen_arrays_exact']=True
    np.savez_compressed(out/'maps.npz',ids=ids,codes=codes,signals=signals,aligned=aligned,ratios=rs,
        unregistered_ratios=unregistered,green=green,green_normalized=gn,radius=rr,radial_centres=r,
        profiles=profiles,sectors=sectors,group_ratios=gr,group_green=gg,group_profiles=gp,
        ratio_difference_percent=difference,green_difference_percent=gdiff,local_residual_percent=hp)
    need(all(file_sha(lookup[i]['path'])==lookup[i]['sha256'] for i in ids),'Source changed during analysis')
    result['ok']=True;write(out/'result.json',result)
    print(json.dumps(dict(ok=True,groups=result['group_radial'],centres=result['centre_green_signals'],
                         changes=result['relative_peak_to_peak_change_percent'],scalar_checks=result['scalar_checks']),indent=2))

if __name__=='__main__':
    main()

"""Regress frozen 112 sites on real modified2 and confirmed modified3 darks.

This is a local suppression regression, not a full dark-current recovery claim.
All tests use stored codes without black subtraction or demosaicing.
"""
import hashlib, json
from pathlib import Path
import numpy as np
import rawpy
from audit_nef import file_sha, stats
from modified3_study_common import ROOT,ROUND,read,write,need
from analyze_modified1_nef import maximum,simple,PHASES,KR,KG

def main():
    out=ROUND/'darks-v2';out.mkdir(exist_ok=False)
    lockpath=ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json';lock=read(lockpath)
    need(len(lock['targets'])==112,'Locked selection changed')
    need(lock['kernel_R_B']==[list(v) for v in KR] and lock['kernel_G1_G2']==[list(v) for v in KG],'Kernel changed')
    oldpath=ROOT/'analysis/modified1-nef-2026-11-09/pixels-v2/result.json';old=read(oldpath)
    inputs=read(ROUND/'inputs.json');lookup={r['id']:r for r in inputs['files']}
    for row in old['files']:
        if row['id'] in (4854,4855,4860,4861):lookup[row['id']]=dict(row,audit=row)
    groups={'stock_dark':[4854,4855],'modified1_dark':[4860,4861],
            'modified2_dark':[4874,4875,4876],'modified3_dark':[4890,4891,4892]}
    ids=[i for seq in groups.values() for i in seq]
    y=np.array([t['y'] for t in lock['targets']]);x=np.array([t['x'] for t in lock['targets']])
    centres=[];maxima=[];patches=[];histograms=[];shifted={-32:[],32:[]}
    result=dict(ok=False,scope=__doc__,locked_targets_sha256=file_sha(lockpath),prior_result_sha256=file_sha(oldpath),
        inputs_sha256=file_sha(ROUND/'inputs.json'),groups=groups,files=[],locked_results={},shifted_controls=[],
        coordinates='zero-based full stored 6064x4040 CFA',formula='centre - same-colour max8 in {0,8,...,56}',
        no_new_bias=True,temperature_controlled=False,independent_exposures=True)
    for ident in ids:
        row=lookup[ident];path=Path(row['path']);need(file_sha(path)==row['sha256'],'Input changed')
        m=row['metadata'];need(str(m['Nikon:SerialNumber'])=='8006677','Different body')
        need(m['ExifIFD:ISO']==1600 and m['ExifIFD:ExposureTime']==5,'Unmatched dark ISO/time')
        # The frozen stock reference deliberately included a capped f/22 frame.
        # The primary modified2/modified3 comparison is f/1.8 throughout.
        need(m['ExifIFD:FNumber']==(22.0 if ident==4855 else 1.8),'Unexpected aperture')
        need(m['Nikon:NoiseReduction']==m['Nikon:HighISONoiseReduction']=='Off','NR changed')
        with rawpy.imread(str(path)) as raw:
            v=raw.raw_image
            need(v.shape==(4040,6064) and raw.raw_pattern.tolist()==[[0,1],[3,2]],'Geometry/CFA changed')
            need(raw.black_level_per_channel==[1008]*4 and raw.white_level==16383,'Black/white changed')
            digest=hashlib.sha256(v.astype('<u2',copy=False).tobytes()).hexdigest()
            need(digest==row['audit']['stored_pixels_sha256'],'Saved code hash changed')
            cc=v[y,x].astype(np.int32);mm=maximum(v,y,x);centres.append(cc);maxima.append(mm)
            patches.append(v[y[:,None,None]+np.arange(-4,5)[None,:,None],x[:,None,None]+np.arange(-4,5)[None,None,:]].copy())
            for shift in shifted:shifted[shift].append(v[y,x+shift].astype(np.int32)-maximum(v,y,x+shift))
            phases=[];hh=[]
            for name,dy,dx in PHASES:
                plane=v[8+dy:4032:2,8+dx:6056:2]
                h=np.bincount(plane.ravel(),minlength=16384);hh.append(h)
                q=stats(plane,1008);q.update(name=name,saturated=int(h[16383]),mean_minus_metadata_black=q['mean']-1008)
                phases.append(q)
            histograms.append(hh)
        result['files'].append(dict(id=ident,path=str(path),sha256=row['sha256'],stored_pixels_sha256=digest,phases=phases,fnumber=m['ExifIFD:FNumber'],
          target_saturated=int((cc==16383).sum()),target_mean=float(cc.mean()),target_median=float(np.median(cc))))
    cc=np.stack(centres);mm=np.stack(maxima);delta=cc-mm;fit=(delta>=0)&(delta<=56)&(delta%8==0)
    for j,ident in enumerate((4854,4855)):
        need(np.array_equal(cc[j],[t['dark_centres'][j] for t in lock['targets']]),'Frozen stock centres differ')
        need(np.array_equal(mm[j],[t['nearest_color_max'][j] for t in lock['targets']]),'Frozen stock maxima differ')
    result['stock_locked_values_exact']=True
    for group,seq in groups.items():
        idx=[ids.index(i) for i in seq];ff=fit[idx];dd=delta[idx];values=cc[idx]
        result['locked_results'][group]=dict(ids=seq,sites=112,per_frame_fit=ff.sum(axis=1).tolist(),
          all_frames_fit=int(ff.all(axis=0).sum()),per_frame_exact_max=(dd==0).sum(axis=1).tolist(),
          all_frames_exact_max=int((dd==0).all(axis=0).sum()),
          per_frame_above_max56=(dd>56).sum(axis=1).tolist(),all_frames_above_max56=int((dd>56).all(axis=0).sum()),
          saturated_sites_per_frame=(values==16383).sum(axis=1).tolist(),
          centre_summary=simple(values),delta_summary=simple(dd))
        for shift,arr in shifted.items():
            vv=np.stack(arr)[idx];ss=(vv>=0)&(vv<=56)&(vv%8==0)
            result['shifted_controls'].append(dict(group=group,shift_x=shift,per_frame_fit=ss.sum(axis=1).tolist(),all_frames_fit=int(ss.all(axis=0).sum())))
    stock=cc[[ids.index(i) for i in groups['stock_dark']]].mean(axis=0)
    a=cc[[ids.index(i) for i in groups['modified2_dark']]].mean(axis=0)
    b=cc[[ids.index(i) for i in groups['modified3_dark']]].mean(axis=0)
    result['modified3_vs_stock']=dict(site_mean_difference=simple(b-stock),sites_above_stock50=int((b-stock>50).sum()))
    result['modified3_vs_modified2']=dict(site_mean_difference=simple(b-a),ratio_of_mean_code=float(b.mean()/a.mean()),
        above50=int((b-a>50).sum()),below_minus50=int((b-a< -50).sum()),
        interpretation='Temperature/time and saturation change magnitudes; not a measured dark-current rate or percentage recovery.')
    result['background_by_group']={group:{name:float(np.mean([result['files'][ids.index(i)]['phases'][k]['mean_minus_metadata_black'] for i in seq])) for k,(name,_,_) in enumerate(PHASES)} for group,seq in groups.items()}
    result['targets']=[dict(x=int(x[j]),y=int(y[j]),phase=lock['targets'][j]['phase'],
        codes=cc[:,j].tolist(),max8=mm[:,j].tolist(),delta=delta[:,j].tolist()) for j in range(112)]
    np.savez_compressed(out/'arrays.npz',ids=ids,target_x=x,target_y=y,centres=cc,maxima=mm,deltas=delta,fit=fit,
                        patches_9x9=np.stack(patches),histograms=np.stack(histograms))
    need(all(file_sha(r['path'])==r['sha256'] for r in result['files']),'Source changed during analysis')
    result['ok']=True;write(out/'result.json',result)
    print(json.dumps(dict(ok=True,locked_results=result['locked_results'],vs_stock=result['modified3_vs_stock'],
                         vs_modified2=result['modified3_vs_modified2']),indent=2))

if __name__=='__main__':
    main()

"""Read-only exploratory CFA analysis of the two tablet-lit candidate flats.

All spatial averages use floating point. No demosaic or image correction is
applied to source NEFs. Filtered views are diagnostic, not ring detections.
"""
from pathlib import Path
import argparse, datetime, json
import numpy as np
import rawpy
import scipy
from scipy.ndimage import gaussian_filter, shift
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from audit_nef import file_sha

ROOT = Path(__file__).resolve().parents[2]
PHASES = [('R', 0, 0), ('G1', 0, 1), ('G2', 1, 0), ('B', 1, 1)]
RN = ['R/G', 'B/G', 'G1/G2']
BIN = 16
plt.rcParams.update({'font.family': 'sans-serif', 'font.sans-serif': ['Microsoft YaHei', 'DejaVu Sans'],
                     'axes.unicode_minus': False, 'font.size': 10, 'figure.dpi': 140})

def need(v, text):
    if not v: raise ValueError(text)

def write_json(p, obj):
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False), encoding='utf8')

def centre(a):
    h,w = a.shape[-2:]
    return a[..., h//3:2*h//3, w//3:2*w//3]

def normalize(a):
    return a / centre(a).mean(axis=(-2,-1), keepdims=True)

def bin_raw(raw, size=BIN):
    active = raw[8:4032, 8:6056]
    h,w = active.shape; ny,nx = h//size,w//size; n = size//2
    return np.stack([active[dy:ny*size:2,dx:nx*size:2].reshape(ny,n,nx,n).mean(axis=(1,3),dtype=np.float64)
                     for _,dy,dx in PHASES])

def register(a, size=BIN):
    return np.stack([shift(v, ((dy-.5)/size,(dx-.5)/size),order=1,mode='nearest',prefilter=False)
                     for v,(_,dy,dx) in zip(a,PHASES)])

def ratios(a):
    g = (a[1]+a[2])/2
    return normalize(np.stack([a[0]/g,a[3]/g,a[1]/a[2]]))

def hp(a, sigma):
    return 100 * (a / gaussian_filter(a,sigma=sigma,mode='reflect') - 1)

def stats(a):
    v = np.asarray(a); v = v[np.isfinite(v)]
    q = np.percentile(v,[1,5,50,95,99])
    return dict(mean=float(v.mean()),std=float(v.std()),p01=float(q[0]),p05=float(q[1]),
                median=float(q[2]),p95=float(q[3]),p99=float(q[4]),p95_minus_p05=float(q[3]-q[1]))

def corr(a,b):
    return float(np.corrcoef(a.ravel(),b.ravel())[0,1])

def radial(a, rr, edges, mask=None):
    use = np.ones(a.shape,dtype=bool) if mask is None else mask.copy()
    idx = np.searchsorted(edges,rr,side='right')-1
    use &= (idx>=0)&(idx<len(edges)-1)&np.isfinite(a)
    count = np.bincount(idx[use],minlength=len(edges)-1)
    total = np.bincount(idx[use],weights=a[use],minlength=len(edges)-1)
    out = np.full(len(edges)-1,np.nan)
    np.divide(total,count,out=out,where=count>=5)
    return out,count

def image(ax,v,title,limits=None,cmap='RdBu_r'):
    lo,hi = np.percentile(v,[1,99]) if limits is None else limits
    im = ax.imshow(v,origin='upper',extent=(0,6048,4016,0),cmap=cmap,vmin=lo,vmax=hi,interpolation='nearest')
    ax.set_title(title);ax.set_xlabel('有效区 X / 像素');ax.set_ylabel('有效区 Y / 像素')
    return im

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--audit',type=Path,required=True);p.add_argument('--metadata',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    audit=json.loads(a.audit.read_text(encoding='utf8'));meta=json.loads(a.metadata.read_text(encoding='utf8'))
    md={Path(m['SourceFile']).name:m for m in meta}
    old=json.loads((ROOT/'analysis/modified1-nef-2026-11-09/pixels-v2/result.json').read_text(encoding='utf8'))
    report=dict(scope=__doc__,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        user_conditions='Candidate firmware; Viltrox 16/1.8; full-brightness Samsung Tab S9+ with paper-like film; visible PWM bands; user reports this lens normally shows weaker rings than Z85S.',
        design='Two repeated exposures, not two exposure levels; no matched stock flat in this dataset.',
        versions=dict(rawpy=rawpy.__version__,libraw=list(rawpy.libraw_version),numpy=np.__version__,scipy=scipy.__version__),
        method=dict(active_crop=[8,8,6048,4024],sensor_bin=BIN,binned_sensor_area=[6048,4016],
            bottom_rows_excluded_from_maps=8,black_main=1008,bin_statistic='float64 arithmetic mean of 64 samples per phase',
            centre_normalization='arithmetic mean of central third rectangle',
            co_registration='bilinear +/-0.5 sensor pixel to common block centre; unregistered control saved',
            filters='ratio / Gaussian-smoothed ratio - 1; sigma 3,6,12 bins; diagnostics only',
            ring_centre='geometric image centre, not an estimated physical correction centre',
            radial_radius_unit='2012 sensor pixels (half active height), isotropic circles',
            noise='No formal detection significance or noise upper limit inferred from two structured flats'),
        files=[],bias_sources=[],metrics={})
    blocks=[]
    for case in audit['files']:
        path=Path(case['path']);need(file_sha(path)==case['sha256'],'Source hash changed')
        m=md[path.name];need(str(m['Nikon:SerialNumber'])=='8006677','Wrong body')
        with rawpy.imread(str(path)) as raw:
            v=raw.raw_image;need(v.shape==(4040,6064) and raw.raw_pattern.tolist()==[[0,1],[3,2]],'Wrong Bayer data')
            b=bin_raw(v);blocks.append(b)
            active=v[8:4032,8:6056];ph=[]
            for k,(name,dy,dx) in enumerate(PHASES):
                q=active[dy::2,dx::2];ph.append(dict(name=name,n=int(q.size),minimum=int(q.min()),maximum=int(q.max()),
                    saturated=int(np.count_nonzero(q>=16383)),below_black=int(np.count_nonzero(q<1008)),
                    centre_mean_signal=float(centre(b[k]).mean()-1008),percentiles_signal=(np.percentile(q,[1,50,99,99.9])-1008).tolist()))
        report['files'].append(dict(name=path.name,path=str(path),sha256=case['sha256'],stored_pixels_sha256=case['stored_pixels_sha256'],
            metadata={k:m.get(k) for k in ['ExifIFD:ISO','ExifIFD:ExposureTime','ExifIFD:FNumber','ExifIFD:LensModel','Nikon:ShutterMode','Nikon:VignetteControl','Nikon:NoiseReduction','Nikon:HighISONoiseReduction','Nikon:BlackLevel','Nikon:SerialNumber','Composite:SubSecDateTimeOriginal']},phases=ph))
    need(len(blocks)==2,'Requires this two-frame design')
    bias=[]
    for case in old['files']:
        if case['id'] not in (4857,4858,4859):continue
        path=Path(case['path']);need(file_sha(path)==case['sha256'],'Bias hash changed')
        with rawpy.imread(str(path)) as r:bias.append(bin_raw(r.raw_image))
        report['bias_sources'].append(dict(path=str(path),sha256=case['sha256']))
    need(len(bias)==3,'Three matched bias frames required')
    codes=np.stack(blocks);bias_mean=np.mean(bias,axis=0)
    signals=codes-1008
    reg=np.stack([register(v) for v in signals]);rats=np.stack([ratios(v) for v in reg])
    unreg=np.stack([ratios(v) for v in signals]);biasrats=np.stack([ratios(register(v-bias_mean)) for v in codes])
    g=reg[:,1:3].mean(axis=1);gn=normalize(g)
    yy,xx=np.mgrid[:g.shape[1],:g.shape[2]]
    xx=xx*BIN+(BIN-1)/2;yy=yy*BIN+(BIN-1)/2
    rr=np.hypot(xx-(6048-1)/2,yy-(4024-1)/2)/2012
    theta=(np.arctan2(yy-(4024-1)/2,xx-(6048-1)/2)+2*np.pi)%(2*np.pi)
    core=rr<.9
    safe=np.zeros(core.shape,bool);safe[36:-36,36:-36]=True
    edges=np.arange(0,1.821,.02);radii=(edges[:-1]+edges[1:])/2
    profiles=np.stack([[radial(100*(v-1),rr,edges)[0] for v in frame] for frame in rats])
    sectors=np.stack([[[radial(100*(v-1),rr,edges,(theta>=k*np.pi/4)&(theta<(k+1)*np.pi/4))[0]
                       for k in range(8)] for v in frame] for frame in rats])
    hpmap=np.stack([[[hp(v,s) for v in frame] for frame in rats] for s in [3,6,12]])
    delta_g=100*(gn[1]/gn[0]-1);delta_ratio=100*(rats[1]/rats[0]-1)
    report['metrics']['green_mean_change_percent']=float(100*(g[1].mean()/g[0].mean()-1))
    report['metrics']['green_normalized_frame_difference_percent']=dict(full=stats(delta_g),central_circle=stats(delta_g[core]))
    report['metrics']['ratios']=[]
    for k,name in enumerate(RN):
        row=dict(name=name,direct_percent=[stats(100*(v[k]-1)) for v in rats],
            normalized_frame_difference_percent=dict(full=stats(delta_ratio[k]),central_circle=stats(delta_ratio[k][core])),
            black_and_geometry_controls=dict(
                bias_subtraction_delta_percent=[stats(100*(biasrats[j,k]/rats[j,k]-1)) for j in range(2)],
                cfa_registration_delta_percent=[stats(100*(rats[j,k]/unreg[j,k]-1)) for j in range(2)]),filters=[])
        for i,s in enumerate([3,6,12]):
            aa,bb=hpmap[i,:,k]
            row['filters'].append(dict(sigma_bins=s,sigma_sensor_pixels=s*BIN,
                percent=[stats(v[safe]) for v in [aa,bb]],repeat_correlation=corr(aa[safe],bb[safe]),
                difference_percent=stats((bb-aa)[safe]),
                green_spatial_correlation=[corr(hp(gn[j],s)[safe],hpmap[i,j,k][safe]) for j in range(2)]))
        variants=[]
        for black in [1004,1012]:
            vr=np.stack([ratios(register(v-black)) for v in codes])
            variants.append(dict(black=black,delta_percent=[stats(100*(vr[j,k]/rats[j,k]-1)) for j in range(2)]))
        row['black_and_geometry_controls']['constant_black_sensitivity']=variants
        report['metrics']['ratios'].append(row)
    # This is an intentionally lossy nuisance diagnostic, NOT a corrected flat.
    # Removing row means can also suppress genuine rings; both views are kept.
    detrended=[]
    for j in range(2):
        dr=[]
        for k in range(3):
            v=hpmap[1,j,k];row=v[:,50:-50].mean(axis=1,keepdims=True)
            q=v-row;col=q[36:-36].mean(axis=0,keepdims=True);dr.append(q-col)
        detrended.append(dr)
    detrended=np.asarray(detrended)
    np.savez_compressed(a.output/'maps.npz',codes=codes,bias_mean=bias_mean,signals=signals,registered=reg,ratios=rats,
        unregistered_ratios=unreg,bias_subtracted_ratios=biasrats,green_normalized=gn,green_difference_percent=delta_g,
        ratio_difference_percent=delta_ratio,highpass_percent=hpmap,row_col_removed_percent=detrended,
        radius=rr,radial_edges=edges,radial_centres=radii,radial_profiles_percent=profiles,sector_profiles_percent=sectors)
    # Main figure: unfiltered colour ratios and temporal difference.
    fig,axs=plt.subplots(3,3,figsize=(15,11),layout='constrained')
    for row in range(3):
        arr=gn if row==0 else 100*(rats[:,row-1]-1)
        limits=np.percentile(arr,[1,99]);name=['G 亮度 / 中心均值','R/G 相对中心 / %','B/G 相对中心 / %'][row]
        for j in range(2):
            im=image(axs[row,j],arr[j],f'{4864+j} · {name}',limits,'gray' if row==0 else 'RdBu_r')
            fig.colorbar(im,ax=axs[row,j],shrink=.7)
        d=delta_g if row==0 else delta_ratio[row-1];lim=np.percentile(abs(d),99)
        im=image(axs[row,2],d,'4865 / 4864（各自中心归一）/ %',[-lim,lim]);fig.colorbar(im,ax=axs[row,2],shrink=.7)
    fig.suptitle('候选固件：两张屏幕平场的 RAW 亮度与颜色比例\nISO 1600 · f/1.8 · 1/8000s；16×16 浮点分箱，无去马赛克；颜色图包括光源、镜头与机内处理',fontsize=14)
    fig.savefig(a.output/'flat-direct-comparison.png');fig.savefig(a.output/'flat-direct-comparison.pdf');plt.close(fig)
    fig,axs=plt.subplots(3,3,figsize=(15,11),layout='constrained')
    for row in range(3):
        values=np.stack([hp(gn[j],6) for j in range(2)]) if row==0 else hpmap[1,:,row-1]
        lim=np.percentile(abs(values[:,safe]),99)
        for j in range(2):
            im=image(axs[row,j],values[j],f'{4864+j} · '+['G 亮度','R/G','B/G'][row]+ ' 局部残差 / %',[-lim,lim])
            fig.colorbar(im,ax=axs[row,j],shrink=.7)
        d=values[1]-values[0];limd=np.percentile(abs(d[safe]),99)
        im=image(axs[row,2],d,'两帧残差之差 / 百分点',[-limd,limd]);fig.colorbar(im,ax=axs[row,2],shrink=.7)
    fig.suptitle('条带与细小纹理检查：除以 σ=96 像素平滑背景\n仅为显示增强；低频颜色渐变、滤波边缘及残差不自动代表固件彩圈',fontsize=14)
    fig.savefig(a.output/'flat-local-residuals.png');plt.close(fig)
    fig,axs=plt.subplots(2,3,figsize=(15,8),layout='constrained')
    for k in range(3):
        for j in range(2):axs[0,k].plot(radii,profiles[j,k],label=str(4864+j),lw=1.3)
        for s in range(8):axs[1,k].plot(radii,sectors[0,k,s],lw=.9,label=f'{s*45}–{(s+1)*45}°')
        for row in range(2):
            axs[row,k].set_xlim(0,1.6);axs[row,k].set_xlabel('半径 / 半幅高');axs[row,k].set_ylabel('相对中心比例变化 / %')
            axs[row,k].axvline(1,color='gray',ls=':',lw=.8);axs[row,k].grid(alpha=.2)
        axs[0,k].set_title(RN[k]+' · 两帧全环均值');axs[0,k].legend()
        axs[1,k].set_title(RN[k]+' · 4864 八个方位分别检查')
    axs[1,2].legend(fontsize=7,ncol=2)
    fig.suptitle('径向剖面（原图几何中心；保留各方位，不将条带投影误认作圆环）\n半径 >1 后圆周逐渐超出画幅；单条径向曲线不作硬编码校正判据',fontsize=13)
    fig.savefig(a.output/'flat-radial-sectors.png');plt.close(fig)
    fig,axs=plt.subplots(3,3,figsize=(14,11),layout='constrained')
    for k in range(3):
        for i,s in enumerate([3,6,12]):
            v=hpmap[i,0,k];lim=np.percentile(abs(v[safe]),99)
            im=image(axs[k,i],v,f'4864 {RN[k]} · σ={s*BIN} 像素 / %',[-lim,lim]);fig.colorbar(im,ax=axs[k,i],shrink=.7)
    fig.suptitle('滤波尺度对照：检查结构是否只由某一平滑尺度产生');fig.savefig(a.output/'flat-filter-controls.png');plt.close(fig)
    for case in report['files']+report['bias_sources']:need(file_sha(case['path'])==case['sha256'],'Source changed during analysis')
    report.update(ok=True,source_unchanged=True,script_sha256=file_sha(__file__))
    write_json(a.output/'result.json',report)
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    # Adapt the existing frozen independent decoder interface without changing it.
    decoder=dict(audit);decoder['files']=[dict(c,id=int(Path(c['path']).stem.split('_')[-1])) for c in audit['files']]
    write_json(a.output/'decoder-input.json',decoder)
    print(json.dumps(dict(ok=True,files=[f['name'] for f in report['files']],metrics=report['metrics']),indent=2))

if __name__=='__main__':main()

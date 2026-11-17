"""Independent, read-only remeasurement of Modified10/11 NEFs.

No firmware edits or camera operations. Separates observed code values from
claims about unobserved sensor charge. Reuses only the bounded TIFF parser.
"""
from pathlib import Path
import argparse, datetime, hashlib, itertools, json, shutil, struct
import numpy as np
import rawpy
from scipy.ndimage import shift, gaussian_filter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from audit_nef import tiff_inventory, file_sha

ROOT = Path(__file__).resolve().parents[2]
PHASES = [('R', 0, 0), ('G1', 0, 1), ('G2', 1, 0), ('B', 1, 1)]
BLACK = 1008

def dump(p, v):
    p.write_text(json.dumps(v, indent=2, ensure_ascii=False, allow_nan=False), encoding='utf8')

def stats(a):
    h = np.bincount(a.ravel(), minlength=16384)
    n = int(h.sum()); x = np.arange(len(h)); mu = float(h @ x / n)
    return dict(n=n, mean=mu, std=float(np.sqrt(h @ ((x-mu)**2) / n)),
                minimum=int(a.min()), maximum=int(a.max()), zero=int(h[0]),
                below_black=int(h[:BLACK].sum()), saturated=int(h[16383:].sum()))

def fft_summary(counts):
    amps = np.abs(np.fft.rfft(counts-counts.mean()))
    freq = np.fft.rfftfreq(len(counts))
    idx = np.flatnonzero((freq >= .1) & (freq <= .49))
    peak = idx[np.argmax(amps[idx])]
    return dict(peak_frequency=float(freq[peak]), period_dn=float(1/freq[peak]),
                peak_amplitude=float(amps[peak]),
                peak_over_band_median=float(amps[peak]/np.median(amps[idx])),
                old_02276_amplitude=float(amps[np.argmin(abs(freq-.2276))])), freq, amps

def spectrum(data):
    h = np.bincount(data.ravel(), minlength=16384)
    legacy, _, _ = fft_summary(h[int(data.min()):int(data.max())+1])
    fixed, f, a = fft_summary(h)
    fixed['amplitude_normalized_by_n'] = fixed['peak_amplitude']/data.size
    # Exact same-frequency DFT avoids different legacy frequency grids.
    fixed['exact_02276_amplitude'] = float(abs(h @ np.exp(-2j*np.pi*.2276*np.arange(len(h)))))
    return dict(n=int(data.size), mean=float(data.mean()), legacy=legacy, fixed_grid=fixed), f, a/data.size

def flat_maps(raw):
    a = raw[8:4032, 8:6056]; ny, nx = a.shape[0]//16, a.shape[1]//16
    planes = []
    for _, dy, dx in PHASES:
        p = a[dy:ny*16:2, dx:nx*16:2].reshape(ny, 8, nx, 8).mean(axis=(1,3))-BLACK
        planes.append(shift(p, ((dy-.5)/16,(dx-.5)/16), order=1, mode='nearest', prefilter=False))
    r,g1,g2,b = planes; g=(g1+g2)/2
    maps=np.stack([r/g,b/g,g1/g2])
    maps /= maps[:,ny//3:2*ny//3,nx//3:2*nx//3].mean(axis=(1,2),keepdims=True)
    yy,xx=np.mgrid[:ny,:nx]
    radius=np.hypot(xx*16+7.5-3023.5,yy*16+7.5-2011.5)/2012
    edges=np.arange(0,1.821,.02); radii=(edges[:-1]+edges[1:])/2
    bins=np.searchsorted(edges,radius,side='right')-1
    valid=(bins>=0)&(bins<len(radii)); count=np.bincount(bins[valid],minlength=len(radii))
    def profile(v):
        sums=np.bincount(bins[valid],weights=v[valid],minlength=len(radii))
        return np.divide(sums,count,out=np.zeros_like(sums),where=count>0)
    broad=np.stack([profile(100*(v-1)) for v in maps])
    hp=np.stack([profile(100*(v/gaussian_filter(v,6,mode='reflect')-1)) for v in maps])
    keep=(radii>=.15)&(radii<=.90)
    met=dict(broad_ptp_pp=np.ptp(broad[:,keep],axis=1).tolist(), hp6_ptp_pp=np.ptp(hp[:,keep],axis=1).tolist())
    return maps,broad,hp,radii,met

def target_check(a, baseline):
    deltas=[]; centers=[]
    for p in baseline['targets']:
        y,x=p['y'],p['x']; c=int(a[y,x]); centers.append(c)
        kernel=baseline['kernel_R_B' if y%2==x%2 else 'kernel_G1_G2']
        deltas.append(c-max(int(a[y+dy,x+dx]) for dy,dx in kernel))
    d=np.array(deltas)
    return dict(points=len(d), matches_0_8_to_56=int(np.isin(d,np.arange(0,57,8)).sum()),
                exact_neighbor_max=int((d==0).sum()), above56=int((d>56).sum()),
                saturated=int((np.array(centers)>=16383).sum()), deltas=deltas, centers=centers)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output;out.mkdir(parents=True,exist_ok=False)
    shutil.copy2(__file__,out/Path(__file__).name)
    frozen=ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json'
    baseline=json.loads(frozen.read_text(encoding='utf8'))
    assert file_sha(frozen)=='4c3979cccf400b341e1859c31903e73e0d050f74dd96b3250eaf8d581cef11fb'
    report=dict(computation_completed=False,scope=__doc__,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                script_sha256=file_sha(__file__),versions=dict(rawpy=rawpy.__version__,libraw=list(rawpy.libraw_version),numpy=np.__version__),
                baseline_sha256=file_sha(frozen),files=[],dark={},bias_pairs=[],flat_groups={},
                cautions=['Peak/band-median is descriptive, not calibrated detection significance.',
                          'Annular colour residuals include optics, screen, PWM and framing effects.',
                          'Neither zero decode mismatches nor black pedestal proves untouched sensor data.'])
    cache={}; maps={}; broad={}; high={}; curves={}; flatrows={}
    for group,ids in [('Modified10',range(4955,4958)),('Modified11',range(4958,4967))]:
        folder='11.13_modified10' if group=='Modified10' else '11.14_modified11'
        maps[group]=[];broad[group]=[];high[group]=[];flatrows[group]=[]
        for number in ids:
            path=ROOT/'samples'/folder/f'Z61_{number}.NEF'
            before=file_sha(path); inv=tiff_inventory(path)
            with rawpy.imread(str(path)) as r:
                a=r.raw_image.copy();wb=list(r.camera_whitebalance)
                assert a.shape==(4040,6064) and r.raw_pattern.tolist()==[[0,1],[3,2]]
                assert r.black_level_per_channel==[1008]*4 and r.white_level==16383
                sizes=r.sizes._asdict()
            active=a[8:4032,8:6056]
            row=dict(id=number,name=path.name,path=str(path),group=group,sha256=before,tiff=inv,
                     stored_pixels_sha256=hashlib.sha256(a.astype('<u2').tobytes()).hexdigest(),
                     stored=stats(a),active=stats(active),sizes=sizes,black=[1008]*4,white=16383,camera_whitebalance=wb)
            if number in range(4958,4964):cache[number]=a
            if number in range(4961,4964):report['dark'][str(number)]=target_check(a,baseline)
            if number<4958 or number>=4964:
                central=a[1820:2220,2832:3232];spectra={}
                for name,dy,dx in PHASES:
                    val,f,amp=spectrum(central[dy::2,dx::2]);spectra[name]=val
                    curves[f'{number}_{name}']=amp
                m,p,h,radii,metrics=flat_maps(a)
                means={name:spectra[name]['mean']-BLACK for name,_,_ in PHASES}
                metrics.update(center_net=means,rg1=means['R']/means['G1'],bg1=means['B']/means['G1'],spectra=spectra)
                row['flat']=metrics;maps[group].append(m);broad[group].append(p);high[group].append(h);flatrows[group].append(row)
            assert file_sha(path)==before
            report['files'].append(row)
            print(json.dumps(dict(file=path.name,stored=row['stored'],flat=row.get('flat',{}).get('rg1'))),flush=True)
    for number in (4854,4855):
        path=ROOT/'samples/11.9'/f'Z61_{number}.NEF'
        assert file_sha(path)==baseline['source_sha256'][str(path.relative_to(ROOT))]
        with rawpy.imread(str(path)) as r:report['dark'][str(number)]=target_check(r.raw_image,baseline)
    for i,j in itertools.combinations(range(4958,4961),2):
        d=cache[i][8:4032,8:6056].astype(np.int32)-cache[j][8:4032,8:6056].astype(np.int32)
        q25,q75=np.percentile(d,[25,75]);v=d[(d>=-20)&(d<=20)]
        report['bias_pairs'].append(dict(ids=[i,j],iqr_sigma_dn=float((q75-q25)/(2*.6745*np.sqrt(2))),
                                         untrimmed_sigma_dn=float(d.std()/np.sqrt(2)),
                                         trimmed_abs20_sigma_dn=float(v.std()/np.sqrt(2)),trimmed_kept=int(v.size),total=int(d.size)))
    bias_mu=np.mean([row['active']['mean'] for row in report['files'] if 4958<=row['id']<=4960])
    report['active_dark_minus_mean_bias_dn']={str(row['id']):row['active']['mean']-bias_mu for row in report['files'] if 4961<=row['id']<=4963}
    keep=(radii>=.15)&(radii<=.90)
    for group in maps:
        p=np.mean(broad[group],axis=0);h=np.mean(high[group],axis=0)
        report['flat_groups'][group]=dict(ids=[v['id'] for v in flatrows[group]],
            broad_ptp_pp=np.ptp(p[:,keep],axis=1).tolist(),hp6_ptp_pp=np.ptp(h[:,keep],axis=1).tolist(),
            means_of_individual_ptp_pp=np.mean([v['flat']['broad_ptp_pp'] for v in flatrows[group]],axis=0).tolist())
    np.savez_compressed(out/'measurements.npz',frequency=f,radii=radii,**curves,
        **{f'{g}_ratio_maps':np.array(v) for g,v in maps.items()},
        **{f'{g}_broad':np.array(v) for g,v in broad.items()},**{f'{g}_hp6':np.array(v) for g,v in high.items()})
    fig,ax=plt.subplots(2,2,figsize=(13,9),layout='constrained')
    colors={'Modified10':'#c44939','Modified11':'#226cb8'}
    for group,ids in [('Modified10',range(4955,4958)),('Modified11',range(4964,4967))]:
        amps=np.array([curves[f'{i}_R'] for i in ids]);sel=(f>=.1)&(f<=.49)
        ax[0,0].plot(f[sel],amps.mean(axis=0)[sel],color=colors[group],label=group,lw=1)
        ax[0,0].fill_between(f[sel],amps.min(axis=0)[sel],amps.max(axis=0)[sel],color=colors[group],alpha=.15)
        for k,target in enumerate([ax[0,1],ax[1,0]]):
            for individual in broad[group]:target.plot(radii[keep],individual[k,keep],color=colors[group],alpha=.25)
            target.plot(radii[keep],np.mean(broad[group],axis=0)[k,keep],color=colors[group],label=group)
    ax[0,0].axvline(.2276,color='gray',ls=':');ax[0,0].axvline(.1715,color='gray',ls=':')
    ax[0,0].set(title='Red-channel code-histogram FFT: all 3 flats / group',xlabel='cycles / DN (same 16384-bin grid)',ylabel='Amplitude / 40000 pixels')
    ax[0,1].set(title='R/G annular profile (unfiltered)',xlabel='Radius / half image height',ylabel='Relative to own centre (%)')
    ax[1,0].set(title='B/G annular profile (unfiltered)',xlabel='Radius / half image height',ylabel='Relative to own centre (%)')
    ax[1,1].scatter(range(112),report['dark']['4854']['deltas'],s=12,label='Stock 4854',color=colors['Modified10'])
    for n in (4961,4962,4963):ax[1,1].scatter(range(112),report['dark'][str(n)]['deltas'],s=10,alpha=.5,label=f'M11 {n}')
    ax[1,1].axhline(56,ls=':',color='gray')
    ax[1,1].set(title='Frozen 112 sites: centre - max(8 neighbours)',xlabel='Frozen site index',ylabel='Difference (DN)')
    for panel in ax.flat:panel.grid(alpha=.2);panel.legend(fontsize=8)
    fig.suptitle('Independent Modified11 review: measurements, not a production certification')
    fig.savefig(out/'independent-comparison.png',dpi=170);plt.close(fig)
    fig,ax=plt.subplots(2,2,figsize=(12,8),layout='constrained')
    for j,group in enumerate(maps):
        mean=np.mean(maps[group],axis=0)
        for k,ch in enumerate(['R/G','B/G']):
            im=ax[k,j].imshow(100*(mean[k]-1),vmin=-2.5,vmax=2.5,cmap='RdBu_r',interpolation='nearest')
            ax[k,j].set(title=f'{group} {ch}',xlabel='16-pixel block X',ylabel='16-pixel block Y')
            fig.colorbar(im,ax=ax[k,j],label='% vs own centre')
    fig.suptitle('Unfiltered colour-ratio maps; optics / screen / PWM / camera are combined')
    fig.savefig(out/'independent-ratio-maps.png',dpi=160);plt.close(fig)
    report['computation_completed']=True
    dump(out/'assessment.json',report)
    dump(out/'decode-input.json',dict(files=[v for v in report['files'] if v['group']=='Modified11']))
    print(json.dumps(dict(computation_completed=True,flat_groups=report['flat_groups'],bias_pairs=report['bias_pairs'])),flush=True)

if __name__=='__main__':main()

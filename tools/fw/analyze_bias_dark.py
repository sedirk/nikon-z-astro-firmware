"""Compare matched local bias/dark exposures in stored CFA code units.

Exposure differences are not automatically physical dark current. Temperature,
conversion gain and firmware processing are separate variables. Independent bias
frames are used when comparing repeat dark residuals to avoid shared-bias noise.
"""
from pathlib import Path
import argparse, hashlib, json, math
import numpy as np
import rawpy
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from audit_nef import file_sha

plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Microsoft YaHei','DejaVu Sans'],
                    'axes.unicode_minus':False,'font.size':10})
NAMES=['R','G1','G2','B'];COLORS=['#d6424a','#32894b','#84ac44','#3274c7']

def values(a):
    q=np.percentile(a,[.1,1,15.8655,50,84.1345,99,99.9])
    return dict(mean=float(a.mean(dtype=np.float64)),std=float(a.std(dtype=np.float64)),
        minimum=float(a.min()),maximum=float(a.max()),quantiles=dict(zip(['p001','p01','p158655','p50','p841345','p99','p999'],map(float,q))))

def pair_noise(a,b):
    d=a.astype(np.int32)-b.astype(np.int32);s=values(d)
    s['pair_std_over_sqrt2']=s['std']/math.sqrt(2)
    s['pair_central68_halfwidth_over_sqrt2']=(s['quantiles']['p841345']-s['quantiles']['p158655'])/(2*math.sqrt(2))
    return s

def neighbors(a,y,x):
    h,w=a.shape
    return [int(a[y+dy,x+dx]) for dy,dx in [(dy,dx) for dy in [-1,0,1] for dx in [-1,0,1] if dy or dx]
            if 0<=y+dy<h and 0<=x+dx<w]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--metadata',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    meta=json.loads(a.metadata.read_text(encoding='utf8'));meta.sort(key=lambda m:m['System:FileName'])
    assert [m['System:FileName'] for m in meta]==[f'Z61_{i}.NEF' for i in range(4851,4856)]
    for key in ['IFD0:Model','IFD0:Software','ExifIFD:ISO','Nikon:SerialNumber','Nikon:ShutterMode',
                'Nikon:NEFCompression','Nikon:NoiseReduction','Nikon:HighISONoiseReduction','Nikon:BlackLevel']:
        assert len({str(m[key]) for m in meta})==1,(key,[m[key] for m in meta])
    assert [m['ExifIFD:ExposureTime'] for m in meta]==['1/8000']*3+[5]*2
    report=dict(scope=__doc__,script_sha256=file_sha(__file__),metadata_sha256=file_sha(a.metadata),
        files=[],phases=[],hot_pixel_definition='min(all three bias codes)>1108; both 5s dark codes<1080 and at least50DN below mean bias',
        persistent_dark_definition='dark4854-bias4851 AND dark4855-bias4852 each exceed threshold; independent bias frames',
        delta_definition='mean(two 5s darks) - mean(three 1/8000s biases), exact numerator in sixth DN',
        temperature='not supplied; same-minute sequence',bias_count=3,dark_count=2,exposure_seconds=[1/8000]*3+[5]*2)
    arrays=[]
    for m in meta:
        path=Path(m['SourceFile']);digest=file_sha(path)
        with rawpy.imread(str(path)) as r:
            assert r.raw_image.shape==(4040,6064) and r.black_level_per_channel==[1008]*4
            s=r.sizes;assert (s.crop_left_margin,s.crop_top_margin,s.crop_width,s.crop_height)==(8,8,6048,4024)
            raw=r.raw_image.copy();arrays.append(raw[8:4032,8:6056].copy())
            report['files'].append(dict(name=path.name,path=str(path),sha256=digest,
                full_pixels_sha256=hashlib.sha256(raw.astype('<u2',copy=False).tobytes()).hexdigest(),
                size=path.stat().st_size,metadata=m))
    binned=[];means=np.zeros((5,4));below=np.zeros((5,4));histograms=[];persistent_total={20:0,50:0,100:0};suppressed_total=0
    for k,(dy,dx) in enumerate([(0,0),(0,1),(1,0),(1,1)]):
        planes=[v[dy::2,dx::2] for v in arrays]
        bs=sum(v.astype(np.int32) for v in planes[:3]);ds=sum(v.astype(np.int32) for v in planes[3:])
        delta6=3*ds-2*bs;delta=delta6.astype(np.float64)/6
        bavg=bs/3;davg=ds/2
        r1=planes[3].astype(np.int32)-planes[0].astype(np.int32)
        r2=planes[4].astype(np.int32)-planes[1].astype(np.int32)
        row=dict(channel=NAMES[k],phase=[dy,dx],pixels=int(delta.size),bias_mean=float(bavg.mean()),dark_mean=float(davg.mean()),
            delta=values(delta),per_dark_minus_master_bias=[float(v.mean(dtype=np.float64)-bavg.mean()) for v in planes[3:]],
            bias_noise_pairs=[pair_noise(planes[i],planes[j]) for i,j in [(0,1),(1,2),(0,2)]],
            dark_noise_pair=pair_noise(planes[3],planes[4]),
            delta6_sha256=hashlib.sha256(delta6.astype('<i4',copy=False).tobytes()).hexdigest(),
            repeat_residual_correlation=float(np.corrcoef(r1.ravel(),r2.ravel())[0,1]),
            persistent_dark_counts={str(t):int(((r1>t)&(r2>t)).sum()) for t in [20,50,100]})
        mask=(np.minimum.reduce(planes[:3])>1108)&(np.maximum.reduce(planes[3:])<1080)&(np.maximum.reduce(planes[3:])<bavg-50)
        ys,xs=np.nonzero(mask);suppressed_total+=len(ys)
        row['persistent_bias_bright_reduced_in_darks']=int(len(ys))
        rank=np.argsort(bavg[ys,xs])[::-1][:12];row['bright_bias_examples']=[]
        for i in rank:
            yy,xx=int(ys[i]),int(xs[i]);row['bright_bias_examples'].append(dict(
                raw_y=8+2*yy+dy,raw_x=8+2*xx+dx,codes=[int(v[yy,xx]) for v in planes],
                same_cfa_neighbors=[neighbors(v,yy,xx) for v in planes]))
        for t in [20,50,100]:persistent_total[t]+=row['persistent_dark_counts'][str(t)]
        # Trim 12 sensor rows top/bottom, preserving the same bins as NAS study.
        dd=delta[6:-6];ny,nx=dd.shape[0]//16,dd.shape[1]//16
        bins=dd.reshape(ny,16,nx,16).mean(axis=(1,3));binned.append(bins)
        hist=[]
        for i,q in enumerate(planes):
            means[i,k]=q.mean(dtype=np.float64);below[i,k]=np.count_nonzero(q<1008)/q.size
            hist.append(np.bincount(q.ravel(),minlength=65536).astype(np.uint32))
        histograms.append(hist);report['phases'].append(row)
        print(NAMES[k],row['delta']['mean'],row['persistent_dark_counts'],len(ys),flush=True)
    report['persistent_dark_counts_total']=persistent_total
    report['persistent_bias_bright_reduced_total']=suppressed_total
    report['file_mean_codes']=means.tolist();report['file_fraction_below_black']=below.tolist()
    report['overall_mean_dark_minus_bias']=float(np.mean([x['delta']['mean'] for x in report['phases']]))
    np.savez_compressed(a.output/'statistics.npz',delta_mean_bins=np.stack(binned),histograms=np.asarray(histograms),
                        file_means=means,file_fraction_below_black=below)
    fig,axes=plt.subplots(2,2,figsize=(13,8),layout='constrained')
    for k,name in enumerate(NAMES):
        axes[0,0].plot(range(5),means[:,k]-1008,'o-',color=COLORS[k],label=name)
        axes[0,1].plot(range(5),below[:,k]*100,'o-',color=COLORS[k],label=name)
    for ax in axes[0]:ax.set_xticks(range(5),['bias 4851','bias 4852','bias 4853','dark 4854','dark 4855'],rotation=15);ax.legend()
    axes[0,0].set_title('各照片均值 − 元数据黑位 1008');axes[0,0].set_ylabel('DN')
    axes[0,1].set_title('实际保存码值低于 1008 的比例');axes[0,1].set_ylabel('%')
    for k,name in enumerate(NAMES):
        row=report['phases'][k]
        axes[1,0].plot([0,1,2],[q['pair_std_over_sqrt2'] for q in row['bias_noise_pairs']],'o-',color=COLORS[k],label=name+' bias')
        axes[1,0].scatter([3],[row['dark_noise_pair']['pair_std_over_sqrt2']],color=COLORS[k],marker='s')
    axes[1,0].set_xticks(range(4),['bias 1−2','bias 2−3','bias 1−3','dark 1−2']);axes[1,0].set_ylabel('差分标准差 / √2 (DN)')
    axes[1,0].set_title('帧间噪声指标（含热像素与状态变化）');axes[1,0].legend(ncol=2)
    axes[1,1].bar(NAMES,[r['delta']['mean'] for r in report['phases']],color=COLORS)
    axes[1,1].set_title('平均 5 秒 dark − 平均 bias');axes[1,1].set_ylabel('保存码值差 DN');axes[1,1].axhline(0,color='black',lw=.8)
    fig.suptitle('同机身、ISO 1600、机械快门、降噪关闭：3 bias + 2 dark\n这是保存信号基线；电子数暗电流与完整曝光增长关系另行量测',fontsize=13)
    fig.savefig(a.output/'bias-dark-overview.png',dpi=140);plt.close(fig)
    fig,axes=plt.subplots(2,2,figsize=(12,8),layout='constrained')
    for k,ax in enumerate(axes.flat):
        v=binned[k];lo,hi=np.percentile(v,[1,99]);im=ax.imshow(v,cmap='RdBu_r',vmin=lo,vmax=hi)
        ax.set_title(NAMES[k]+' · dark−bias 块均值');fig.colorbar(im,ax=ax,label='DN')
    fig.suptitle('5 秒暗场差分的空间分布（32×32 传感器像素分箱，色标1–99百分位）')
    fig.savefig(a.output/'bias-dark-spatial.png',dpi=140);plt.close(fig)
    for f in report['files']:assert file_sha(f['path'])==f['sha256']
    report['sources_unchanged']=True;report['ok']=True
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    (a.output/'result.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps(dict(ok=True,overall_mean_dark_minus_bias=report['overall_mean_dark_minus_bias'],
        persistent_dark_counts=persistent_total,persistent_bias_bright_reduced_total=suppressed_total),indent=2))

if __name__=='__main__':main()

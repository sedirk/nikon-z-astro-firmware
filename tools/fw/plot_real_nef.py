"""Descriptive CFA diagnostics, with independent split and processing controls.

Residual maps remove a specified smooth component for display, not a fitted
camera correction. Dust, illumination and lens shading remain plausible causes.
No ring/firmware classifier or camera correction is applied.
"""
from pathlib import Path
import argparse, hashlib, json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
import numpy as np
from scipy.ndimage import gaussian_filter, shift

plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Microsoft YaHei','DejaVu Sans'],
                     'axes.unicode_minus':False,'font.size':10,'figure.dpi':120})
NAMES=['R','G1','G2','B']; COLORS=['#d6424a','#32894b','#84ac44','#3274c7']

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def center(a):
    h,w=a.shape[-2:];return a[...,h//3:2*h//3,w//3:2*w//3]

def registered(a):
    # Every CFA tile mean is located at a slightly different physical centre.
    # Move means by +/-0.5 sensor pixel (1/64 of a tile) to a common centre.
    return np.stack([shift(v,((dy-.5)/32,(dx-.5)/32),order=1,mode='nearest',prefilter=False)
                     for v,(dy,dx) in zip(a,[(0,0),(0,1),(1,0),(1,1)])])

def ratios(a):
    g=(a[1]+a[2])/2
    r=np.stack([a[0]/g,a[3]/g,a[1]/a[2]])
    return r/np.median(center(r),axis=(1,2))[:,None,None]

def residual(a,sigma):return a-gaussian_filter(a,sigma=sigma,mode='reflect')
def summary(a):return dict(p01=float(np.percentile(a,1)),p50=float(np.median(a)),p99=float(np.percentile(a,99)),std=float(np.std(a)))
def correlation(a,b):return float(np.corrcoef(a.ravel(),b.ravel())[0,1])
def robust_correlation(a,b):
    aa=np.clip(a,*np.percentile(a,[.5,99.5]));bb=np.clip(b,*np.percentile(b,[.5,99.5]))
    return correlation(aa,bb)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--flats-only',action='store_true')
    p.add_argument('--nefinfo',type=Path)
    p.add_argument('--light-statistic',choices=['mean','median','mean-temporal-median'],default='mean-temporal-median')
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'plot-source.py').write_bytes(Path(__file__).read_bytes())
    records=[]; groups={}
    for f in sorted(a.input.glob('*/result.json')):
        r=json.loads(f.read_text(encoding='utf8'))
        if a.flats_only and r['kind']!='flat':continue
        with np.load(f.parent/'cfa.npz') as z:
            black=np.asarray(r['black_level'])[[0,1,3,2]]
            mean=z['mean']-black[:,None,None]; med=z['median']-black[:,None,None]
            normalized=mean/np.median(center(mean),axis=(1,2))[:,None,None]
            records.append(dict(record=r,hist=z['histograms'].copy(),signal=mean,median=med,normalized=normalized,
                result_sha256=sha(f),bins_sha256=sha(f.parent/'cfa.npz')))
            groups.setdefault(r['kind'],[]).append(records[-1])
    flats=groups['flat']; assert len(flats)==37
    stack=np.stack([v['normalized'] for v in flats])
    # Arithmetic means keep sub-ADU signal; no integer rounding in derived data.
    master=stack.mean(axis=0); rat=ratios(registered(master)); unregistered=ratios(master)
    split_a=ratios(registered(stack[::2].mean(axis=0)))
    split_b=ratios(registered(stack[1::2].mean(axis=0)))
    early=ratios(registered(stack[:18].mean(axis=0))); late=ratios(registered(stack[19:].mean(axis=0)))
    sigma_values=[3,6,12]
    res=np.stack([np.stack([residual(v,s) for v in rat]) for s in sigma_values])
    inner=(slice(12,-12),slice(12,-12))
    report=dict(scope=__doc__,script_sha256=sha(__file__),flat_frames=37,
        method=dict(sensor_bin=32,black='subtract metadata 1008 in floating point, never clip',
            spatial_normalization='divide each phase by its central-third median per frame',
            stack='arithmetic mean of normalized binned frames',
            interpolation='bilinear CFA centres onto common bin centre; retain no-interpolation control',
            high_pass_sigma_bins=sigma_values,metrics_edge_exclusion_bins=12,
            half_sets='alternating 19/18 frames; temporal first18/last18 excludes middle frame'),
        input_hashes=[dict(name=v['record']['name'],result_sha256=v['result_sha256'],bins_sha256=v['bins_sha256']) for v in records],
        flat_channels=[],ratios=[],groups={k:len(v) for k,v in groups.items()})
    for j,name in enumerate(NAMES):
        signals=np.asarray([np.median(center(v['signal'][j])) for v in flats])
        report['flat_channels'].append(dict(channel=name,central_signal_min=float(signals.min()),
            central_signal_max=float(signals.max()),central_signal_mean=float(signals.mean())))
    ratio_names=['R / G','B / G','G1 / G2']
    fig,axes=plt.subplots(3,4,figsize=(15,10),layout='constrained')
    for k,name in enumerate(ratio_names):
        row=dict(name=name,relative_ratio_percent=summary(100*(rat[k]-1)),high_pass=[])
        for j,sig in enumerate(sigma_values):
            aa=residual(split_a[k],sig);bb=residual(split_b[k],sig)
            ee=residual(early[k],sig);ll=residual(late[k],sig)
            rr=res[j,k]
            row['high_pass'].append(dict(sigma=sig,percent=summary(100*rr[inner]),
                alternating_half_correlation=correlation(aa[inner],bb[inner]),
                temporal_half_correlation=correlation(ee[inner],ll[inner]),
                alternating_half_winsorized_correlation=robust_correlation(aa[inner],bb[inner]),
                temporal_half_winsorized_correlation=robust_correlation(ee[inner],ll[inner]),
                alternating_difference_percent=summary(100*(aa-bb)[inner]),
                registration_effect_percent=summary(100*(rat[k]-unregistered[k])[inner])))
        report['ratios'].append(row)
        views=[100*(rat[k]-1),100*res[1,k],100*residual(split_a[k],6),100*residual(split_b[k],6)]
        lim=np.percentile(np.abs(views[1][inner]),99)
        for j,(ax,v) in enumerate(zip(axes[k],views)):
            lo,hi=np.percentile(v,[1,99])
            kw=dict(vmin=lo,vmax=hi) if j==0 else dict(vmin=-lim,vmax=lim)
            im=ax.imshow(v,cmap='RdBu_r',origin='upper',**kw)
            ax.set_title(f'{name} · '+['直接比例（中心归一）','高通残差 σ=6 格','奇数片独立堆叠','偶数片独立堆叠'][j])
            ax.set_xlabel('32 像素网格 X');ax.set_ylabel('网格 Y')
            fig.colorbar(im,ax=ax,shrink=.72,label='%')
    fig.suptitle('37 张 Z6 原始平场：CFA 颜色比例与独立分组\n直接图色标取 1–99 百分位；高通仅用于观察，不自动区分光学与机内处理',fontsize=14)
    fig.savefig(a.output/'flat-ratio-diagnostics.png');plt.close(fig)
    np.savez_compressed(a.output/'flat-ratio-maps.npz',master=master,ratios=rat,unregistered=unregistered,
        split_a=split_a,split_b=split_b,early=early,late=late,residuals=res)
    # Scale sensitivity: a feature should not be declared a ring from one filter.
    fig,axes=plt.subplots(3,3,figsize=(12,10),layout='constrained')
    for k,name in enumerate(ratio_names):
        for j,sig in enumerate(sigma_values):
            v=100*res[j,k]; lim=np.percentile(np.abs(v[inner]),99)
            im=axes[k,j].imshow(v,cmap='RdBu_r',vmin=-lim,vmax=lim)
            axes[k,j].set_title(f'{name} · σ={sig} 格 ({sig*32} 像素)')
            fig.colorbar(im,ax=axes[k,j],shrink=.7,label='%')
    fig.suptitle('平场残差的滤波尺度检查（描述性分析，不自动判定固件彩圈）')
    fig.savefig(a.output/'flat-filter-sensitivity.png');plt.close(fig)
    # Raw histograms are displayed in stored DN, black is a reference line.
    fig,axes=plt.subplots(1,2,figsize=(13,4.5),layout='constrained')
    hist=np.sum([v['hist'] for v in flats],axis=0,dtype=np.uint64)
    for k,name in enumerate(NAMES):
        axes[0].plot(np.arange(1100,2801),hist[k,1100:2801]/hist[k].sum(),color=COLORS[k],label=name,lw=1)
    axes[0].set_title('37 张平场：原始码值分布');axes[0].set_xlabel('保存码值 DN（未扣黑位）');axes[0].legend()
    if 'dark_other_body' in groups:
        d=groups['dark_other_body'][0];hist=d['hist'];report['dark']=d['record']
        for k,name in enumerate(NAMES):axes[1].semilogy(np.arange(930,1091),hist[k,930:1091]/hist[k].sum(),color=COLORS[k],label=name)
        axes[1].axvline(1008,color='black',ls='--',label='BlackLevel 1008')
        axes[1].set_title('另一台 Z6 暗场：ISO 1600 / 1.3 秒');axes[1].legend()
        axes[1].set_xlabel('保存码值 DN（未扣黑位）')
    else:
        for k,name in enumerate(NAMES):axes[1].plot([np.median(center(v['signal'][k])) for v in flats],label=name,color=COLORS[k])
        axes[1].set_title('平场中央信号随序列变化');axes[1].set_xlabel('帧序号');axes[1].set_ylabel('DN（仅扣元数据黑位）');axes[1].legend()
    fig.savefig(a.output/'stored-code-distributions.png');plt.close(fig)
    if 'light30' in groups:
        lights=groups['light30'];assert len(lights)==127
        # The scientific default is floating-point means throughout. A median
        # of integer-valued low-signal pixels can introduce quantization steps;
        # keep that view only as an explicitly selected processing control.
        ls=[]
        for v in lights:
            m=v['median' if a.light_statistic=='median' else 'signal']
            ls.append(m/np.median(center(m),axis=(1,2))[:,None,None])
        light=np.mean(ls,axis=0) if a.light_statistic=='mean' else np.median(ls,axis=0)
        lr=ratios(registered(light))
        flat_corrected=ratios(registered(light/master))
        fig,axes=plt.subplots(2,3,figsize=(13,8),layout='constrained')
        for k,name in enumerate(ratio_names[:2]):
            for j,v in enumerate([lr[k],rat[k],flat_corrected[k]]):
                vals=100*(v-1);lo,hi=np.percentile(vals,[1,99])
                im=axes[k,j].imshow(vals,cmap='RdBu_r',vmin=lo,vmax=hi);fig.colorbar(im,ax=axes[k,j],shrink=.75,label='%')
                label={'mean':'星空浮点均值','median':'星空中值处理对照',
                       'mean-temporal-median':'浮点块均值→时间中值'}[a.light_statistic]
                axes[k,j].set_title(name+' · '+[label,'独立平场','相除后的诊断图'][j])
        fig.suptitle('127 张 30 秒星空片与平场（'+a.light_statistic+'）\n色标取 1–99 百分位；保留天空与星系，相除图为诊断图',fontsize=13)
        fig.savefig(a.output/'light-flat-comparison.png');plt.close(fig)
        np.savez_compressed(a.output/'light-flat-maps.npz',light=light,light_ratios=lr,flat_corrected=flat_corrected)
        report['light30']=dict(frames=127,method=dict(spatial='median' if a.light_statistic=='median' else 'float mean',
            temporal='mean' if a.light_statistic=='mean' else 'median',normalize='central third per phase',alignment='none'),
            central_signal_dn_by_frame=[dict(name=v['record']['name'],signals=[float(np.median(center(v['signal'][k]))) for k in range(4)]) for v in lights],
            ratio_summary=[dict(name=n,percent=summary(100*(v-1))) for n,v in zip(ratio_names,lr)])
    if a.nefinfo:
        series=json.loads(a.nefinfo.read_text(encoding='utf8'))
        byname={x['name']:x for x in series['files']}
        joined=[]
        for v in records:
            row=v['record'];n=byname[row['name']]
            signal=[q['mean']-q['metadata_black'] for q in row['phases']]
            joined.append(dict(name=row['name'],kind=row['kind'],green_mean_dn=(signal[1]+signal[2])/2,
                L=n['L_owner_1024'],signals_dn=signal))
        sky=[x for x in joined if x['kind']=='light30']
        fig,axes=plt.subplots(1,2,figsize=(13,4.7),layout='constrained')
        green=[x['green_mean_dn'] for x in sky];levels=[x['L'] for x in sky]
        axes[0].plot(green,color='#32894b',label='G 平均信号 DN');axes[0].set_xlabel('30 秒星空片序号')
        axes[0].set_ylabel('G 平均信号 DN（扣元数据黑位）',color='#32894b')
        right=axes[0].twinx();right.step(range(len(levels)),levels,where='mid',color='#844aba',label='NEFInfo L')
        right.set_ylabel('NEFInfo L（物理单位待查）',color='#844aba');axes[0].set_title('同曝光序列的实际信号与元数据档位')
        labels=dict(light30='30 秒星空',light10='10 秒星空',flat='1/2000 秒平场',dark_other_body='另一机身暗场')
        for k in groups:
            v=[x for x in joined if x['kind']==k]
            axes[1].scatter([x['green_mean_dn'] for x in v],[x['L'] for x in v],s=16,label=labels[k],alpha=.7)
        axes[1].set_xlabel('G 平均信号 DN（扣元数据黑位）');axes[1].set_ylabel('NEFInfo L（物理单位待查）')
        axes[1].legend();axes[1].set_title('这是文件内的相关性，不代表 ISP 运算已确定')
        fig.savefig(a.output/'nefinfo-L-and-signal.png');plt.close(fig)
        report['nefinfo_series']=dict(source_sha256=sha(a.nefinfo),rows=joined,
            light30_pearson=float(np.corrcoef(green,levels)[0,1]),
            unique_L_by_group={k:sorted({x['L'] for x in joined if x['kind']==k}) for k in groups})
    (a.output/'result.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps({k:report[k] for k in ['groups','flat_channels','ratios']},indent=2,ensure_ascii=False))

if __name__=='__main__':main()

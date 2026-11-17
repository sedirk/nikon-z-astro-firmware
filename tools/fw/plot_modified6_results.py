"""Plot measured A/B CFA ratios only; no firmware work."""
from pathlib import Path
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from analyze_modified1_flats import centre, radial

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/modified6-real-2026-11-10'
a=np.load(OUT/'flats/maps.npz')
plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Microsoft YaHei','DejaVu Sans'], 'axes.unicode_minus':False})
fig,axes=plt.subplots(2,3,figsize=(15,8),layout='constrained')
r=a['radial_centres']; keep=(r>=.15)&(r<=.9)
for k,name in enumerate(('R/G','B/G')):
    values=100*(a['group_ratios'][:,k]-1)
    limit=float(np.percentile(np.abs(values),98))
    for j,version in enumerate(('modified4','modified6')):
        im=axes[k,j].imshow(values[j],vmin=-limit,vmax=limit,cmap='RdBu_r',interpolation='nearest')
        axes[k,j].set_title(version+' '+name+' / 中央归一 (%)')
        axes[k,j].set_xticks([]);axes[k,j].set_yticks([])
        fig.colorbar(im,ax=axes[k,j],shrink=.8)
    for j,label in enumerate(('modified4','modified6')):
        pp=a['profiles'][j*2:j*2+2,k]
        for frame in pp:axes[k,2].plot(r[keep],frame[keep],color=('tab:blue','tab:orange')[j],alpha=.25,linewidth=.7)
        axes[k,2].plot(r[keep],pp.mean(axis=0)[keep],label=label,color=('tab:blue','tab:orange')[j])
    axes[k,2].set_title(name+' 径向剖面（未经平滑）');axes[k,2].set_xlabel('半径 / 2012像素')
    axes[k,2].set_ylabel('百分点');axes[k,2].grid(alpha=.2);axes[k,2].legend()
fig.suptitle('11.10 新 A/B：原始 CFA，扣黑位1008，不去马赛克或镜头校正；每组两张')
fig.savefig(OUT/'ring-comparison.png',dpi=140);plt.close(fig)
fig,ax=plt.subplots(1,3,figsize=(14,4.7),layout='constrained')
for j,name in enumerate(('modified4','modified6')):
    im=ax[j].imshow(a['group_green'][j],vmin=.3,vmax=1.5,cmap='gray');ax[j].set_title(name+' G / 中央归一');fig.colorbar(im,ax=ax[j],shrink=.8)
im=ax[2].imshow(a['green_group_difference_percent'],vmin=-20,vmax=20,cmap='RdBu_r');ax[2].set_title('归一G差异 B/A−1 (%)');fig.colorbar(im,ax=ax[2],shrink=.8)
for x in ax:x.set_xticks([]);x.set_yticks([])
fig.savefig(OUT/'brightness-comparison.png',dpi=140);plt.close(fig)
print(json.dumps(dict(ok=True,figures=['ring-comparison.png','brightness-comparison.png'])))

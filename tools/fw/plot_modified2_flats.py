"""Render shared-scale physical A/B RAW figures; no simulated pixel output."""
from pathlib import Path
import argparse,json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2]
ROUND=ROOT/'analysis/modified2-flat-2026-11-09'
plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Microsoft YaHei','DejaVu Sans'],
                    'axes.unicode_minus':False,'font.size':10,'figure.dpi':140})


def image(ax,values,title,limits,cmap='RdBu_r'):
    im=ax.imshow(values,origin='upper',extent=(0,6048,4016,0),interpolation='nearest',
                 vmin=limits[0],vmax=limits[1],cmap=cmap)
    ax.set_title(title);ax.set_xlabel('有效区 X / 像素');ax.set_ylabel('有效区 Y / 像素')
    return im


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    source=ROUND/'cfa-comparison/maps.npz';d=np.load(source)
    r=d['radial_centres'];interval=(r>=.15)&(r<=.9);core=(d['radius']>=.15)&(d['radius']<=.9)
    colors=['#a53836','#d27055','#235d9f','#35a8b6']
    labels=['A · 4864','A · 4865','B · 4870','B · 4873']
    fig,ax=plt.subplots(2,3,figsize=(15,8.2),layout='constrained')
    for k,name in enumerate(('R/G','B/G')):
        values=100*(d['group_ratios'][:,k]-1)
        lim=np.ceil(np.percentile(abs(values[:,core]),99)*2)/2
        for g in (0,1):
            im=image(ax[k,g],values[g],f'{"A · modified1" if g==0 else "B · modified2"} · {name}',(-lim,lim))
            fig.colorbar(im,ax=ax[k,g],shrink=.72,label='相对各自中心 / %')
        for j,label in enumerate(labels):
            ax[k,2].plot(r[interval],d['profiles'][j,k,interval],color=colors[j],label=label,lw=1.5,
                         ls='-' if j%2==0 else '--')
        ax[k,2].set_title(name+' · 四张原始帧的径向剖面')
        ax[k,2].set_xlabel('半径 / 半幅高（2012 像素）');ax[k,2].set_ylabel('相对各自中心 / %')
        ax[k,2].grid(alpha=.2);ax[k,2].legend(fontsize=8,ncol=2)
    fig.suptitle('257 项曲线中性化前后：保存 RAW 的宽环仍然存在\n'
        'ISO1600 · f/1.8 · 1/8000s；每组两张，16×16 浮点分箱；位置／对焦可能改变',fontsize=14)
    fig.savefig(a.output/'modified2-ring-comparison.png');fig.savefig(a.output/'modified2-ring-comparison.pdf');plt.close(fig)
    fig,ax=plt.subplots(3,3,figsize=(15,11),layout='constrained')
    for k,name in enumerate(('G 亮度 / 中心均值','R/G 相对中心 / %','B/G 相对中心 / %')):
        values=d['group_green'] if k==0 else 100*(d['group_ratios'][:,k-1]-1)
        limits=(0,1.1) if k==0 else tuple(np.percentile(values[:,core],[1,99]))
        for g in (0,1):
            im=image(ax[k,g],values[g],('A 组均值 · ' if g==0 else 'B 组均值 · ')+name,limits,'gray' if k==0 else 'RdBu_r')
            fig.colorbar(im,ax=ax[k,g],shrink=.72)
        diff=d['green_group_difference_percent'] if k==0 else d['ratio_group_difference_percent'][k-1]
        limit=float(np.percentile(abs(diff[core]),99))
        im=image(ax[k,2],diff,'B / A − 1（中心归一）/ %',(-limit,limit));fig.colorbar(im,ax=ax[k,2],shrink=.72)
    fig.suptitle('实拍 RAW 空间差异：包含固件、光源和布置变化\n同色标；差图不等同于固件单独效果，边缘色标截断以便观察内区',fontsize=14)
    fig.savefig(a.output/'brightness-and-differences.png');fig.savefig(a.output/'brightness-and-differences.pdf');plt.close(fig)
    fig,ax=plt.subplots(3,4,figsize=(17,10),layout='constrained')
    for k in range(3):
        values=d['green_normalized'] if k==0 else 100*(d['ratios'][:,k-1]-1)
        limits=(0,1.1) if k==0 else tuple(np.percentile(values[:,core],[1,99]))
        for j,label in enumerate(labels):
            im=image(ax[k,j],values[j],label+' · '+('G' if k==0 else ('R/G' if k==1 else 'B/G')),
                     limits,'gray' if k==0 else 'RdBu_r')
        fig.colorbar(im,ax=list(ax[k,:]),shrink=.7)
    fig.suptitle('四张真实 RAW 分开检查：不把组内变化平均掉\n无去马赛克、无镜头元数据校正；上下边缘条带与颜色宽结构分别观察',fontsize=14)
    fig.savefig(a.output/'all-four-frames.png');plt.close(fig)
    fig,ax=plt.subplots(2,3,figsize=(14,8),layout='constrained')
    for k,name in enumerate(('R/G','B/G')):
        for g in (0,1):
            for sector in range(8):
                prof=d['sectors'][g*2:g*2+2,k,sector].mean(axis=0)
                ax[k,g].plot(r[interval],prof[interval],lw=1,label=f'{sector*45}–{(sector+1)*45}°')
            ax[k,g].set_title(('A' if g==0 else 'B')+' · '+name+' · 八方位')
        for j,label in enumerate(labels):
            ax[k,2].plot(r[interval],d['profiles'][j,k,interval],label=label,color=colors[j])
        ax[k,2].set_title(name+' · 全环均值')
        for x in ax[k,:]:x.set_xlabel('半径 / 半幅高');x.set_ylabel('相对中心 / %');x.grid(alpha=.2)
    ax[0,0].legend(ncol=2,fontsize=7);ax[0,2].legend(fontsize=8)
    fig.suptitle('方向对照：宽环叠加不对称，径向平均不代表纯圆对称校正',fontsize=14)
    fig.savefig(a.output/'sector-controls.png');plt.close(fig)
    value=dict(ok=True,input_sha256=file_sha(source),figures=[dict(name=p.name,sha256=file_sha(p)) for p in sorted(a.output.glob('*')) if p.suffix in ('.png','.pdf')])
    (a.output/'result.json').write_text(json.dumps(value,indent=2),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True,figures=len(value['figures']))))


if __name__=='__main__':main()

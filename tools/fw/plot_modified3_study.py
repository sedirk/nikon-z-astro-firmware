"""Render physical RAW comparisons with shared scales and visible limitations."""
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from modified3_study_common import ROOT,ROUND,read,write,record

plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Microsoft YaHei','DejaVu Sans'],
                    'axes.unicode_minus':False,'font.size':10,'figure.dpi':140})

def image(ax,values,title,limits,cmap='RdBu_r'):
    im=ax.imshow(values,origin='upper',extent=(0,6048,4016,0),interpolation='nearest',
                 vmin=limits[0],vmax=limits[1],cmap=cmap)
    ax.set_title(title);ax.set_xlabel('有效区 X / 像素');ax.set_ylabel('有效区 Y / 像素')
    return im

def save(fig,out,name,pdf=False):
    fig.savefig(out/(name+'.png'))
    if pdf:fig.savefig(out/(name+'.pdf'))
    plt.close(fig)

def main():
    out=ROUND/'figures';out.mkdir(exist_ok=False)
    d=np.load(ROUND/'flats/maps.npz');dark=np.load(ROUND/'darks-v2/arrays.npz')
    r=d['radial_centres'];interval=(r>=.15)&(r<=.9);core=(d['radius']>=.15)&(d['radius']<=.9)
    colors=['#1666a6','#4196c6','#77b7ce','#b73835','#d77446','#e8a65f']
    fig,ax=plt.subplots(2,3,figsize=(15,8.1),layout='constrained')
    for k,name in enumerate(('R/G','B/G')):
        v=100*(d['group_ratios'][:2,k]-1);lim=max(.5,np.ceil(np.percentile(abs(v[:,core]),99)*2)/2)
        for g in (0,1):
            im=image(ax[k,g],v[g],f'modified{g+2} · {name}（三帧均值）',(-lim,lim))
            fig.colorbar(im,ax=ax[k,g],shrink=.72,label='相对各自中心 / %')
        for j,ident in enumerate(d['ids'][:6]):
            ax[k,2].plot(r[interval],d['profiles'][j,k,interval],color=colors[j],label=f'm{2 if j<3 else 3} · {ident}',lw=1.2)
        ax[k,2].plot(r[interval],d['group_profiles'][2,k,interval],color='gray',ls=':',label='m2 较早两帧',lw=1.2)
        ax[k,2].set_title(name+' · 逐帧径向剖面');ax[k,2].set_xlabel('半径 / 半幅高（2012 像素）')
        ax[k,2].set_ylabel('相对各自中心 / %');ax[k,2].grid(alpha=.2);ax[k,2].legend(fontsize=8,ncol=2)
    fig.suptitle('modified2 与确认刷入的 modified3：宽环状颜色结构仍在\n'
                 'ISO1600 · f/1.8 · 1/8000s；16×16 浮点 CFA，无去马赛克；同光源，位置／对焦可能移动',fontsize=14)
    save(fig,out,'modified3-ring-comparison',True)

    fig,ax=plt.subplots(3,3,figsize=(15,10.7),layout='constrained')
    for k,name in enumerate(('G 亮度','R/G','B/G')):
        values=d['group_green'][:2] if k==0 else 100*(d['group_ratios'][:2,k-1]-1)
        limits=(0,1.15) if k==0 else tuple(np.percentile(values[:,core],[1,99]))
        for g in (0,1):
            im=image(ax[k,g],values[g],f'modified{g+2} · {name}',limits,'gray' if k==0 else 'RdBu_r')
            fig.colorbar(im,ax=ax[k,g],shrink=.7)
        diff=d['green_difference_percent'] if k==0 else d['ratio_difference_percent'][k-1]
        lim=float(np.percentile(abs(diff[core]),99))
        im=image(ax[k,2],diff,'m3 / m2 − 1（各自中心归一）/ %',(-lim,lim));fig.colorbar(im,ax=ax[k,2],shrink=.7)
    fig.suptitle('实际保存 CFA 的空间差异\n颜色比例为伪彩色；差图包含照明、布置和曝光噪声，未作固件单独效果估计',fontsize=14)
    save(fig,out,'brightness-and-differences')

    fig,ax=plt.subplots(3,3,figsize=(15,10),layout='constrained')
    for k,name in enumerate(('G 亮度','R/G','B/G')):
        values=d['green_normalized'][:6] if k==0 else 100*(d['ratios'][:6,k-1]-1)
        limits=(0,1.15) if k==0 else tuple(np.percentile(values[:,core],[1,99]))
        for j in range(3):
            im=image(ax[k,j],values[j+3],f'modified3 · {d["ids"][j+3]} · {name}',limits,'gray' if k==0 else 'RdBu_r')
        fig.colorbar(im,ax=list(ax[k,:]),shrink=.7)
    fig.suptitle('modified3 三张平场逐张检查：条带和组内变化保留\n未对图像做行列扣除、镜头校正或空间配准',fontsize=14)
    save(fig,out,'modified3-individual-flats')

    fig,ax=plt.subplots(2,3,figsize=(14.5,8),layout='constrained')
    for k,name in enumerate(('R/G','B/G')):
        for g in (0,1):
            for s in range(8):
                prof=d['sectors'][g*3:g*3+3,k,s].mean(axis=0)
                ax[k,g].plot(r[interval],prof[interval],label=f'{s*45}–{(s+1)*45}°',lw=1)
            ax[k,g].set_title(f'modified{g+2} · {name} · 八方位')
        for g in (0,1,2):
            ax[k,2].plot(r[interval],d['group_profiles'][g,k,interval],label=('m2 新三帧','m3 新三帧','m2 较早两帧')[g],ls=':' if g==2 else '-')
        for a in ax[k,:]:a.set_xlabel('半径 / 半幅高');a.set_ylabel('相对中心 / %');a.grid(alpha=.2)
        ax[k,2].legend(fontsize=9)
    ax[0,0].legend(fontsize=7,ncol=2)
    fig.suptitle('保留各方向对照：全环平均不代替纯圆对称结构识别',fontsize=14)
    save(fig,out,'sector-controls')

    labels=['原厂','modified1','modified2','modified3'];groups=[slice(0,2),slice(2,4),slice(4,7),slice(7,10)]
    palette=['#6f7780','#7d57a6','#277fb0','#d34c38']
    fig,ax=plt.subplots(1,2,figsize=(13.5,5.5),layout='constrained')
    order=np.argsort(dark['centres'][4:7].mean(axis=0));site=np.arange(1,113)
    for label,sl,col in zip(labels,groups,palette):
        ax[0].plot(site,dark['centres'][sl].mean(axis=0)[order],'.-',ms=3,lw=.8,color=col,label=label)
    ax[0].axhline(1008,color='gray',ls=':',label='元数据黑位 1008')
    ax[0].set_xlabel('冻结的 112 点（仅按 modified2 亮度排序）');ax[0].set_ylabel('保存码值 / DN')
    ax[0].set_title('同一批亮点仍保留强信号');ax[0].grid(alpha=.2);ax[0].legend(fontsize=9)
    for k,(label,sl,col) in enumerate(zip(labels,groups,palette)):
        counts=dark['fit'][sl].sum(axis=1)
        ax[1].bar(k,float(counts.mean()),color=col,width=.65)
        ax[1].text(k,float(counts.mean())+2,str(counts.tolist()),ha='center',fontsize=10)
    ax[1].set_xticks(range(4),labels);ax[1].set_ylim(0,125);ax[1].set_ylabel('符合原抑制关系的点数 / 112')
    ax[1].set_title('各帧 centre = max8 + 8k（k=0…7）')
    fig.suptitle('5 秒 ISO1600 暗场回归：modified3 延续既有补丁效果\n'
                 'modified2 / modified3 均为每帧 0/112 符合旧抑制关系；两版同一个点已在背景附近，其余 111 点保留强信号',fontsize=12)
    save(fig,out,'dark-regression',True)
    write(out/'result.json',dict(ok=True,inputs=[record(ROUND/'flats/maps.npz'),record(ROUND/'darks-v2/arrays.npz')],
              figures=[record(p) for p in sorted(out.iterdir()) if p.suffix in ('.png','.pdf')]))
    print('Rendered shared-scale RAW and dark regression figures.')

if __name__=='__main__':
    main()

"""Summarize observed broad colour structure without assigning a firmware cause."""
from pathlib import Path
import argparse,json
import numpy as np
from analyze_modified1_flats import plt,write_json,file_sha

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    with np.load(a.root/'spatial/maps.npz') as z:
        prof=z['radial_profiles_percent'];r=z['radial_centres'];rats=z['ratios'];biasrats=z['bias_subtracted_ratios'];rr=z['radius']
    with np.load(a.root/'scale-controls/coarse-maps.npz') as z:coarse=z['ratio_64']
    mask=(r>=.15)&(r<=.9);core=(rr>=.15)&(rr<=.9)
    summary=dict(scope=__doc__,range_note='Exploratory geometric-centre radial range 0.15–0.90 of half active height, selected after initial visual review; not a pre-registered detection.',channels=[])
    fig,axs=plt.subplots(2,3,figsize=(14,7.5),layout='constrained')
    for k,name in enumerate(['R/G','B/G']):
        vals=100*(coarse[:,k]-1);limits=np.percentile(vals,[1,99])
        for j in range(2):
            im=axs[k,j].imshow(vals[j],cmap='RdBu_r',vmin=limits[0],vmax=limits[1],extent=[0,6016,3968,0],interpolation='nearest')
            axs[k,j].set_title(f'{4864+j} · {name}（中心归一）');axs[k,j].set_xlabel('有效区 X / 像素');axs[k,j].set_ylabel('有效区 Y / 像素')
            fig.colorbar(im,ax=axs[k,j],shrink=.72,label='相对中心变化 / %')
            axs[k,2].plot(r,prof[j,k],label=str(4864+j),lw=1.4)
        show=(r>=.05)&(r<=1);lo=float(prof[:,k,show].min());hi=float(prof[:,k,show].max())
        axs[k,2].set_ylim(lo-.15,hi+.15)
        axs[k,2].set_xlim(.05,1);axs[k,2].set_xlabel('半径 / 半幅高');axs[k,2].set_ylabel('相对中心变化 / %');axs[k,2].legend();axs[k,2].grid(alpha=.2);axs[k,2].set_title(name+' 径向起伏')
        summary['channels'].append(dict(name=name,radial_range_percent_points=[float(np.ptp(prof[j,k,mask])) for j in range(2)],
            radial_profile_repeat_correlation=float(np.corrcoef(prof[0,k,mask],prof[1,k,mask])[0,1]),
            bias_control_core_abs_p95_percent=[float(np.percentile(abs(100*(biasrats[j,k]/rats[j,k]-1))[core],95)) for j in range(2)]))
    fig.suptitle('两张候选平场：仍有宽环状颜色起伏，来源待区分\n左图为 64×64 浮点分箱；右图为 16×16 分箱后的圆环均值；伪彩色显示比例，不是照片实际颜色',fontsize=14)
    fig.savefig(a.output/'flat-first-result.png');fig.savefig(a.output/'flat-first-result.pdf');plt.close(fig)
    summary.update(ok=True,script_sha256=file_sha(__file__))
    write_json(a.output/'result.json',summary);(a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(summary,indent=2))
if __name__=='__main__':main()

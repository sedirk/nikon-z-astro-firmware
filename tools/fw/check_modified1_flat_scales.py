"""Coarser CFA means and independent scalar checks for exploratory flat analysis."""
from pathlib import Path
import argparse,json
import numpy as np
import rawpy
from scipy.ndimage import gaussian_filter
from analyze_modified1_flats import register,ratios,stats,file_sha,need,write_json,plt,PHASES

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    report=json.loads((a.input/'result.json').read_text(encoding='utf8'))
    with np.load(a.input/'maps.npz') as z:codes=z['codes'];bias=z['bias_mean'];rawrat=z['ratios']
    out=dict(scope=__doc__,scalar_checks=[],scales=[],source_sha256=file_sha(a.input/'maps.npz'),
             note='Coarser unfiltered maps and band-pass views are controls, not calibrated sensitivity limits.')
    # Recompute selected original CFA block means with Python integer summation,
    # independent of reshape/axis averaging; include edges and centre.
    sites=[(0,0),(0,377),(250,0),(250,377),(125,189),(100,100),(40,310),(180,50)]
    for j,case in enumerate(report['files']):
        with rawpy.imread(case['path']) as r:
            for by,bx in sites:
                for k,(_,dy,dx) in enumerate(PHASES):
                    vals=[int(r.raw_image[8+by*16+dy+2*y,8+bx*16+dx+2*x]) for y in range(8) for x in range(8)]
                    value=sum(vals)/64
                    need(value==codes[j,k,by,bx],'Scalar CFA bin mismatch')
                    out['scalar_checks'].append(dict(frame=case['name'],phase=k,block=[by,bx],value=value))
    # Rebin stored means before taking ratios (not averaging ratios).
    fig,axs=plt.subplots(2,4,figsize=(16,8),layout='constrained');saved={}
    for si,factor in enumerate([2,4]):
        h,w=codes.shape[-2:];ny,nx=h//factor,w//factor
        b=codes[:,:,:ny*factor,:nx*factor].reshape(2,4,ny,factor,nx,factor).mean(axis=(3,5))-1008
        reg=np.stack([register(v,16*factor) for v in b]);rr=np.stack([ratios(v) for v in reg]);saved[f'ratio_{16*factor}']=rr
        for k,name in enumerate(['R/G','B/G']):
            col=si*2+k;vals=100*(rr[0,k]-1);lo,hi=np.percentile(vals,[1,99])
            im=axs[0,col].imshow(vals,cmap='RdBu_r',vmin=lo,vmax=hi,extent=[0,nx*16*factor,ny*16*factor,0]);fig.colorbar(im,ax=axs[0,col],shrink=.7)
            axs[0,col].set_title(f'4864 {name} · {16*factor} 像素分箱 / %')
            # Additional smoothing 32 sensor pixels and broad component 192px.
            fine=gaussian_filter(rr[0,k],32/(16*factor),mode='reflect')
            broad=gaussian_filter(rr[0,k],192/(16*factor),mode='reflect')
            view=100*(fine/broad-1);edge=max(1,round(192/(16*factor)*3));inner=view[edge:-edge,edge:-edge]
            lim=np.percentile(abs(inner),99)
            im=axs[1,col].imshow(view,cmap='RdBu_r',vmin=-lim,vmax=lim,extent=[0,nx*16*factor,ny*16*factor,0]);fig.colorbar(im,ax=axs[1,col],shrink=.7)
            axs[1,col].set_title('32–192 像素平滑尺度间的变化 / %')
        out['scales'].append(dict(bin_sensor_pixels=16*factor,shape=list(rr.shape),
            unfiltered_percent=[dict(name=n,frames=[stats(100*(rr[j,k]-1)) for j in range(2)]) for k,n in enumerate(['R/G','B/G','G1/G2'])]))
    for ax in axs.ravel():ax.set_xlabel('有效区 X / 像素');ax.set_ylabel('有效区 Y / 像素')
    fig.suptitle('降低随机噪声后的空间结构：两种浮点分箱尺度\n缓慢渐变、光源纹理和滤波残差均保留解释空间；此图不代表消圈验收',fontsize=14)
    fig.savefig(a.output/'flat-coarse-controls.png');plt.close(fig)
    np.savez_compressed(a.output/'coarse-maps.npz',**saved)
    out.update(ok=True,scalar_check_count=len(out['scalar_checks']),script_sha256=file_sha(__file__))
    write_json(a.output/'result.json',out);(a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True,scalar_checks=len(out['scalar_checks']),scales=[32,64])))
if __name__=='__main__':main()

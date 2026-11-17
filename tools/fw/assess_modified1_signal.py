"""Summarize locked-site changes, background controls, and actual NEF plots."""
from pathlib import Path
import argparse,hashlib,json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from audit_nef import file_sha
ROOT=Path(__file__).resolve().parents[2]
plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Microsoft YaHei','DejaVu Sans'],
                    'axes.unicode_minus':False,'font.size':10})
def need(value,msg):
    if not value:raise ValueError(msg)
def summarize(v):
    return dict(n=int(v.size),mean=float(v.mean(dtype=np.float64)),median=float(np.median(v)),
                min=float(v.min()),max=float(v.max()))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--audit',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);r=json.loads(a.audit.read_text(encoding='utf8'))
    zpath=a.audit.parent/'arrays.npz'
    with np.load(zpath) as z:ids=z['ids'].tolist();hist=z['histograms'].astype(np.uint64);patches=z['target_patches_9x9']
    frames={v['id']:v for v in r['files']};targets=r['targets'];summary=[];group={}
    # Independent scalar pixel/kernel verification using persisted raw patches.
    verified=0
    for i,ident in enumerate(ids):
        row=frames[ident];g=row['group'];j=r['groups'][g].index(ident);f=hist[i].sum(axis=0);n=int(f.sum())
        centres=[];maxima=[];neighbour_values=[]
        for k,t in enumerate(targets):
            offsets=[(-2,0),(2,0),(0,-2),(0,2),(-1,-1),(-1,1),(1,-1),(1,1)] if t['phase'].startswith('G') else [(dy,dx) for dy in (-2,0,2) for dx in (-2,0,2) if dy or dx]
            centre=int(patches[i,k,4,4]);neighbors=[int(patches[i,k,4+dy,4+dx]) for dy,dx in offsets]
            want=t['groups'][g]
            need(centre==want['centres'][j] and max(neighbors)==want['max8'][j],'Scalar target mismatch')
            centres.append(centre);maxima.append(max(neighbors));neighbour_values.extend(neighbors);verified+=1
        centre=np.array(centres);mx=np.array(maxima);d=centre-mx
        got=dict(id=ident,group=g,fnumber=row['metadata']['ExifIFD:FNumber'],time=row['metadata']['ExifIFD:DateTimeOriginal'],
            pixels=n,whole_saturated=int(f[16383]),whole_zero=int(f[0]),whole_over_black100=int(f[1109:].sum()),
            whole_over_black1000=int(f[2009:].sum()),whole_over_5000=int(f[5001:].sum()),
            target_saturated=int((centre==16383).sum()),target_centre=summarize(centre),
            target_neighbors=summarize(np.array(neighbour_values)),target_max8=summarize(mx),
            target_delta=summarize(d),fingerprint_fit=int(((d>=0)&(d<=56)&(d%8==0)).sum()),
            mean_stored=float(np.dot(f.astype(np.float64),np.arange(65536))/n),
            median_stored=int(np.searchsorted(np.cumsum(f),n/2)))
        summary.append(got)
    byid={s['id']:s for s in summary}
    for g,seq in r['groups'].items():
        group[g]=dict(centres=summarize(np.array([t['groups'][g]['centres'] for t in targets])),
            neighbour_mean=float(np.mean([byid[i]['target_neighbors']['mean'] for i in seq])),
            neighborhood_maximum_mean=float(np.mean([byid[i]['target_max8']['mean'] for i in seq])),
            saturated_target_observations=sum(byid[i]['target_saturated'] for i in seq),
            saturated_whole_observations=sum(byid[i]['whole_saturated'] for i in seq))
    old=np.array([t['groups']['stock_dark']['centres'] for t in targets]);new=np.array([t['groups']['modified_dark']['centres'] for t in targets])
    oldmean=old.mean(axis=1);newmean=new.mean(axis=1)
    matched=dict(stock_id=4854,modified_ids=[4860,4861],fnumber=1.8,
        locked_sites=112,old_fit=byid[4854]['fingerprint_fit'],new_fit=[byid[i]['fingerprint_fit'] for i in (4860,4861)],
        mean_dark_change=summarize(newmean-old[:,0]))
    # Use the old-bias brightness only to order all 112 points, never to select new ones.
    order=np.argsort([np.mean(t['groups']['stock_bias']['centres']) for t in targets])
    fig,axes=plt.subplots(2,2,figsize=(12.8,8.2),layout='constrained')
    ax=axes[0,0]
    ax.scatter(np.arange(112),oldmean[order],s=15,color='#b26724',label='原版：两张 dark 均值')
    ax.scatter(np.arange(112),newmean[order],s=15,color='#1976b3',label='候选：两张 f/1.8 dark 均值')
    ax.axhline(16383,color='#a84b58',lw=.8,ls='--');ax.set_ylim(0,17400)
    ax.set_title('固定112个位置的保存码值');ax.set_xlabel('按原版 bias 亮度排序，包含全部112点');ax.set_ylabel('14位保存码值 DN');ax.legend(fontsize=9)
    darkids=[4854,4855,4860,4861,4862];labels=['原版4854\nf/1.8','原版4855\nf/22','候选4860\nf/1.8','候选4861\nf/1.8','候选4862\nf/20']
    colors=['#b26724','#b26724','#1976b3','#1976b3','#799bc6']
    ax=axes[0,1];counts=[byid[i]['fingerprint_fit'] for i in darkids];bars=ax.bar(np.arange(5),counts,color=colors)
    ax.bar_label(bars,padding=3);ax.set_xticks(np.arange(5),labels,fontsize=9);ax.set_ylim(0,130);ax.set_ylabel('符合的目标点数 / 112')
    ax.set_title('中心 = 最近同色 max8 + 8×k，k=0…7')
    ax=axes[1,0];codes=np.arange(950,1081)
    for seq,label,color in (([4854,4855],'原版5秒 dark','#b26724'),([4860,4861],'候选5秒 dark','#1976b3')):
        h=hist[[ids.index(i) for i in seq]].sum(axis=(0,1));ax.plot(codes,h[codes]/h.sum()*100,color=color,label=label)
    ax.axvline(1008,color='#666666',lw=.8,ls='--',label='元数据黑位 1008');ax.set_title('全幅暗背景分布（展示中心区间）')
    ax.set_xlabel('保存码值 DN');ax.set_ylabel('像素比例 % / DN');ax.legend(fontsize=9)
    ax=axes[1,1];sat=[byid[i]['whole_saturated'] for i in darkids];bars=ax.bar(np.arange(5),sat,color=colors)
    ax.bar_label(bars,padding=3);ax.set_xticks(np.arange(5),labels,fontsize=9);ax.set_ylim(0,125)
    ax.set_title('全幅有效区达到16383的像素');ax.set_ylabel('饱和像素数 / 24,337,152')
    fig.suptitle('首次实机 NEF：预先锁定的112点邻域抑制指纹消失',fontsize=16)
    fig.supxlabel('同一台一代Z6 · ISO1600 · 5秒 · 14位无损；无去马赛克。原版与候选相隔约10小时，温度未记录。',fontsize=10)
    fig.savefig(a.output/'modified1-evidence.png',dpi=150);fig.savefig(a.output/'modified1-evidence.pdf');plt.close(fig)
    # Full tabular point record, JSON only; avoid any mutation of samples.
    examples=[]
    for k in order[[0,len(order)//2,-1]].tolist():
        t=targets[k];examples.append(dict(x=t['x'],y=t['y'],phase=t['phase'],
            selection='fixed old-bias brightness rank: first/middle/last',groups=t['groups']))
    report=dict(ok=True,scope=__doc__,audit_sha256=file_sha(a.audit),arrays_sha256=file_sha(zpath),
        scalar_patch_checks=verified,frames=summary,group_summaries=group,matched_f18_comparison=matched,
        examples=examples,temperature='Not recorded; original and candidate are about ten hours apart.',
        aperture_note='Stock 4855 f/22 and modified 4862 f/20 are capped darks; f/1.8-only comparison also reported.',
        conclusion='All 112 preselected sites lose the old max8+8*k signature in each of three candidate 5s NEFs. Strong physical support for suppressor bypass by the candidate as a whole; individual patched lanes and full dark-current/ring goals remain separate.',
        plots=[dict(path=f.name,sha256=file_sha(f)) for f in (a.output/'modified1-evidence.png',a.output/'modified1-evidence.pdf')])
    (a.output/'result.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True,frames=summary,groups=group,matched=matched,scalar_patch_checks=verified),indent=2))
if __name__=='__main__':main()

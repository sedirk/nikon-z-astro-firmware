"""Render stored-NEF observations; this is an evidence plot, not an ISP model."""
from pathlib import Path
import argparse,json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT=Path(__file__).resolve().parents[2]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    r=json.loads((ROOT/'analysis/raw-neighborhood-2026-11-09/fingerprint/result.json').read_text())
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':11})
    fig,axes=plt.subplots(1,2,figsize=(12,4.6),constrained_layout=True)
    bins=np.arange(8)*8;bottom=np.zeros(8)
    for phase,color in [('R','#ca4747'),('G1','#398353'),('G2','#82bc72'),('B','#477eb9')]:
        vals=np.array([r['phases'][phase]['delta_histogram'].get(str(int(x)),0) for x in bins])
        axes[0].bar(bins,vals,bottom=bottom,width=5.8,color=color,label=phase);bottom+=vals
    for x,v in zip(bins,bottom):axes[0].text(x,v+2,str(int(v)),ha='center')
    axes[0].set(xticks=bins,xlabel='Saved centre - nearest same-color max8 (DN)',ylabel='Number of saved dark values',
        title='112 sites x 2 darks: all 224 fit max8 + 8*k',ylim=(0,180))
    axes[0].legend(ncol=4,frameon=False,loc='upper right')
    cats=['Selected\n112 sites','Nearby\nx - 32','Nearby\nx + 32','Swapped dark\nneighbours','Additional\nbias-only sites']
    counts=[112,0,0,r['controls'][2]['both_fit'],r['bias_only_additional_sites']['both_fit']]
    totals=[112,112,112,112,r['bias_only_additional_sites']['n']]
    rate=np.array(counts)/totals*100
    bars=axes[1].bar(np.arange(5),rate,color=['#447aa7','#a5aeb7','#a5aeb7','#bf9854','#739c82'],width=.65)
    for i,(v,n,t) in enumerate(zip(rate,counts,totals)):axes[1].text(i,v+2,f'{n}/{t}',ha='center')
    axes[1].set(xticks=np.arange(5),xticklabels=cats,ylim=(0,114),ylabel='Sites fitting in BOTH darks (%)',title='Controls from the same five captures')
    for ax in axes:ax.spines[['top','right']].set_visible(False);ax.set_axisbelow(True);ax.grid(axis='y',alpha=.15)
    fig.suptitle('Z6 C3.80 / ISO 1600 / two 5 s darks — stored CFA codes',fontsize=14)
    fig.savefig(a.output/'fingerprint.png',dpi=160);fig.savefig(a.output/'fingerprint.svg');plt.close(fig)
    (a.output/'source.py').write_bytes(Path(__file__).read_bytes())
    (a.output/'plot-note.json').write_text(json.dumps(dict(
        exploratory=True,independent_new_captures=False,
        note='Kernel/8-DN rule chosen after inspection. Bias-only extra sites exclude discovery112, but use the same captures.'),indent=2))
    print(json.dumps(dict(png=str(a.output/'fingerprint.png'),svg=str(a.output/'fingerprint.svg'))))


if __name__=='__main__':main()

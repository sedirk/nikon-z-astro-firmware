"""Shared-scale physical flat figures; no new dark result is drawn or implied."""
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from modified4_study_common import ROOT, ROUND, read, write, record
from plot_modified3_study import image, save


def main():
    out = ROUND/'figures'
    out.mkdir(exist_ok=False)
    d = np.load(ROUND/'flats/maps.npz')
    r = d['radial_centres']
    interval = (r >= .15) & (r <= .9)
    core = (d['radius'] >= .15) & (d['radius'] <= .9)
    colors = ['#1666a6', '#4196c6', '#77b7ce', '#b73835', '#d77446', '#e8a65f']
    fig, ax = plt.subplots(2, 3, figsize=(15, 8.1), layout='constrained')
    for k, name in enumerate(('R/G', 'B/G')):
        v = 100*(d['group_ratios'][:, k]-1)
        lim = max(.5, np.ceil(np.percentile(abs(v[:, core]), 99)*2)/2)
        for g in (0, 1):
            im = image(ax[k, g], v[g], f'modified{g+3} · {name}（三帧均值）', (-lim, lim))
            fig.colorbar(im, ax=ax[k, g], shrink=.72, label='相对各自中心 / %')
        for j, ident in enumerate(d['ids']):
            ax[k, 2].plot(r[interval], d['profiles'][j, k, interval], color=colors[j],
                         label=f'm{3 if j < 3 else 4} · {ident}', lw=1.2)
        ax[k, 2].set_title(name+' · 逐帧径向剖面')
        ax[k, 2].set_xlabel('半径 / 半幅高（2012 像素）')
        ax[k, 2].set_ylabel('相对各自中心 / %')
        ax[k, 2].grid(alpha=.2)
        ax[k, 2].legend(fontsize=8, ncol=2)
    fig.suptitle('modified3 与确认刷入的 modified4：宽环仍在，未见整体改善\n'
                 'ISO1600 · f/1.8 · 1/8000s；16×16 浮点 CFA，无去马赛克；同光源，位置／对焦可能移动', fontsize=14)
    save(fig, out, 'modified4-ring-comparison', True)

    fig, ax = plt.subplots(3, 3, figsize=(15, 10.7), layout='constrained')
    for k, name in enumerate(('G 亮度', 'R/G', 'B/G')):
        values = d['group_green'] if k == 0 else 100*(d['group_ratios'][:, k-1]-1)
        limits = (0, 1.15) if k == 0 else tuple(np.percentile(values[:, core], [1, 99]))
        for g in (0, 1):
            im = image(ax[k, g], values[g], f'modified{g+3} · {name}', limits, 'gray' if k == 0 else 'RdBu_r')
            fig.colorbar(im, ax=ax[k, g], shrink=.7)
        diff = d['green_difference_percent'] if k == 0 else d['ratio_difference_percent'][k-1]
        lim = float(np.percentile(abs(diff[core]), 99))
        im = image(ax[k, 2], diff, 'm4 / m3 − 1（各自中心归一）/ %', (-lim, lim))
        fig.colorbar(im, ax=ax[k, 2], shrink=.7)
    fig.suptitle('实际保存 CFA 的空间差异\n颜色比例为伪彩色；差图包含照明、布置和曝光噪声，未作固件单独效果估计', fontsize=14)
    save(fig, out, 'brightness-and-differences')

    fig, ax = plt.subplots(3, 3, figsize=(15, 10), layout='constrained')
    for k, name in enumerate(('G 亮度', 'R/G', 'B/G')):
        values = d['green_normalized'] if k == 0 else 100*(d['ratios'][:, k-1]-1)
        limits = (0, 1.15) if k == 0 else tuple(np.percentile(values[:, core], [1, 99]))
        for j in range(3):
            im = image(ax[k, j], values[j+3], f'modified4 · {d["ids"][j+3]} · {name}', limits, 'gray' if k == 0 else 'RdBu_r')
        fig.colorbar(im, ax=list(ax[k, :]), shrink=.7)
    fig.suptitle('modified4 三张平场：条带与组内变化保留\n未对照片做行列扣除、镜头校正或帧间配准', fontsize=14)
    save(fig, out, 'modified4-individual-flats')

    fig, ax = plt.subplots(2, 3, figsize=(14.5, 8), layout='constrained')
    for k, name in enumerate(('R/G', 'B/G')):
        for g in (0, 1):
            for s in range(8):
                profile = d['sectors'][g*3:g*3+3, k, s].mean(axis=0)
                ax[k, g].plot(r[interval], profile[interval], label=f'{s*45}–{(s+1)*45}°', lw=1)
            ax[k, g].set_title(f'modified{g+3} · {name} · 八方位')
            ax[k, 2].plot(r[interval], d['group_profiles'][g, k, interval], label=f'modified{g+3}')
        for a in ax[k, :]:
            a.set_xlabel('半径 / 半幅高')
            a.set_ylabel('相对中心 / %')
            a.grid(alpha=.2)
        ax[k, 2].legend(fontsize=9)
    ax[0, 0].legend(fontsize=7, ncol=2)
    fig.suptitle('各方向对照：全环平均不代替纯圆对称结构识别', fontsize=14)
    save(fig, out, 'sector-controls')
    write(out/'result.json', dict(ok=True, inputs=[record(ROUND/'flats/maps.npz')],
        figures=[record(p) for p in sorted(out.iterdir()) if p.suffix in ('.png', '.pdf')],
        no_modified4_dark_figure=True))
    print('Rendered shared-scale modified3/modified4 RAW comparisons.')


if __name__ == '__main__':
    main()

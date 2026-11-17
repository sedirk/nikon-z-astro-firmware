"""Plot raw CFA flat-field chromatic structures and BIAS/DARK regression for 11.12_modified7."""
from pathlib import Path
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/modified7-real-2026-11-12'

plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['Microsoft YaHei', 'DejaVu Sans'],
    'axes.unicode_minus': False,
})

a = np.load(OUT / 'flats/maps.npz')
r = a['radial_centres']
keep = (r >= 0.15) & (r <= 0.90)
g_slices = [slice(0, 2), slice(2, 4), slice(4, 7)]
g_labels = ['modified4 (11.10)', 'modified6 (11.10)', 'modified7 (11.12)']
g_colors = ['tab:blue', 'tab:orange', 'tab:green']

# Figure 1: 2D central-normalized R/G & B/G maps + unfiltered radial + high-pass sigma=6 radial
fig, axes = plt.subplots(2, 4, figsize=(18, 8.2), layout='constrained')
for k, name in enumerate(('R/G', 'B/G')):
    values = 100 * (a['group_ratios'][:, k] - 1)
    limit = float(np.percentile(np.abs(values), 98))
    for j in (0, 2):
        col = 0 if j == 0 else 1
        im = axes[k, col].imshow(values[j], vmin=-limit, vmax=limit, cmap='RdBu_r', interpolation='nearest')
        axes[k, col].set_title(f'{g_labels[j]} {name} / 中央归一 (%)')
        axes[k, col].set_xticks([]); axes[k, col].set_yticks([])
        fig.colorbar(im, ax=axes[k, col], shrink=0.8)
    for j, (sl, lbl, clr) in enumerate(zip(g_slices, g_labels, g_colors)):
        pp = a['profiles'][sl, k]
        for frame in pp:
            axes[k, 2].plot(r[keep], frame[keep], color=clr, alpha=0.22, linewidth=0.7)
        axes[k, 2].plot(r[keep], pp.mean(axis=0)[keep], label=lbl, color=clr, linewidth=1.6)
    axes[k, 2].plot(r[keep], a['b7_bias_profiles'][k, keep], '--', color='black', linewidth=1.0, label='modified7 (扣实测Master BIAS)')
    axes[k, 2].set_title(f'{name} 径向剖面（未经平滑）')
    axes[k, 2].set_xlabel('半径 / 2012像素'); axes[k, 2].set_ylabel('百分点')
    axes[k, 2].grid(alpha=0.2); axes[k, 2].legend(fontsize=8)

    for j, (lbl, clr) in enumerate(zip(g_labels, g_colors)):
        axes[k, 3].plot(r[keep], a['group_hp6_profiles'][j, k, keep], label=lbl, color=clr, linewidth=1.4)
    axes[k, 3].plot(r[keep], a['b7_bias_hp6'][k, keep], '--', color='black', linewidth=1.0, label='modified7 (扣Master BIAS)')
    axes[k, 3].set_title(f'{name} 细环残差剖面（高通 σ=6 仅展示）')
    axes[k, 3].set_xlabel('半径 / 2012像素'); axes[k, 3].set_ylabel('百分点')
    axes[k, 3].grid(alpha=0.2); axes[k, 3].legend(fontsize=8)

fig.suptitle('11.12 modified7 vs modified4/6：原始 CFA，扣黑位1008（含实测 Master BIAS 对照），不去马赛克或镜头校正')
fig.savefig(OUT / 'ring-comparison.png', dpi=140)
plt.close(fig)

# Figure 2: Normalized Green brightness & difference
fig, ax = plt.subplots(1, 3, figsize=(14, 4.7), layout='constrained')
for col, (j, lbl) in enumerate(((0, 'modified4 (11.10)'), (2, 'modified7 (11.12)'))):
    im = ax[col].imshow(a['group_green'][j], vmin=0.3, vmax=1.5, cmap='gray')
    ax[col].set_title(f'{lbl} G / 中央归一')
    fig.colorbar(im, ax=ax[col], shrink=0.8)
im = ax[2].imshow(a['green_group_difference_m7_vs_m4_percent'], vmin=-20, vmax=20, cmap='RdBu_r')
ax[2].set_title('归一G差异 modified7 / modified4 − 1 (%)')
fig.colorbar(im, ax=ax[2], shrink=0.8)
for x in ax:
    x.set_xticks([]); x.set_yticks([])
fig.savefig(OUT / 'brightness-comparison.png', dpi=140)
plt.close(fig)

# Figure 3: BIAS & DARK 112-site local suppression regression
bd = json.loads((OUT / 'bias-dark/result.json').read_text(encoding='utf8'))
lock = json.loads((ROOT / 'outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json').read_text(encoding='utf8'))
stock_d = np.mean([np.array([t['dark_centres'][k] - t['nearest_color_max'][k] for t in lock['targets']]) for k in (0, 1)], axis=0)
m4_d = np.mean([r['deltas'] for r in bd['dark_files'] if r['group'] == 'modified4_11.10_dark'], axis=0)
m7_d = np.mean([r['deltas'] for r in bd['dark_files'] if r['group'] == 'modified7_11.12_dark'], axis=0)
order = np.argsort(m7_d)

fig, ax = plt.subplots(1, 2, figsize=(13.5, 4.8), layout='constrained')
ax[0].plot(stock_d[order], 'o', markersize=3.5, label='原厂 C3.80 (4854-4855, 112/112 钳位 ≤56)', color='tab:red')
ax[0].plot(m4_d[order], '^', markersize=3.5, alpha=0.75, label='modified4 (4913-4914, 0/112 钳位)', color='tab:blue')
ax[0].plot(m7_d[order], 's', markersize=3.5, alpha=0.8, label='modified7 (4925-4927, 0/112 钳位)', color='tab:green')
ax[0].axhline(56, color='gray', linestyle='--', linewidth=0.9, label='原厂抑制上界 +56 DN')
ax[0].set_yscale('symlog', linthresh=100)
ax[0].set_title('冻结112暗场位点：中心码值 − 同色8邻域最大值')
ax[0].set_xlabel('按 modified7 增量排序的位点序号 (0..111)'); ax[0].set_ylabel('centre − max8 (DN, symlog)')
ax[0].grid(alpha=0.2); ax[0].legend(fontsize=8)

phases = [p['channel'] for p in bd['modified7_net_signal']['phases']]
b_means = [p['bias_mean'] - 1008.0 for p in bd['modified7_net_signal']['phases']]
d_means = [p['dark_mean'] - 1008.0 for p in bd['modified7_net_signal']['phases']]
x_pos = np.arange(len(phases))
ax[1].bar(x_pos - 0.18, b_means, width=0.34, label='BIAS (4922-4924) 均值 − 1008', color='tab:cyan')
ax[1].bar(x_pos + 0.18, d_means, width=0.34, label='5s DARK (4925-4927) 均值 − 1008', color='tab:purple')
ax[1].set_xticks(x_pos, phases)
ax[1].set_title('modified7 四相位全画幅均值偏移与净暗场信号')
ax[1].set_ylabel('DN (相对黑位1008)'); ax[1].grid(alpha=0.2, axis='y'); ax[1].legend(fontsize=9)

fig.savefig(OUT / 'bias-dark-summary.png', dpi=140)
plt.close(fig)

print(json.dumps(dict(ok=True, figures=['ring-comparison.png', 'brightness-comparison.png', 'bias-dark-summary.png'])))

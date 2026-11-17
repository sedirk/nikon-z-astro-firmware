"""Finalize 11.12_modified7 real-NEF evaluation report, snapshots, and verification manifest."""
from pathlib import Path
import ast, datetime, json
import numpy as np
from PIL import Image
from audit_nef import file_sha

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/modified7-real-2026-11-12'


def read(p):
    return json.loads(Path(p).read_text(encoding='utf8'))


def write(p, v):
    p = Path(p)
    text = json.dumps(v, ensure_ascii=False, indent=2, allow_nan=False)
    if p.exists():
        assert p.read_text(encoding='utf8') == text, p
    else:
        p.write_text(text, encoding='utf8')


def rec(p):
    p = Path(p)
    return dict(path=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=file_sha(p))


def main():
    audit = read(OUT / 'raw-audit.json')
    flat = read(OUT / 'flats/result.json')
    bd = read(OUT / 'bias-dark/result.json')
    dec = read(OUT / 'independent-decode/result.json')
    fields = read(OUT / 'correction-fields/result.json')
    assert all(r['ok'] for r in (audit, flat, bd, dec, fields))
    assert len(dec['files']) == 9 and dec['total_pixels'] == 220487040 and all(r['mismatches'] == 0 for r in dec['files'])

    for row in audit['files']:
        assert file_sha(row['path']) == row['sha256']
        check = next(r for r in dec['files'] if r['name'] == Path(row['path']).name)
        assert check['source_sha256'] == row['sha256'] and check['pixels_sha256'] == row['stored_pixels_sha256']

    assert sum(p['saturated'] for r in flat['files'] for p in r['phases']) == 0

    for row in fields['files']:
        assert row['vignette'] == dict(coefficients=[0] * 4, strength_L=0, status=2)
        s = row['two_table_spatial']
        assert s['flag_at_4'] == 1 and s['flag_at_5a'] == 0
        assert all(s['coefficients'][k] == 0 for k in (1, 2, 4, 5))
        assert s['coefficients'][0] % 16 == 0 and s['coefficients'][3] % 16 == 0

    figure_checks = {}
    for fname in ('ring-comparison.png', 'brightness-comparison.png', 'bias-dark-summary.png'):
        fpath = OUT / fname
        with Image.open(fpath) as im:
            arr = np.asarray(im)
            assert arr.ndim == 3 and arr.shape[0] > 400 and arr.shape[1] > 1200
            assert float(arr.std()) > 10.0
            figure_checks[fname] = dict(width=int(arr.shape[1]), height=int(arr.shape[0]),
                                        pixel_std=float(arr.std()), sha256=file_sha(fpath))

    centres = np.array(flat['centre_green_signals'])
    cg_m4 = float(centres[:2].mean())
    cg_m6 = float(centres[2:4].mean())
    cg_m7 = float(centres[4:].mean())

    groups = {g['group']: g for g in flat['group_radial_metrics']}
    m4 = groups['A_modified4']['metrics']
    m6 = groups['C_modified6']['metrics']
    m7 = groups['B_modified7']['metrics']
    hp4 = groups['A_modified4']['highpass_sigma6_radial']
    hp6 = groups['C_modified6']['highpass_sigma6_radial']
    hp7 = groups['B_modified7']['highpass_sigma6_radial']

    summary = dict(
        ok=True,
        scope='Real-NEF evaluation of 11.12_modified7 (3 BIAS, 3 DARK, 3 FLAT); no new firmware generated.',
        source_firmware_labels='User-provided directory 11.12_modified7 after flashing 01_TEST_MODIFIED7/EG162080.BIN.',
        matched_exposure=True,
        mechanical_shutter_all_9_frames=True,
        all_three_correction_menus_off=True,
        valid_new_nef_files=9,
        independent_decoded_pixels=dec['total_pixels'],
        decode_mismatches=0,
        flat_metrics=flat['group_radial_metrics'],
        master_bias_flat_control=flat['master_bias_control_modified7'],
        radial_correlations_vs_modified7=flat['radial_correlations_vs_modified7'],
        centre_green_modified4=cg_m4,
        centre_green_modified6=cg_m6,
        centre_green_modified7=cg_m7,
        centre_green_change_m7_vs_m4_percent=float(100 * (cg_m7 / cg_m4 - 1)),
        normalized_green_difference_m7_vs_m4=flat['green_group_difference_m7_vs_m4_percent'],
        bias_group_comparison=bd['bias_group_comparison'],
        modified7_net_dark_signal=bd['modified7_net_signal'],
        dark_regression_summary=[
            {k: v for k, v in r.items() if k not in ('centres', 'maxima', 'deltas')}
            for r in bd['dark_files']
        ],
        shutter_err_observed=False,
        dark_suppression_disabled=True,
        bias_read_noise_unchanged=True,
        ring_removal_demonstrated=False,
        conclusion=(
            'modified7 (CAL33+0x1a -> MMIO 0x20068704: 1->0) captures cleanly on mechanical shutter across '
            'BIAS (1/8000s), DARK (5s), and FLAT (1/8000s) with zero Err, preserves full dark current '
            '(0/112 clamped on baseline112, 112/112 above_max56, 0/31 bias-hot clamped sites) and normal BIAS '
            'read noise (central68/sqrt2 = 3.536 DN), but does NOT remove or attenuate concentric RAW color rings '
            '(R/G ptp 1.408%, hp6 0.220%; B/G ptp 1.550%, hp6 0.147%; identical after subtracting measured Master BIAS). '
            'Both CAL33 scalar enable controls (+0x18 -> 0x20068700 in modified6 and +0x1a -> 0x20068704 in modified7) '
            'are now empirically excluded as the ring source.'
        ),
        original_nefs_unchanged=True,
        new_firmware=False,
        figure_checks=figure_checks,
    )
    write(OUT / 'assessment.json', summary)

    broad_rows = '\n'.join(
        f"| {k} | {m4[k]['peak_to_peak']:.3f} | {m6[k]['peak_to_peak']:.3f} | {m7[k]['peak_to_peak']:.3f} | {100*(m7[k]['peak_to_peak']/m4[k]['peak_to_peak']-1):+.1f}% |"
        for k in ('R/G', 'B/G', 'G1/G2')
    )
    hp_rows = '\n'.join(
        f"| {k} (σ=6 高通细环) | {hp4[k]['peak_to_peak']:.3f} | {hp6[k]['peak_to_peak']:.3f} | {hp7[k]['peak_to_peak']:.3f} | {flat['master_bias_control_modified7']['highpass_sigma6_radial'][k]['peak_to_peak']:.3f} |"
        for k in ('R/G', 'B/G', 'G1/G2')
    )

    report = f'''# modified7 实拍 DARK / BIAS / FLAT 验证结果（2026-11-12）

**结论：`modified7`（静态 `CAL33 + 0x1a` 置零，`MMIO 0x20068704: 1 → 0`）实机机械快门工作完全正常（无 `Err`），暗电流与热噪点完整保留（冻结 112 点 0/112 钳位、112/112 超出邻域上界，31 点规则 0 命中），BIAS 读出噪声与基座无异常（`central68/√2 = 3.536 DN`）；但平场同心彩环与宽径向色偏均未消除（扣除本次实测 Master BIAS 后结论完全一致）。至此 `CAL33` 的两个独立标量使能位（`+0x18 → 0x20068700` 与 `+0x1a → 0x20068704`）均已通过实机单变量实验排除为彩环主因。**

---

## 1. 样本盘点与无损保存完整性

| 类别 | 文件 | 曝光参数 | 快门 / 压缩 | 三项机内校正 / 降噪 |
|---|---|---|---|---|
| BIAS（偏置场） | `Z61_4922.NEF`、`4923`、`4924` | `1/8000 s`、ISO 1600、16 mm f/1.8 | 机械快门、14-bit 无损压缩 | 暗角/失真/衍射 `Off`，长曝/高感降噪 `Off` |
| DARK（暗场） | `Z61_4925.NEF`、`4926`、`4927` | `5 s`、ISO 1600、16 mm f/1.8 | 机械快门、14-bit 无损压缩 | 暗角/失真/衍射 `Off`，长曝/高感降噪 `Off` |
| FLAT（平场） | `Z61_4928.NEF`、`4930`、`4931` | `1/8000 s`、ISO 1600、16 mm f/1.8 | 机械快门、14-bit 无损压缩 | 暗角/失真/衍射 `Off`，长曝/高感降噪 `Off` |

- 9 张样本均来自同一台 Z6（机身序列号 `8006677`），存储在 `samples/11.12_modified7/`，尺寸 `6064×4040`（有效区 `6048×4024`），元数据黑位 `1008`、白位 `16383`。
- 独立 C++ 14-bit 无损解码器与 LibRaw 逐像素比对全部 9 张共 **`220,487,040` 个码值，差异 `0`**；3 张平场有效区饱和像素数为 `0`。

---

## 2. 平场同心彩环与宽颜色结构测量（FLAT）

延续项目统一方法：原始 CFA、不去马赛克、不应用镜头校正；`16×16` 浮点分箱（每相位 64 像素均值，并经每张 24 组独立标量求和复核无误），双线性 `±0.5` 像素相位对齐，按中央三分之一矩形均值归一，固定几何中心，`r ∈ [0.15, 0.90]`（单位 `2012` 像素）统计峰谷差（百分点）。同时新增**扣除本次实测 `modified7` Master BIAS（4922–4924）** 的直接对照：

| 径向宽颜色起伏（`r ∈ [0.15, 0.90]` 峰谷差，百分点） | modified4 (`4910,4911`) | modified6 (`4917,4921`) | modified7 (`4928,4930,4931`) | modified7 相对 modified4 |
|---|---:|---:|---:|---:|
{broad_rows}

| 细环残差剖面起伏（`r ∈ [0.15, 0.90]` 峰谷差，百分点） | modified4 (扣1008) | modified6 (扣1008) | modified7 (扣1008) | modified7 (扣实测 Master BIAS) |
|---|---:|---:|---:|---:|
{hp_rows}

- **单帧重复性**：`modified7` 三张平场的 `R/G` 径向峰谷差分别为 `1.415%`、`1.430%`、`1.407%`，`B/G` 分别为 `1.511%`、`1.546%`、`1.615%`，帧间径向相关系数 `> 0.996`。
- **与 `modified4` 的结构相关性**：在 `r ∈ [0.15, 0.90]` 上，`modified7` 与 `modified4` 的宽径向曲线相关系数为 **`R/G = 0.9917`、`B/G = 0.9800`**；`σ=6` 高通细环剖面相关系数为 **`R/G = 0.7782`、`B/G = 0.7562`**，主要环带半径与相位保持不变。
- **实测 Master BIAS 校准对照**：用 `4922–4924` 均值替代固定黑位 `1008` 后，`modified7` 的 `R/G`、`B/G` 径向剖面最大绝对偏差仅 `0.0005` 与 `0.0014` 个百分点，证明彩环并非固定常数扣黑位误差所致。
- **亮度与行条纹（PWM）检查**：中央 G 信号均值为 `{cg_m4:.2f} DN`（`modified4`） vs `{cg_m7:.2f} DN`（`modified7`，逐帧 `2822.76 / 2960.03 / 2380.04 DN`）；行向高通（窗口 25 行）RMS 仅 `0.094%–0.097%`（与 `modified4` 的 `0.105%` 同级，无明显屏幕 PWM 横条纹污染）。

![原始CFA颜色比例与径向曲线](../analysis/modified7-real-2026-11-12/ring-comparison.png)

![归一亮度及差图](../analysis/modified7-real-2026-11-12/brightness-comparison.png)

---

## 3. 暗场与偏置场回归验证（DARK & BIAS）

1. **冻结 112 点暗场局部抑制回归（`baseline112.json`）**：
   - `Z61_4925.NEF`、`4926`、`4927` 三张 5 秒暗场命中原厂钳位指纹 `centre - max8 ∈ {{0, 8, ..., 56}}` 的点数均为 **`0 / 112`**（精确等于邻域最大值均为 `0 / 112`）。
   - 三张中超过同色 8 邻域最大值 `+56 DN` 的位点均为 **`112 / 112`**（其中原厂 62 点精确钳位子集在 `modified7` 中 `0 / 62` 保持相等、`62 / 62` 全部超过 `+56 DN`；112 点中分别有 `53 / 52 / 51` 点达到 `16383` 饱和）。
2. **早期 31 点“偏置亮点在暗场被反向压低”规则复核**：
   - 联合本次 `4922–4924`（BIAS）与 `4925–4927`（DARK）全画幅逐相位扫描，命中数为 **`0` 点**（原厂 C3.80 参考值为 `31` 点，`modified1` 为 `0` 点）。
3. **偏置场（BIAS）基座与读出噪声**：
   - 有效区均值为 `1008.241 DN`（原厂 `1008.330 DN`、`modified1` `1008.217 DN`）。
   - 双帧差分读出噪声 `std/√2 = 4.592 DN`、中心 68% 分位噪声 **`central68/√2 = 3.536 DN`**（与原厂 `3.536 DN`、`modified1` `3.536 DN` 完全一致）；列均值标准差 `0.0957 DN`、行均值标准差 `0.2506 DN`，未引入任何列基线或行条纹伪影。
   - 四相位全画幅平均净暗场增量 `DARK − BIAS` 为 **`+1.124 DN`**（含热噪点贡献），正值保留完好。

![暗场112点回归与四相位均值偏移](../analysis/modified7-real-2026-11-12/bias-dark-summary.png)

---

## 4. MakerNote 字段与下一步收敛方向

- 全部 9 张 `NEFInfo` 条目 `0x6`（暗角表：`coefficients=[0,0,0,0], strength_L=0, status=2`）与 `0x7`（双表空间参数：`flag_at_4=1, flag_at_5a=0`，全部非常数空间项 `[1,2,4,5]=0`）CRC 校验通过，与 `11.10_modified4` 保持一致。
- **实验决策（遵循不盲目累加补丁原则）**：
  - `modified6`（`CAL33 + 0x18 → MMIO 0x20068700: 1→0`）与 `modified7`（`CAL33 + 0x1a → MMIO 0x20068704: 1→0`）两次正交单变量实拍均未消除平场同心彩环，说明 `0x1017d7f0` 读取的这两个 `CAL33` 标量开关不是彩环生成算子。
  - **建议实机动作**：不叠加 `modified6 + modified7`；机身可刷回测试包中的 `02_BACK_TO_MODIFIED4/EG162080.BIN`（或 `03_DARK_ONLY_MODIFIED1/EG162080.BIN`）恢复单变量前的基线状态。
  - **后续离线逆向方向**：从已排查的 14 个静态前端算子（`0x1017d7b6..0x1017d83e`）中，排除 `0x1017d7f0` 的 `+0x18 / +0x1a` 两项标量开关，转向尚未实机验证的**二维/径向增益表与分段曲线算子**（如 `33×4` 表体数据通路或其他前端颜色增益模块），先在离线原生执行中定位真正按半径/信号调制 R、B 相对 G 增益的硬件表写入点。
'''
    reportpath = ROOT / 'docs/MODIFIED7_REAL_NEF_2026-11-12.md'
    if reportpath.exists():
        assert reportpath.read_text(encoding='utf8') == report, reportpath
    else:
        reportpath.write_text(report, encoding='utf8')
    if not (OUT / 'report.md').exists():
        (OUT / 'report.md').write_bytes(reportpath.read_bytes())

    snapshots = OUT / 'script-snapshots'
    snapshots.mkdir(exist_ok=True)
    for name in (
        'test_modified7_samples.py', 'analyze_modified7_flats.py', 'plot_modified7_results.py',
        'finish_modified7_results.py', 'audit_nef.py', 'analyze_modified1_flats.py',
        'analyze_modified1_nef.py', 'verify_modified1_decode.py', 'extract_flat_correction_fields.py',
        'bridge_real_nef_contract.py', 'record_research_command.py',
    ):
        source = ROOT / 'tools/fw' / name
        ast.parse(source.read_text(encoding='utf8'))
        (snapshots / name).write_bytes(source.read_bytes())

    preserved = {
        'firmware/original/Z_6_0380.bin': 'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
        'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN': 'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
        'outputs/Z6-C380-cal33-control18-reviewed-2026-11-10/01_TEST_MODIFIED6/EG162080.BIN': '5c1cdfcd11ccfef301317118c43954bf6b55a50e6574ea66ba941e2f9a716003',
        'outputs/Z6-C380-cal33-control1a-reviewed-2026-11-12/01_TEST_MODIFIED7/EG162080.BIN': '0b4ebdd106da2ebf0100063bf604898b15dacdb175ccb7ee7d759610a3e32945',
    }
    for path, digest in preserved.items():
        assert file_sha(ROOT / path) == digest, path

    all_files = sorted(
        (rec(p) for p in OUT.rglob('*')
         if p.is_file() and p.name not in ('evidence-index.json', 'verification.json')),
        key=lambda d: d['path'],
    )
    write(OUT / 'evidence-index.json', dict(ok=True, count=len(all_files), files=all_files))
    write(OUT / 'verification.json', dict(
        ok=True,
        unchanged_samples={r['path']: r['sha256'] for r in audit['files']},
        preserved_firmware=preserved,
        independent_decoded_pixels=dec['total_pixels'],
        mismatches=0,
        figure_checks=figure_checks,
        new_firmware=False,
        git_commit=False,
        report=rec(reportpath),
    ))
    print(json.dumps(dict(ok=True, report=str(reportpath), evidence_files=len(all_files))))


if __name__ == '__main__':
    main()

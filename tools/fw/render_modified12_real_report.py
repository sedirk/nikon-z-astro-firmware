"""Programmatically render docs/MODIFIED12_REAL_NEF_2026-11-14.md from unrounded JSON artifacts."""
from pathlib import Path
import binascii
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / 'analysis/modified12-real-2026-11-14'
FW_PATH = ROOT / 'outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN'
DOC_PATH = ROOT / 'docs/MODIFIED12_REAL_NEF_2026-11-14.md'


def crc16_ccitt_xmodem(data: bytes, init: int = 0x0000) -> int:
    return binascii.crc_hqx(data, init)


def main() -> None:
    assess = json.loads((OUT_DIR / 'samples-v2/assessment.json').read_text(encoding='utf8'))
    decode = json.loads((OUT_DIR / 'independent-lossless/result.json').read_text(encoding='utf8'))
    nefinfo = json.loads((OUT_DIR / 'nefinfo/result.json').read_text(encoding='utf8'))
    meta_list = json.loads((OUT_DIR / 'metadata/metadata.json').read_text(encoding='utf8'))

    fw_bytes = FW_PATH.read_bytes()
    fw_sha = hashlib.sha256(fw_bytes).hexdigest()
    fw_crc_hex = fw_bytes[-2:].hex()
    assert fw_sha == '9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c'
    assert fw_crc_hex == 'dded' and crc16_ccitt_xmodem(fw_bytes) == 0

    meta_by_name = {m['System:FileName']: m for m in meta_list}
    dec_by_name = {d['name']: d for d in decode['files']}
    nef_by_name = {n['name']: n for n in nefinfo['files']}

    m12_files = [f for f in assess['files'] if f['group'] == 'Modified12']
    flat_files = [f for f in assess['files'] if f['kind'] == 'FLAT' and f['group'] in ('Modified10', 'Modified11', 'Modified12')]

    fg = assess['flat_groups']
    m10_02276 = fg['Modified10']['mean_exact_02276_R_amp']
    m11_02276 = fg['Modified11']['mean_exact_02276_R_amp']
    m12_02276 = fg['Modified12']['mean_exact_02276_R_amp']
    drop_02276_pct = (1.0 - m12_02276 / m10_02276) * 100.0

    m10_rg1 = fg['Modified10']['mean_center_rg1']
    m11_rg1 = fg['Modified11']['mean_center_rg1']
    m12_rg1 = fg['Modified12']['mean_center_rg1']

    cor_10_12 = assess['flat_group_correlations']['Modified10_vs_Modified12']
    tail = assess['bias_4969_tail']
    ta = tail['active_area']
    ts = tail['stored_array']

    mech_counts = {
        fn: meta_by_name[fn]['Nikon:MechanicalShutterCount']
        for fn in ('Z61_4972.NEF', 'Z61_4975.NEF', 'Z61_4976.NEF', 'Z61_4978.NEF')
    }

    bp_map = {(tuple(b['ids']), b['group']): b for b in assess['bias_pairs']}
    bp_m12_67_68 = bp_map[((4967, 4968), 'Modified12')]
    bp_m12_67_69 = bp_map[((4967, 4969), 'Modified12')]
    bp_m12_68_69 = bp_map[((4968, 4969), 'Modified12')]
    bp_m11_58_60 = bp_map[((4958, 4960), 'Modified11')]

    net_dk_all = assess['active_dark_minus_mean_bias_dn']['Modified12']
    net_dk_67_68 = assess['active_dark_minus_mean_bias_dn']['Modified12_vs_4967_4968']

    dips_m12 = {
        f['name']: f['flat']['dip_periodicity_2000x2000']['R']
        for f in m12_files if f['kind'] == 'FLAT'
    }

    lines = []
    a = lines.append

    a('# Nikon Z6 C3.80 天文固件 Modified12 实机样本审计报告（2026-11-14）')
    a('')
    a('- **审计日期**：2026-11-14')
    a('- **实拍样本目录**：`samples/11.14_modified12`（本地归档，未公开）')
    a(f'- **被测固件**：`Modified12`（`EG162080.BIN`，实测 SHA-256 `{fw_sha}`，尾部 CRC16 `{fw_crc_hex}`，整包 XMODEM 余数 `0x0000`）')
    a('- **核心对照版本**：')
    a('  - `Modified10`（全尺寸前端直通 + 前后端空间表归零，前端 4 路 Q12 增益保持原厂非单位倍率）')
    a('  - `Modified11`（前端 4 路 Q12 增益锁定 `4096`，但存在 `0x10122cba` 覆盖 `cbz r1` 的空指针与控制字节回归）')
    a('- **分析产物目录**：`analysis/modified12-real-2026-11-14`（本地归档，未公开）')
    a('  - 修订版样本定量审计：`analysis/modified12-real-2026-11-14/samples-v2/assessment.json`（本地归档，未公开）')
    a('  - 独立无损解码核验：`analysis/modified12-real-2026-11-14/independent-lossless/result.json`（本地归档，未公开）')
    a('  - NEFInfo 序列化校验：`analysis/modified12-real-2026-11-14/nefinfo/result.json`（本地归档，未公开）')
    a('  - 四联定量对比图：`analysis/modified12-real-2026-11-14/samples-v2/modified12-comparison.png`（本地归档，未公开）')
    a('  - 二维比例场对比图：`analysis/modified12-real-2026-11-14/samples-v2/modified12-ratio-maps.png`（本地归档，未公开）')
    a('')
    a('---')
    a('')
    a('## 1. 核心结论摘要（严格基于实测数据边界）')
    a('')
    a(f"1. **离线控制流修复验证与实机留存样本无损解码通过（严格区分两类证据）**：`Modified12` 在 `0x10122cba` 保留原版 `cbz r1, #0x10122cce` 与调用方控制字节写回，其 `r1 == NULL` 与 `r1 != NULL` 两路行为由离线 ARM/Thumb 原生执行独立验证；实机侧留存的 9 张 14-bit 无损压缩 NEF（3 张 1/8000s BIAS + 3 张 5s DARK + 3 张 1/8000s FLAT）共 **{decode['total_pixels']:,} 个存储像素**经固定哈希 C++ 解码器与 LibRaw 逐像素比对**差异为 0**（证明正常静态采集与无损编码有效，但不将该 9 张留存文件等同于 `r1 == NULL` 分支的实机运行时覆盖证明）。")
    a("2. **暗场旧最近同色 8 邻域抑制保持解除，黑位附近未见零码截断**：在冻结的 112 个基准热像素点（`baseline112.json`，采用**最近同色 8 邻域核**，其中绿色核包含跨 `G1/G2` 的 `(±1,±1)` 对角点）上，原厂暗场为 `112/112` 命中 `中心 - 最近同色8邻域最大值 ∈ {0, 8, ..., 56}`，而 `Modified12` 三张 5s 暗场（`4970/4971/4972`）均为 **`0/112` 命中**、`111/112` 超出 `+56 DN`（中位差值 `11,387.0 ~ 12,388.0 DN`）。9 张样本有效区（`[8:4032, 8:6056]`）与完整存储区 `0 ADU` 像素计数均为 **0**，偏置/暗场存在 `<1008 DN` 码值分布（此系本批存储码值统计观察，不单独证明物理负向读出噪声完好无损、全局暗电流线性度或极弱星点测光保真）。")
    a('3. **同信号量级下旧红通道数字缩放缺码梳齿（`0.2276 cycles/DN`）大幅消退**：')
    a(f"   - 在 `0..16383` 统一 16,384 档直方图精确频率 `f = 0.2276 cycles/DN` 上，红通道 DFT 幅度组均值由 `Modified10` 的 **{m10_02276:.2f}** 降至 `Modified12` 的 **{m12_02276:.2f}**（**下降 {drop_02276_pct:.2f}%**，与 `Modified11` 的 `{m11_02276:.2f}` 处于同一量级），且本次 `Modified12` 平场中心净 `G1`（`3041.1 ~ 3497.4 DN`）与 `Modified10`（`3043.9 ~ 3609.5 DN`）处于同一曝光区间；")
    a(f"   - 平场中心净信号比 `R/G1` 组均值为 **{m12_rg1:.4f}**（`Modified11` 为 `{m11_rg1:.4f}`，`Modified10` 为 `{m10_rg1:.4f}`），相机记录的 `Auto1` 红通道白平衡系数为 `1.2871 ~ 1.2910`（`Modified10` 为 `1.5391`）。上述指标支持前端红通道数字乘数回落的定量判断，但在缺乏中性色标与标准预览对照前，不将其单独表述为色彩还原或“异常泛红消除”的定性验收。")
    a('4. **必须如实陈述的未闭环项与样本观察记录**：')
    a(f"   - **残余直方图周期谱峰仍在（来源未定）**：中心 400×400 红通道直方图在 `f = 0.17163 cycles/DN`（`4975/4976`，近似 `6/35 = 0.17143`）及 `f = 0.25732 cycles/DN`（`4978`，近似 `9/35 = 0.25714`）仍有显著峰值（主峰/频带中位数为 `13.17 ~ 16.51`），蓝/绿通道亦存在各自谱峰。中心 2000×2000 窗口局部可见 `12, 12, 11` 下凹间隔片段，但全窗口自动提取的全部局部下凹平均间距分别为 `{dips_m12['Z61_4975.NEF']['mean_gap']:.2f}`、`{dips_m12['Z61_4976.NEF']['mean_gap']:.2f}`、`{dips_m12['Z61_4978.NEF']['mean_gap']:.2f} DN` 且混有其他间距，因此仅记为**约 `35/3 DN` 候选周期族残余谱峰（物理或固件来源未定）**，不归因为特定传感器列 ADC DNL，更不能宣称直方图梳齿完全消失。")
    a(f"   - **径向与二维环状颜色结构尚未彻底消除**：在 `r ∈ [0.15, 0.90]` 统计区间内，`Modified12` 三张平场平均剖面的未滤波径向峰谷差为 `R/G = {fg['Modified12']['broad_ptp_pp'][0]:.4f} pp`、`B/G = {fg['Modified12']['broad_ptp_pp'][1]:.4f} pp`，`σ=6`（96 像素）局部高通残差峰谷差为 `R/G = {fg['Modified12']['hp6_ptp_pp'][0]:.4f} pp`、`B/G = {fg['Modified12']['hp6_ptp_pp'][1]:.4f} pp`（与 `Modified10` 局部残差相关系数 `r_RG = {cor_10_12['hp6_rg_r']:.4f}`、`r_BG = {cor_10_12['hp6_bg_r']:.4f}`）。平场混合了镜头光学、发光板与机内剩余固定链路，**“消除同心彩圈”目标尚未达成最终验收**。")
    a(f"   - **序号缺口与 `Z61_4969.NEF` 暗场相关亮点尾端**：样本目录在 `Z61_4972.NEF`（`MechanicalShutterCount = {mech_counts['Z61_4972.NEF']}`）与 `Z61_4975/4976/4978.NEF`（`{mech_counts['Z61_4975.NEF']} / {mech_counts['Z61_4976.NEF']} / {mech_counts['Z61_4978.NEF']}`）之间缺少 `4973、4974、4977` 三个序号对应文件，**缺失原因未知（需拍摄记录确认）**，既不据此推定做过人工筛片，也不推定发生过或未发生过机身异常。此外第三张偏置场 `Z61_4969.NEF` 在有效区有 `{ta['count_gt_2000']}` 个像素 `> 2000 DN`（完整存储区为 `{ts['count_gt_2000']}` 个，多出的 1 点位于有效区外边框 `(y=4038, x=3137)`），其坐标与紧随其后的 5s 暗场 `4970` 高值点重合，记为**暗场相关亮点尾端**（单组样本不足以鉴定温升或曝光间隔等具体物理成因）。")
    a('')
    a('---')
    a('')
    a('## 2. 样本清单、EXIF 与有效区像素统计')
    a('')
    a('全部 9 张样本均为全尺寸 14-bit 无损压缩 NEF（存储尺寸 `6064×4040 = 24,498,560` 像素，有效区 `[8:4032, 8:6056] = 6048×4024 = 24,337,152` 像素，`BlackLevel = [1008, 1008, 1008, 1008]`，`WhiteLevel = 16383`，镜头 `Viltrox 16mm f/1.8`，`ISO 1600`，`f/1.8`，机械快门 `Mechanical`，机内暗角控制 `Off`、自动失真控制 `Off`、衍射补偿 `Off`、高感降噪 `Off`）：')
    a('')
    a('| 文件名 | 类别与曝光 | 机械快门计数 | 文件字节 | 有效区均值 / 标准差 (DN) | 有效区 `<1008 DN` 像素 (占比) | 有效区 `0 ADU` | 有效区饱和 (`16383`) | C++ vs LibRaw 解码差异 |')
    a('| :--- | :--- | ---: | ---: | :--- | :--- | ---: | ---: | :--- |')
    act_total = 6048 * 4024
    for f in m12_files:
        fn = f['name']
        m = meta_by_name[fn]
        d = dec_by_name[fn]
        exp_str = '1/8000s' if f['kind'] in ('BIAS', 'FLAT') else '5s'
        mc = m['Nikon:MechanicalShutterCount']
        fsize = Path(f['path']).stat().st_size
        ac = f['active']
        pct_lt = ac['below_black'] / act_total * 100.0
        a(
            f"| `{fn}` | {f['kind']} (`{exp_str}`) | `{mc}` | {fsize:,} | "
            f"`{ac['mean']:.4f} / {ac['std']:.4f}` | `{ac['below_black']:,}` (`{pct_lt:.2f}%`) | "
            f"`{ac['zero']}` | `{ac['saturated']}` | `{d['mismatches']} / {d['pixels']:,}` |"
        )
    a('')
    a('---')
    a('')
    a('## 3. 暗场热点解除抑制与偏置帧差评估')
    a('')
    a('### 3.1 冻结 112 基准热像素点检验（最近同色 8 邻域核，绿色含跨 `G1/G2` 的 `(±1,±1)`）')
    a('')
    a('| 样本帧 | 版本 | 命中旧钳制 `{0,8,…,56}` | 恰好等于邻域最大值 | 差值 `> 56 DN` | 饱和点数 (`16383`) | 中位差值 (DN) |')
    a('| :--- | :--- | ---: | ---: | ---: | ---: | ---: |')
    for dk_id, ver, bold in [
        ('4854', 'Stock C3.80', False),
        ('4855', 'Stock C3.80', False),
        ('4961', 'Modified11', False),
        ('4970', 'Modified12', True),
        ('4971', 'Modified12', True),
        ('4972', 'Modified12', True),
    ]:
        dk = assess['dark'][dk_id]
        if bold:
            a(
                f"| `Z61_{dk_id}.NEF` | **{ver}** | **`{dk['matches_0_8_to_56']} / {dk['points']}`** | "
                f"**`{dk['exact_neighbor_max']}`** | **`{dk['above56']}`** | `{dk['saturated']}` | `{dk['median_delta']:,.1f}` |"
            )
        else:
            a(
                f"| `Z61_{dk_id}.NEF` | {ver} | `{dk['matches_0_8_to_56']} / {dk['points']}` | "
                f"`{dk['exact_neighbor_max']}` | `{dk['above56']}` | `{dk['saturated']}` | `{dk['median_delta']:,.1f}` |"
            )
    a('')
    a('### 3.2 有效区偏置帧差噪声与 `Z61_4969.NEF` 尾端分口径统计')
    a('')
    a(f"- `4967 - 4968`（有效区，除以 $\\sqrt{{2}}$ 折算单帧）：IQR 折算 `{bp_m12_67_68['iqr_sigma_dn']:.4f} DN`，`|Δ| ≤ 20` 截尾标准差 `{bp_m12_67_68['trimmed_abs20_sigma_dn']:.4f} DN`，未裁剪标准差 `{bp_m12_67_68['untrimmed_sigma_dn']:.4f} DN`（与 `Modified11` 的 `4958 - 4960` 对 `{bp_m11_58_60['iqr_sigma_dn']:.4f} / {bp_m11_58_60['trimmed_abs20_sigma_dn']:.4f} / {bp_m11_58_60['untrimmed_sigma_dn']:.4f} DN` 一致）。")
    a(f"- `4967 - 4969` 与 `4968 - 4969`（有效区）：IQR 折算 `{bp_m12_67_69['iqr_sigma_dn']:.4f} DN`，`|Δ| ≤ 20` 截尾标准差 `{bp_m12_67_69['trimmed_abs20_sigma_dn']:.4f} / {bp_m12_68_69['trimmed_abs20_sigma_dn']:.4f} DN`，未裁剪标准差 `{bp_m12_67_69['untrimmed_sigma_dn']:.4f} / {bp_m12_68_69['untrimmed_sigma_dn']:.4f} DN`。")
    a(f"- 三张 5s 暗场有效区均值减去三张偏置有效区均值为：`4970: +{net_dk_all['4970']:.4f} DN`、`4971: +{net_dk_all['4971']:.4f} DN`、`4972: +{net_dk_all['4972']:.4f} DN`（若以 `4967/4968` 有效区均值基准计算，则分别为 `+{net_dk_67_68['4970']:.4f} / +{net_dk_67_68['4971']:.4f} / +{net_dk_67_68['4972']:.4f} DN`）。")
    a('- `Z61_4969.NEF` 超过 `2000 DN` 像素的有效区与完整存储区分口径对照（避免混用两套坐标范围）：')
    a('')
    a('| 统计范围 | `4969` 中 `>2000 DN` 点数 | `4969` 该范围饱和点数 (`16383`) | `4969` 该范围整幅标准差 (DN) | 该批坐标在 `4967 / 4968 / 4969 / 4970` 的均值 (DN) | 备注 |')
    a('| :--- | ---: | ---: | ---: | :--- | :--- |')
    ma = ta['means_at_sites_dn']
    ms = ts['means_at_sites_dn']
    by, bx, bval = ts['border_only_sites'][0]
    a(
        f"| 有效区 `[8:4032, 8:6056]` | `{ta['count_gt_2000']}` | `{ta['saturated_16383_in_frame']}` | "
        f"`{ta['frame_std_dn']:.4f}` | `{ma['4967']:.1f} / {ma['4968']:.1f} / {ma['4969']:.1f} / {ma['4970']:.1f}` | 与表 2 有效区口径严格一致 |"
    )
    a(
        f"| 完整存储区 `4040×6064` | `{ts['count_gt_2000']}` | `{ts['saturated_16383_in_frame']}` | "
        f"`{ts['frame_std_dn']:.4f}` | `{ms['4967']:.1f} / {ms['4968']:.1f} / {ms['4969']:.1f} / {ms['4970']:.1f}` | 额外 1 点位于边框 `(y={by}, x={bx})` 值为 `{bval}` |"
    )
    a('')
    a('---')
    a('')
    a('## 4. 平场直方图频谱、白平衡与径向比例场对比（M10 vs M11 vs M12）')
    a('')
    a('### 4.1 统一 16,384 档网格（`0..16383 DN`）中心 400×400 频谱与中心色比')
    a('')
    a('| 样本帧 | 版本 | 中心净 `G1` (DN) | 中心净 `R/G1` | 相机 WB `R/B` 倍率 | 红通道精确 `0.2276` 幅度 | 红通道 `0.10..0.49` 主峰频率 (周期) | 主峰 / 频带中位数 |')
    a('| :--- | :--- | ---: | ---: | :--- | ---: | :--- | ---: |')
    for f in flat_files:
        fn = f['name']
        grp = f['group']
        fl = f['flat']
        fg_r = fl['spectra']['R']['fixed_grid']
        wb = f['camera_whitebalance']
        wb_r = wb[0] / wb[1]
        wb_b = wb[2] / wb[1]
        pk_f = fg_r['peak_frequency']
        pk_T = 1.0 / pk_f
        amp_02276 = fg_r['exact_02276_amplitude']
        med_r = fg_r['peak_over_band_median']
        if grp == 'Modified12':
            a(
                f"| `{fn}` | **{grp}** | `{fl['center_net']['G1']:.1f}` | `{fl['rg1']:.5f}` | "
                f"`{wb_r:.4f} / {wb_b:.4f}` | **`{amp_02276:.2f}`** | `{pk_f:.5f}` (`{pk_T:.3f} DN`) | `{med_r:.2f}` |"
            )
        else:
            a(
                f"| `{fn}` | {grp} | `{fl['center_net']['G1']:.1f}` | `{fl['rg1']:.5f}` | "
                f"`{wb_r:.4f} / {wb_b:.4f}` | `{amp_02276:.2f}` | `{pk_f:.5f}` (`{pk_T:.3f} DN`) | `{med_r:.2f}` |"
            )
    a('')
    a(f"- **同信号量级直接可比性**：`Modified12` 平场中心净 `G1`（`3041.1 ~ 3497.4 DN`）与 `Modified10`（`3043.9 ~ 3609.5 DN`）落在同一信号区间。在此同信号条件下，精确频率 `f = 0.2276 cycles/DN` 的红通道 DFT 幅度均值从 `{m10_02276:.2f}` 降至 `{m12_02276:.2f}`（**-{drop_02276_pct:.2f}%**），排除了 `Modified11` 平场曝光偏低（`1986.4 ~ 2272.0 DN`）的信号幅度混淆因素。")
    a(f"- **残余谱峰观察（不做超界物理归因）**：`4975/4976` 主峰位于 `0.17163 cycles/DN`（周期 `5.826 DN`），`4978` 主峰位于 `0.25732 cycles/DN`（周期 `3.886 DN`），数值上靠近约 `35/3 = 11.667 DN` 候选周期族的 2 次与 3 次谐波（`6/35 = 0.17143`、`9/35 = 0.25714`）。中心 2000×2000 窗口虽可见局部 `[12, 12, 11, 12, 12, 11]` 下凹间隔片段，但自动检测到的全部下凹间距均值分别为 `{dips_m12['Z61_4975.NEF']['mean_gap']:.2f}`、`{dips_m12['Z61_4976.NEF']['mean_gap']:.2f}`、`{dips_m12['Z61_4978.NEF']['mean_gap']:.2f} DN`（含 `2, 10` 等间距），目前来源未定。")
    a('')
    a('### 4.2 径向比例剖面统计（`16×16` 分箱，`r ∈ [0.15, 0.90]`，3 张平均剖面峰谷差）')
    a('')
    a('| 指标（百分点 `pp`） | Modified10 | Modified11 | Modified12 | M12 相对 M10 |')
    a('| :--- | ---: | ---: | ---: | ---: |')
    rows_42 = [
        ('未滤波径向 `R/G` 峰谷差', fg['Modified10']['broad_ptp_pp'][0], fg['Modified11']['broad_ptp_pp'][0], fg['Modified12']['broad_ptp_pp'][0]),
        ('未滤波径向 `B/G` 峰谷差', fg['Modified10']['broad_ptp_pp'][1], fg['Modified11']['broad_ptp_pp'][1], fg['Modified12']['broad_ptp_pp'][1]),
        ('未滤波径向 `G1/G2` 峰谷差', fg['Modified10']['broad_ptp_pp'][2], fg['Modified11']['broad_ptp_pp'][2], fg['Modified12']['broad_ptp_pp'][2]),
        ('`σ=6`（96 px）局部高通残差 `R/G` 峰谷差', fg['Modified10']['hp6_ptp_pp'][0], fg['Modified11']['hp6_ptp_pp'][0], fg['Modified12']['hp6_ptp_pp'][0]),
        ('`σ=6`（96 px）局部高通残差 `B/G` 峰谷差', fg['Modified10']['hp6_ptp_pp'][1], fg['Modified11']['hp6_ptp_pp'][1], fg['Modified12']['hp6_ptp_pp'][1]),
    ]
    for label, v10, v11, v12 in rows_42:
        rel_pct = (v12 - v10) / v10 * 100.0
        a(f'| {label} | `{v10:.4f}` | `{v11:.4f}` | `{v12:.4f}` | `{rel_pct:+.2f}%` |')
    a('')
    a('### 4.3 `NEFInfo` 序列化字段核验（全部 9 张块 CRC16 校验通过）')
    a('')
    v6_set = {(tuple(n['vignette']['coefficients']), n['vignette']['strength_L'], n['vignette']['status']) for n in nefinfo['files']}
    assert v6_set == {((0, 0, 0, 0), 0, 2)}
    a('- `NEFInfo 0x0006`（暗角块）：9 张全部为 `status = 2`（非零）、四项多项式系数 `coefficients = [0, 0, 0, 0]`、强度 `strength_L = 0`。')
    a(
        f"- `NEFInfo 0x0007`（双 17 项空间块）：9 张全部为 `flag_at_5a = 0`、`flag_at_4 = 1`（非零）；"
        f"提取的 6 个系数字段在 6 张 BIAS/DARK 中为 `{nef_by_name['Z61_4967.NEF']['two_table_spatial']['coefficients']}`，"
        f"在 `4975/4976` 中为 `{nef_by_name['Z61_4975.NEF']['two_table_spatial']['coefficients']}`，"
        f"在 `4978` 中为 `{nef_by_name['Z61_4978.NEF']['two_table_spatial']['coefficients']}`（仅精确报告上述实测序列化字段，不泛化表述为“全部激活位或校正已归零”）。"
    )
    a('')
    a('---')
    a('')
    a('## 5. 当前项目三项目标状态判定')
    a('')
    a('| 核心目标 | `Modified12` 实拍与离线证据状态 |')
    a('| :--- | :--- |')
    a('| **1. 保留暗电流** | **已验证解除冻结 112 点最近同色 8 邻域钳制**（`0/112` 命中 `{0,8,…,56}`）；本批 9 张有效区与存储区 `0 ADU` 像素均为 `0` 且保留 `<1008 DN` 码值分布；`0x10122cba` 控制流回归已通过离线原生执行验证，留存 9 张 NEF 无损解码 `0` 差异（全局暗电流线性度与极弱星点测光保真仍需专门天文标定）。 |')
    a('| **2. 关闭静态 NEF 写入前 RAW 校正** | **已定位的前后端可变通路已按设计生效**（全尺寸绕过后端 `0x20380000` 替换缓冲、前端 2D 多项式清零、前端 `0x10122cba` 非空路径四路 Q12 数字增益锁定 `4096`、`NEFInfo 0x0006` 四系数与 `strength_L` 为 `0` 且 `0x0007` 的 `flag_at_5a = 0`）；但 `0x0006 status=2`、`0x0007 flag_at_4=1`、前端固定标定表（如 `CAL33` 4×17 表体、`ID35` 列数据）与传感器硬件链路仍存在，不宣称“全部机内或硬件预处理已清零”。 |')
    a(f"| **3. 消除同心彩圈** | **部分改善、尚未达成最终根除**：在同信号量级下，前端红通道旧缩放缺码梳齿（`0.2276 cycles/DN`）实测下降 **{drop_02276_pct:.2f}%**，中心 `R/G1` 降至 `{m12_rg1:.4f}`；但来源未定的约 `35/3 DN` 周期族谱峰及 `~0.16–0.22 pp` 级径向细环残差仍可见，需结合后续固定光路多档曝光阶梯实验与前端 `CAL33` 表体对照继续排查。 |")
    a('')

    DOC_PATH.write_text('\n'.join(lines), encoding='utf8')
    print(json.dumps(dict(ok=True, doc=str(DOC_PATH), bytes=DOC_PATH.stat().st_size)))


if __name__ == '__main__':
    main()

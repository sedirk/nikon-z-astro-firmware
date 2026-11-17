"""Record sample-test results and freeze evidence; no next firmware changes."""
from pathlib import Path
import ast, datetime, hashlib, json
import numpy as np
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/modified6-real-2026-11-10'
def read(p):return json.loads(p.read_text(encoding='utf8'))
def write(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf8')
def rec(p):return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=file_sha(p))

def main():
    audit=read(OUT/'raw-audit.json');flat=read(OUT/'flats/result.json')
    dark=read(OUT/'dark-regression.json');dec=read(OUT/'independent-decode/result.json')
    fields=read(OUT/'correction-fields/result.json')
    assert all(r['ok'] for r in (audit,flat,dark,dec,fields))
    assert len(dec['files'])==6 and dec['total_pixels']==146991360 and all(r['mismatches']==0 for r in dec['files'])
    for row in audit['files']:
        assert file_sha(row['path'])==row['sha256']
        check=next(r for r in dec['files'] if r['name']==Path(row['path']).name)
        assert check['source_sha256']==row['sha256'] and check['pixels_sha256']==row['stored_pixels_sha256']
    assert sum(p['saturated'] for r in flat['files'] for p in r['phases'])==0
    for row in fields['files']:
        assert row['vignette']==dict(coefficients=[0]*4,strength_L=0,status=2)
        s=row['two_table_spatial'];assert s['flag_at_4']==1 and s['flag_at_5a']==0
        assert all(s['coefficients'][k]==0 for k in (1,2,4,5))
    centres=np.array(flat['centre_green_signals']);a=centres[:2].mean();b=centres[2:].mean()
    summary=dict(ok=True,scope='Only requested new sample tests; no further reverse engineering or firmware modification.',
        source_firmware_labels='User-provided directory labels; menu C3.80 is not an independent patch fingerprint.',
        geometry_fixed_confirmation=None,matched_exposure=True,all_three_correction_menus_off=True,
        valid_nef_files=6,independent_decoded_pixels=dec['total_pixels'],decode_mismatches=0,
        flat_metrics=flat['group_radial_metrics'],centre_green_A=float(a),centre_green_B=float(b),
        centre_green_change_percent=float(100*(b/a-1)),normalized_green_difference=flat['green_group_difference_percent'],
        dark_regression=dark,ring_removal_demonstrated=False,modified6_dark_test=None,
        conclusion='Broad ring structure remains. R/G excursion increases; B/G decreases. No overall ring-removal benefit in supplied flats. Modified4 local dark suppression regression passes; no modified6 dark frames.',
        original_nefs_unchanged=True,new_firmware=False,
        visual_review='Both figures inspected: persistent broad chromatic structures, matching radial shape with changed amplitudes, directional normalized brightness difference.')
    write(OUT/'assessment.json',summary)
    groups=flat['group_radial_metrics'];ra=groups[0]['metrics'];rb=groups[1]['metrics']
    table='\n'.join(f"| {k} | {ra[k]['peak_to_peak']:.3f} | {rb[k]['peak_to_peak']:.3f} | {100*(rb[k]['peak_to_peak']/ra[k]['peak_to_peak']-1):+.1f}% |" for k in ('R/G','B/G','G1/G2'))
    report=f'''# modified6 与新 modified4 实拍结果（2026-11-10）

**结论：这批照片没有显示 modified6 的整体消圈收益，宽环状颜色结构仍在。R/G 起伏增加，B/G 减小。modified4 新暗场保持既有局部抑制关闭效果；本次 modified6 没有暗场。**

按用户要求，本轮仅测试和反馈，不进行下一步逆向、补丁修改或固件生成。原始 NEF 未改动。版本身份依据用户提供的文件夹标签，不用 C3.80 菜单号单独确认补丁。

## 样本与保存完整性

| 组别 | 平场 | 5秒暗场 |
|---|---|---|
| 11.10_modified4 | 4910、4911 | 4913、4914 |
| 11.10_modified6 | 4917、4921 | 无 |

六张来自 Z6 8006677、唯卓仕16/1.8；ISO1600、f/1.8、机械快门、无损压缩。四张平场均1/8000秒；两张暗场5秒。两组暗角控制、自动失真控制、衍射补偿均记录Off；长曝与高ISO降噪均Off。RAW为6064×4040，有效区6048×4024，黑位1008、白位16383。

独立C++解码与LibRaw逐像素核对六张共 **146,991,360个码值，差异0**。modified6的两张NEF文件保存完整且可正常解码；这不是对其他拍摄模式的兼容性承诺。四张平场有效区均无饱和像素。

## 彩圈测量

延续之前方法：原始CFA、不去马赛克、不应用软件镜头校正；16×16浮点分箱、各相位64点均值，扣黑位1008；颜色比值按每张中央三分之一均值归一；几何中心，半径单位2012像素，统计0.15–0.90。指标是组平均径向曲线的峰谷差，单位百分点。主剖面不做平滑。

| 径向宽颜色起伏 | modified4 | modified6 | 相对变化 |
|---|---:|---:|---:|
{table}

R/G 的单帧范围为A组1.206–1.249、B组1.517–1.558；B/G为A组1.595–1.628、B组1.390–1.434。32/64像素分箱仍为R/G增加、B/G减小。主要峰谷位置及宽结构保持，不能将单通道下降概括成消圈成功。

![原始CFA颜色比例与径向曲线](../analysis/modified6-real-2026-11-10/ring-comparison.png)

扣黑位后的中央G均值 **{a:.2f}→{b:.2f} DN（{100*(b/a-1):+.2f}%）**；逐帧为2083.72、2305.18、3125.73、2890.53 DN。归一后G差异内圈5–95百分位跨度12.08个百分点，并呈方向梯度。曝光参数虽一致，实际信号及空间亮度分布仍有差异；本轮没有新增“布置/对焦完全不动”的确认。沿用屏幕光源的PWM/角度色偏条件，故这里报告样本变化，不给固件单独的消圈改善率，也不把亮度变化直接认作固件增益。

![归一亮度及差图](../analysis/modified6-real-2026-11-10/brightness-comparison.png)

该指标主要描述宽颜色结构，光源/镜头结构与细密量化环仍需区分；本批未形成细密硬编码环已消除的证据。

## 暗场结果

新modified4的4913、4914各有 **0/112** 命中冻结旧关系 `centre=max8+8*k, k=0..7`；各有111点超过同色邻域最大值56 DN以上，且比旧原版两张平均值高50 DN以上。原有暗场局部抑制关闭效果保持。

冻结112点中，原版两张均精确等于邻域最大值的子集实际为62点；新两张均0/62保持精确相等，其中61/62超过邻域最大值56 DN以上。新两张112点中分别82、80点已饱和，强信号数值不用于推断完整暗电流率或恢复百分比。

本次modified6仅两张平场，暗场效果记录为未复验，不把modified4结果移作modified6通过结论。

## 保存参数与记录

六张NEFInfo6的四系数及L均0，status=2；NEFInfo7 active=0、非常数项均0，已有中性参数保持。与之前菜单开启的status=1分开记录。这些字段不是新增前端control18的实机寄存器读回。

暗场脚本初次误将早期“31点”口径套到完整冻结112点集，触发断言后停止；按冻结清单明确的62点子集重新运行通过，未重新选点。失败脚本、stderr及重跑命令均保存。

命令、完整元数据、解码、数值和脚本快照位于 `analysis/modified6-real-2026-11-10/`；[结构化结论](../analysis/modified6-real-2026-11-10/assessment.json)。本轮到结果反馈结束，不提出新固件或开展后续修正。
'''
    reportpath=ROOT/'docs/MODIFIED6_REAL_NEF_2026-11-10.md'
    assert not reportpath.exists();reportpath.write_text(report,encoding='utf8')
    (OUT/'report.md').write_bytes(reportpath.read_bytes())
    snapshots=OUT/'script-snapshots';snapshots.mkdir(exist_ok=False)
    for name in ('test_modified6_samples.py','analyze_modified6_flats.py','plot_modified6_results.py','finish_modified6_results.py',
                 'audit_nef.py','analyze_modified1_flats.py','analyze_modified2_flats.py','analyze_modified1_nef.py',
                 'inventory_nas_nef.py','verify_modified1_decode.py','extract_flat_correction_fields.py','bridge_real_nef_contract.py','record_research_command.py'):
        source=ROOT/'tools/fw'/name;ast.parse(source.read_text(encoding='utf8'));(snapshots/name).write_bytes(source.read_bytes())
    preserved={
        'firmware/original/Z_6_0380.bin':'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
        'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
        'outputs/Z6-C380-cal33-control18-reviewed-2026-11-10/01_TEST_MODIFIED6/EG162080.BIN':'5c1cdfcd11ccfef301317118c43954bf6b55a50e6574ea66ba941e2f9a716003'}
    for path,digest in preserved.items():assert file_sha(ROOT/path)==digest,path
    write(OUT/'verification.json',dict(ok=True,unchanged_samples={r['path']:r['sha256'] for r in audit['files']},
        preserved_firmware=preserved,independent_decoded_pixels=dec['total_pixels'],mismatches=0,
        figures_visually_reviewed=True,new_firmware=False,git_commit=False,report=rec(reportpath)))
    print(json.dumps(dict(ok=True,report=str(reportpath),centre_green_change=summary['centre_green_change_percent'],no_next_firmware_work=True)))

if __name__=='__main__':main()

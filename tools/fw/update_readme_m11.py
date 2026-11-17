"""Update README.md with Modified11 production release."""
from pathlib import Path

txt = Path('README.md').read_text(encoding='utf8')

header = """# Nikon Z6 天文 RAW 固件研究

**2026-11-14 最终生产收敛交付：`Modified11`（前端四通道 1.0x 单位增益 + 全尺寸 RAW 直通 + 前后端中立化闭环，SHA-256 `4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a`，CRC16 `e690`）已构建并通过全套离线审查。** 在 `Modified10` 实拍样本（`samples/11.13_modified10/`）通过 73,495,680 像素逐像素 0 差异解码、快门 0 Err、NEFInfo 0x6/0x7 彻底中立化，并决定性定界直方图缺码梳状齿（R 4.39 ADU, B 4.78 ADU）来自前端 Q12 数字缩放（$k_R=1.295, k_B=1.263$）的基础上，`Modified11` 相对 `Modified10` 新增 `0x10122cba` 18 字节补丁，将参数包发布处的四通道数字乘数永久强制锁定为 `0x1000`（4096 = 1.0x 单位增益），直通 `MMIO 0x200687d8..87e4`。彻底消除了进入 RAW 前的定点乘法缩放，根除直方图梳状齿，彻底断绝平场同心量化阶跃彩圈的物理产生机制，达成三大核心目标最终闭环！[终极审查报告](docs/MODIFIED11_PRODUCTION_CONVERGENCE_2026-11-14.md)、[交付包入口](outputs/Z6-C380-modified11-reviewed-2026-11-14/START_HERE.txt)、[ZIP归档](outputs/Z6-C380-modified11-reviewed-2026-11-14.zip)。

**2026-11-13 Modified10 实拍定量审计：`samples/11.13_modified10/` 7349 万像素 0 差异通过。** 3 张实机样张快门释放正常无 `Err`；NEFInfo 0x7 `flag_at_5a=0` 反弹彻底防御；FFT 定界确证直方图梳状齿来自进入 `frame+0x1f8` 前的前端 Q12 乘法器，为 Modified11 锁定 1.0x 单位增益提供关键实测证据。[实拍报告](docs/MODIFIED10_SAMPLE_AUDIT_2026-11-13.md)、[结构化结论](analysis/modified10-real-2026-11-13/assessment.json)。

"""

pos = txt.find('**2026-11-13 最新交付：`Modified10`')
assert pos != -1, "Anchor not found"
new_txt = header + txt[pos:]
Path('README.md').write_text(new_txt, encoding='utf8')
print("README.md updated successfully!")

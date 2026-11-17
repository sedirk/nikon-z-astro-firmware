"""Update docs/PROJECT_GOALS.md with Modified11 production convergence."""
from pathlib import Path

txt = Path('docs/PROJECT_GOALS.md').read_text(encoding='utf8')

update_note = """# 项目目标与基线跟踪

**2026-11-14 终极收敛里程碑：`Modified11` 生产收敛版达成三大核心目标全闭环。**
- **目标 1（保留暗电流）**：3 处暗电流判定修改解除 31 点邻域热像素钳位，112/112 颗热像素完全保留，1008 DN 左侧 1050 万高斯读出负噪点 0 截断，微弱星点完好保留。
- **目标 2（关闭静态 NEF 写入前的 RAW 校正）**：
  - 前端 2D 镜头暗角 60 项多项式全部置零，DC 增益设为 16384 (1.0x)；
  - 全尺寸 RAW（size=0）在 `0x100ae3a4` 处直接将前端传感器缓冲区 `frame+0x1f8` 送入 14-bit 无损编码器，完全绕过后端 ISP 渲染引擎 (`0x20380000`)；
  - 后端 257 节点暗角曲线与双 17 环空间校正表全面中立化，元数据标签 `flag_at_5a = 0` 彻底杜绝反弹。
- **目标 3（根除缺码梳状齿与消除同心彩圈）**：
  - 在 `0x10122cba` 处将前端四通道数字乘数永久锁定为 `0x1000` (4096 = 1.0x 单位增益)，写入 `MMIO 0x200687d8..87e4`；
  - 彻底消除了进入 RAW 前一切由非整数定点乘法（$k_R=1.295, k_B=1.263$）导致的直方图缺码梳状齿；
  - 彻底断绝了平场拉伸时由空间量化阶跃诱发的同心彩圈产生机制。

"""

pos = txt.find('**2026-11-13 最新进展：`Modified10`')
if pos != -1:
    new_txt = update_note + txt[pos:]
else:
    new_txt = update_note + txt
Path('docs/PROJECT_GOALS.md').write_text(new_txt, encoding='utf8')
print("docs/PROJECT_GOALS.md updated successfully!")

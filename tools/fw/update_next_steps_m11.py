"""Update docs/NEXT_STEPS.md with Modified11 camera shoot protocol."""
from pathlib import Path

txt = Path('docs/NEXT_STEPS.md').read_text(encoding='utf8')

next_steps_top = """# 下一步研究计划

**2026-11-14 当前执行顺序：`Modified11` 生产收敛版实机刷入与全要素实拍验收**

1. **刷前准备与刷机操作**：
   - 固件位置：[outputs/Z6-C380-modified11-reviewed-2026-11-14/01_TEST_MODIFIED11/EG162080.BIN](../outputs/Z6-C380-modified11-reviewed-2026-11-14/01_TEST_MODIFIED11/EG162080.BIN)
   - SHA-256: `4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a`，CRC16: `e690`
   - 将 `01_TEST_MODIFIED11/EG162080.BIN` 复制到格式化后的存储卡根目录；
   - 插入相机开机，按【回放键 ▶】等待 3~5 秒后再进【设置菜单 -> 固件版本 -> 更新】，100% 避免 `0x0d02` 忙碌跳过；
   - 更新完成后关机拔电池 5 秒。
2. **标准 9 张全要素实拍验收矩阵**：
   - **暗场（DARK）3 张**：5s ISO 1600，镜头盖盖紧，核验 112 颗热像素完全保留（目标 112/112 释放）；
   - **偏置场（BIAS）3 张**：1/8000s ISO 1600，核验 1008 DN 黑电平左侧高斯读出噪声无零点截断；
   - **平场（FLAT）3 张**：均匀柔光屏平场，核验：
     - 中心 400×400 ADU 直方图 FFT：梳状齿峰值（R 4.39 ADU, B 4.78 ADU）彻底消失（SNR < 2.0）；
     - 径向细同心环：由量化阶跃诱发的同心彩圈彻底消除！
3. **无损随时回退预案**：
   - 软件包内已提供：
     - `02_BACK_TO_MODIFIED10/EG162080.BIN`
     - `03_BACK_TO_MODIFIED9/EG162080.BIN`
     - `04_DARK_ONLY_MODIFIED1/EG162080.BIN`
     - `05_STOCK_C380/EG162080.BIN`
   - 任意时刻均可通过卡刷一键原样回退，绝无单向锁死风险。

"""

pos = txt.find('**2026-11-13 当前执行顺序：`Modified10`')
if pos != -1:
    new_txt = next_steps_top + txt[pos:]
else:
    new_txt = next_steps_top + txt
Path('docs/NEXT_STEPS.md').write_text(new_txt, encoding='utf8')
print("docs/NEXT_STEPS.md updated successfully!")

# Nikon Z6 C3.80 文档索引 (Documentation Index)

> 🌐 **语言 / Language**: **简体中文** | **[English](README_EN.md)** · 🏠 [返回项目主页](../README.md)

本项目文档分为 **核心技术专题**、**测试与证据固化**、**固件下载与构建说明** 以及 **历史版本演进记录** 四大部分。

---

## 1. 核心技术专题 (Core Architecture)

| 专题文档 | 主要内容 | 覆盖功能 |
| :--- | :--- | :--- |
| **[01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md](01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md)** | 前端 ISP 空间校正绕过与同心彩圈消除机制 | 14 处 RAW 与硬件位打包钩子，4 通道 Q12 增益固定 4096 单位增益，消除 FFT 0.228 cyc/DN 周期性梳齿 |
| **[02_STAR_EATER_AND_DARK_CURRENT.md](02_STAR_EATER_AND_DARK_CURRENT.md)** | 空间滤波旁路与暗电流完全保留 | 旁路 `0x100C2654/7C/90` 3 处邻域热点过滤，无损压缩与未压缩下均完整保留原始热像素与极弱星点光子 |
| **[03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md](03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md)** | 色空间菜单接管与 sRGB 有效色空间锁定 | 使用真彩色空间属性 `PID 0x0526` 作为 UI 开关载体，锁定 `PID 0x130A = 0 (sRGB)`，保持标准命名与原生自动 ISO |
| **[04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md](04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md)** | M 档 600 秒长曝光与曝光后纯等待间隔定时器 | M 档扩充 60"~600" 慢门档位，重构间隔拍摄完成回调，动态预测结束时刻 |

---

## 2. 证据与验证 (Evidence & Catalog)

- **[MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md)**：`Modified23` 未压缩直通 RAW 硬件位打包修复（`0x100A34D0 -> 0x1002DB5C`）、437 组 Unicorn 分类矩阵与真机 `5s` / `60s` 9 张 NEF 逐像素闭环验证报告（附固化证据 **[evidence/m23_audit_metrics.json](evidence/m23_audit_metrics.json)**、**[evidence/probe_modified23_native_result.json](evidence/probe_modified23_native_result.json)** 与 **[evidence/modified23_updater_audit.json](evidence/modified23_updater_audit.json)**）。
- **[MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md](MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md)**：首版公开基线真机 18 张平场/暗场/偏置 NEF 逐像素审计报告（附固化证据 **[evidence/m22_audit_metrics.json](evidence/m22_audit_metrics.json)** 与 **[evidence/baseline112.json](evidence/baseline112.json)**）。
- **[images/modified22_real_camera_verification.png](images/modified22_real_camera_verification.png)**：真实相机实拍（`Astro RAW` vs `Standard`）平场直方图与傅里叶梳状纹抑制对比图。
- **[SAMPLE_EVIDENCE_CATALOG.json](SAMPLE_EVIDENCE_CATALOG.json)**：全量 130 个实机样本文件的元数据、SHA-256 与频谱测量指标。

---

## 3. 固件下载与构建 (Release Package & Build Guide)

- **直接下载刷机包**：前往 **[GitHub Releases (`v3.80-modified23`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified23)** 下载打包好的 [`Nikon-Z6-C380-Modified23-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified23/Nikon-Z6-C380-Modified23-Astro-Firmware.zip)（内含 `01_MODIFIED23/EG162080.BIN`、`02_STOCK_C380_ROLLBACK/EG162080.BIN` 及离线校验脚本 `verify.py`）。
- **[TOOLS.md](TOOLS.md)**：项目分析工具、环境依赖及可复现构建说明（运行 `python tools/build_modified23.py --stock <Z_6_0380.bin> --zip` 即可在本地复现正式发布包）。

---

## 4. 版本更新日志与后续路线图 (Changelog & Roadmap)

- **[CHANGELOG.md](CHANGELOG.md)**：**正式发布更新日志与历次原型迭代记录**（汇总 `v3.80-modified23`、`v3.80-modified22` 及早期实验阶段演进）。
- **[NEXT_STEPS.md](NEXT_STEPS.md)**：**优先待解决路线图**与专题攻关记录：
  1. **P1 — 长曝未压缩直通 RAW 问题（已于 `Modified23` 真机实拍闭环发布）**（详见 [MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md)）；
  2. **P2 — 夜视红光模式（待攻关）**（为初代 Z6 增加保护暗适应且不污染实拍数据的机内红光夜视显示开关）；
  3. **P3 — 对焦位置待机记忆（待攻关）**（解决唯卓仕 AF 16mm F1.8 Z 等线控镜头待机休眠唤醒后复位至假无限远丢焦问题，前序排查复盘见 [STANDBY_FOCUS_LOSS_INVESTIGATION.md](STANDBY_FOCUS_LOSS_INVESTIGATION.md)）。
- **[PROJECT_GOALS.md](PROJECT_GOALS.md)** 与 **[SOURCES.md](SOURCES.md)**：项目总体工程目标、验收准则与外部研究文献索引。
- 早期原型阶段的专题备忘与离线审查档案保留在本目录下的 `MODIFIED*.md` 与 `RAW_*.md` 文件中。

> [!NOTE]
> 历史研究档案中提及的 `outputs/`、`analysis/`、`references/` 及 `work/` 目录属于机台实验归档产物，已由 `.gitignore` 排除，不包含在公开 Git 仓库中。最终用户请统一从 GitHub Releases 下载或使用 `tools/build_modified23.py` 构建生产固件。

# Nikon Z6 C3.80 文档索引 (Documentation Index)

> 🌐 **语言 / Language**: **简体中文** | **[English](README_EN.md)** · 🏠 [返回项目主页](../README.md)

本项目文档分为 **核心技术专题**、**测试与证据固化**、**固件下载与构建说明** 以及 **历史版本演进记录** 四大部分。

---

## 1. 核心技术专题 (Core Architecture)

| 专题文档 | 主要内容 | 覆盖功能 |
| :--- | :--- | :--- |
| **[01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md](01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md)** | 前端 ISP 空间校正绕过与同心彩圈消除机制 | 旁路 13 处 RAW 算子，4 通道 Q12 增益固定 4096 单位增益，消除 FFT 0.228 cyc/DN 周期性梳齿 |
| **[02_STAR_EATER_AND_DARK_CURRENT.md](02_STAR_EATER_AND_DARK_CURRENT.md)** | 空间滤波旁路与暗电流完全保留 | 旁路 `0x100C2654/7C/90` 3 处邻域热点过滤，保留原始热像素与深空极弱星点光子 |
| **[03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md](03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md)** | 色空间菜单接管与 sRGB 有效色空间锁定 | 使用真彩色空间属性 `PID 0x0526` 作为 UI 开关载体，锁定 `PID 0x130A = 0 (sRGB)`，彻底解决色彩与自动 ISO 冲突 |
| **[04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md](04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md)** | M 档 600 秒长曝光与曝光后纯等待间隔定时器 | M 档扩充 60"~600" 慢门档位，重构间隔拍摄完成回调，动态预测结束时刻 |

---

## 2. 证据与验证 (Evidence & Catalog)

- **[MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md](MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md)**：`Modified22` 真机 18 张 NEF 独立像素级审计与未压缩暗场布局分析。
- **[evidence/m22_audit_metrics.json](evidence/m22_audit_metrics.json)** 与 **[evidence/baseline112.json](evidence/baseline112.json)**：M22 量化核验数据与冻结的 112 个原生热像素基准坐标。
- **[images/modified22_real_camera_verification.png](images/modified22_real_camera_verification.png)**：M22 实机实拍（Astro RAW vs 原厂标准）平场傅里叶谱、暗场邻域热像素及偏置读噪对比图。
- **[SAMPLE_EVIDENCE_CATALOG.json](SAMPLE_EVIDENCE_CATALOG.json)**：全量 121 个实机样本文件的元数据与校验哈希。

---

## 3. 固件下载与构建 (Release Package & Build Guide)

- **直接下载刷机包**：前往 **[GitHub Releases (`v3.80-modified22`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified22)** 下载打包好的 [`Nikon-Z6-C380-Modified22-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified22/Nikon-Z6-C380-Modified22-Astro-Firmware.zip)（内含 `01_MODIFIED22/EG162080.BIN`、`02_STOCK_C380_ROLLBACK/EG162080.BIN` 及离线校验脚本 `verify.py`）。
- **[TOOLS.md](TOOLS.md)**：项目分析工具、环境依赖及可复现构建说明（运行 `python tools/build_modified22.py --stock <Z_6_0380.bin> --zip` 可在本地复现逐字节一致的刷机包）。
---

## 4. 历史版本演进记录 (Historical Archive)

从 `Modified1` 至 `Modified21` 的中间技术备忘与离线审查报告保存在本目录下的 `MODIFIED*.md` 文件中。

> [!NOTE]
> 历史研究记录中提及的 `outputs/`、`analysis/` 及本地绝对路径属于机台实验过程中的归档目录，已被 `.gitignore` 排除，不包含在公开 Git 仓库中。最终用户请统一使用 `tools/build_modified22.py` 构建生产固件。

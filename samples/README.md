# 样片存放与测试规范 (Sample Guidelines & Evidence Status)

> 🌐 **语言 / Language**: **[简体中文主页](../README.md)** | **[English README](../README_EN.md)**

## 简体中文

本项目图像管线的所有公开发布功能均基于真实相机实拍 NEF 样片（涵盖平场、偏置场、5 秒无损压缩与未压缩暗场，以及 M 档 60 秒扩展慢门未压缩暗场序列）完成逐像素闭环验收；机内显示后端功能同步附有原生指令仿真、QEMU 帧缓冲像素对比与真机上机核验记录。

- **样片规范**：按测试批次分子目录存放：`bias/`（偏置）、`dark/`（暗场）、`flat/`（平场）、`light/`（亮场）。拍摄时严格记录机身固件版本、ISO、曝光时间、快门模式、RAW 压缩/位深与菜单开关状态，严禁修改原始 NEF 字节。
- **证据归档与公开分发说明**：为控制 Git 仓库体积（避免数 GB 二进制膨胀），原始高分辨率 `.NEF` 文件由实验机台本地归档保存，未纳入公开 Git 跟踪集。全量 **130 张**实拍样片的 SHA-256 哈希、EXIF/MakerNote 元数据、全幅 `packed-14` 解码核验与频谱/读噪测量指标均已冻结于 [docs/SAMPLE_EVIDENCE_CATALOG.json](../docs/SAMPLE_EVIDENCE_CATALOG.json) 与 [docs/evidence/](../docs/evidence/)（详见 [无损/未压缩全模式验证报告](../docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md) 与 [平场/偏置频谱审计报告](../docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md)）。

---

## English

Every image-pipeline feature shipped in this firmware is validated pixel-by-pixel against real-camera NEF captures (spanning matched flat and bias frames, 5-second lossless compressed and uncompressed darks, and 60-second M-mode extended-shutter uncompressed dark sequences), complemented by native Unicorn, QEMU framebuffer, and physical-camera verification for display-backend features.

- **Capture Organization**: Local capture batches are organized by session into `bias/`, `dark/`, `flat/`, and `light/`, recording exact firmware build, ISO, shutter speed, shutter mode, RAW compression/bit depth, and menu toggle state without modifying raw NEF bytes.
- **Public Repository Boundary**: To prevent multi-gigabyte binary bloat in Git history, raw high-resolution `.NEF` files are archived offline on the lab workstation and excluded from public Git tracking. Complete SHA-256 digests, EXIF/MakerNote tags, full-frame `packed-14` parity checks, and spectral/noise metrics for all **130** real-camera NEF frames are pinned in [docs/SAMPLE_EVIDENCE_CATALOG.json](../docs/SAMPLE_EVIDENCE_CATALOG.json) and [docs/evidence/](../docs/evidence/) (see the [Uncompressed & Lossless Full-Mode Verification Report](../docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md) and [Flat/Bias Spectral Audit Report](../docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md)).

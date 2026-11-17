# 样片存放与测试规范 (Sample Guidelines & Evidence Status)

> 🌐 **语言 / Language**: **[简体中文主页](../README.md)** | **[English README](../README_EN.md)**

## 简体中文

本项目历次固件迭代均基于真实相机实拍样本（包括 M9、M12、M13 以及最终收敛版 `Modified22` 的 18 张全套平场/暗场/偏置帧）完成闭环验证。

- **样片规范**：按测试轮次或日期分子目录存放：`bias/`（偏置）、`dark/`（暗场）、`flat/`（平场）、`light/`（亮场）。拍摄时需严格记录机身固件版本、ISO、曝光时间、快门模式与菜单开关状态，且严禁修改原始 NEF 字节。
- **证据归档与公开分发说明**：为控制 Git 仓库体积（避免数十 GB 二进制膨胀），原始高分辨率 NEF 文件由实验机台本地归档保存，未纳入公开 Git 跟踪集。全量 121 张实拍样片的 SHA-256 哈希、EXIF/MakerNote 元数据与频谱/读噪测量指标均已冻结于 [docs/SAMPLE_EVIDENCE_CATALOG.json](../docs/SAMPLE_EVIDENCE_CATALOG.json) 与 [docs/evidence/](../docs/evidence/)（详见 [中文审计报告](../docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md)）。

---

## English

Every firmware iteration in this project (including M9, M12, M13, and the 18 matched flat/dark/bias frames of the final **`Modified22`** build) has been validated end-to-end against real-camera NEF captures.

- **Capture Organization**: Local capture batches are organized by test session into `bias/`, `dark/`, `flat/`, and `light/`, recording exact firmware build, ISO, shutter speed, shutter mode, and menu toggle state without modifying raw NEF bytes.
- **Public Repository Boundary**: To prevent multi-gigabyte binary bloat in Git history, raw high-resolution `.NEF` files are archived offline on the lab workstation and excluded from public Git tracking. Complete SHA-256 digests, EXIF/MakerNote tags, and pixel/spectral metrics for all 121 real-camera NEF frames are pinned in [docs/SAMPLE_EVIDENCE_CATALOG.json](../docs/SAMPLE_EVIDENCE_CATALOG.json) and [docs/evidence/](../docs/evidence/) (see the [English Audit Report](../docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17_EN.md)).

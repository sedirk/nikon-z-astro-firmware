# 样片存放与测试规范 (Sample Guidelines & Evidence Status)

本项目历次固件迭代均基于真实相机实拍样本（包括 M9、M12、M13 以及最终候选 M22 的 18 张全套平场/暗场/偏置帧）完成闭环验证。

- **样片规范**：按测试轮次或日期分子目录存放：`bias/`（偏置）、`dark/`（暗场）、`flat/`（平场）、`light/`（亮场）。拍摄时需严格记录机身固件版本、ISO、曝光时间、快门模式与菜单开关状态，且严禁修改原始 NEF 原始字节。
- **证据归档与公开分发说明**：为控制 Git 仓库体积（避免数十 GB 二进制膨胀），原始高分辨率 NEF 文件由实验机台本地归档保存，未纳入公开 Git 跟踪集。全量样片哈希、元数据与测量指标请参考 [docs/SAMPLE_EVIDENCE_CATALOG.json](../docs/SAMPLE_EVIDENCE_CATALOG.json) 与 [docs/evidence/](../docs/evidence/)。

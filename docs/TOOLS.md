# 工具与构建说明 (Tools & Build Guide)

> 🌐 **语言 / Language**: **简体中文** | **[English](TOOLS_EN.md)** · 🏠 [返回项目主页](../README.md)

本仓库的核心固件构建、容器解包与仓库卫生校验工具均基于 **Python 3.10+ 标准库**编写，在项目根目录下即可直接运行，不连接相机、不直接刷写硬件，亦不在 Git 源码库中捆绑原厂二进制或第三方预计算密钥表。

> [!TIP]
> 如无需本地编译，可直接前往 **[GitHub Releases (`v3.80-modified22`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified22)** 下载已打包好的 [`Nikon-Z6-C380-Modified22-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified22/Nikon-Z6-C380-Modified22-Astro-Firmware.zip)，解压后运行包内的 `python verify.py` 即可离线完成完整性核验。

---

## 1. 生产固件可复现构建与完整性校验（面向所有用户）

将合法取得的尼康官方 Z6 C3.80 固件文件 `Z_6_0380.bin`（SHA-256: `ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54`）传入独立构建器，即可复现与 GitHub Release 完全一致的固件目录及确定性 `.zip` 归档：

```powershell
# 标准构建并打包确定性 .zip（仅需 Python 3.10+ 标准库）
python tools/build_modified22.py --stock path\to\Z_6_0380.bin --output-dir outputs\Nikon-Z6-C380-Modified22-Astro-Firmware --zip

# 对已生成或从 Release 解压的固件包执行独立只读校验（尺寸、SHA-256、CRC-16/XMODEM、PID 0x0526 / 0x130A 机器码不变量）
python tools/build_modified22.py --verify outputs\Nikon-Z6-C380-Modified22-Astro-Firmware
```

若本地已安装反汇编校验依赖（`pip install capstone`），还可附加 `--rebuild-from-source` 参数，从 `tools/fw/` 下的 Thumb 汇编发射器现场重编译全部补丁指令并与冻结的 [`patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json`](../patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json) 逐字节比对：

```powershell
python tools/build_modified22.py --stock path\to\Z_6_0380.bin --rebuild-from-source --force
```

---

## 2. 核心公共模块说明

| 脚本路径 | 依赖要求 | 功能说明 |
| :--- | :--- | :--- |
| [`tools/build_modified22.py`](../tools/build_modified22.py) | Python 3.10+ 标准库（`--rebuild-from-source` 可选 `capstone`） | 解包官方 `Z_6_0380.bin`、核验 ROM 属性表槽位、注入 104 处补丁跨度、重算 CRC-16/XMODEM、执行反向回退字节恒等证明，并原子化生成 `01_MODIFIED22/EG162080.BIN` 与 `02_STOCK_C380_ROLLBACK/EG162080.BIN` |
| [`tools/fw/z6_c380_container.py`](../tools/fw/z6_c380_container.py) | Python 3.10+ 标准库 | 基于 [`tools/fw/z6_c380_zero_samples.json`](../tools/fw/z6_c380_zero_samples.json) 中的结构性零填充偏移图（生成树差分恢复算法），在运行期从用户提供的 `Z_6_0380.bin` 动态恢复三张 256 字节 XOR 掩码表（列、行、块）并解出主模块 `eg1620_038000.bi` |
| [`tools/verify_repo_hygiene.py`](../tools/verify_repo_hygiene.py) | Python 3.10+ 标准库 + `git` | 公开仓库自动化门禁：检查 `.gitignore` 跟踪合规性、禁止目录/扩展名、单文件体积上限、隐私路径脱敏、UTF-8/JSON 完整性、Markdown 相对链接可达性、LaTeX 转义规范及（可选 `--check-history`）Git 历史对象纯洁性 |
| [`tools/analyze_z6.py`](../tools/analyze_z6.py) | Python 3.10+ 标准库 | 静态解析官方 `Z_6_0380.bin`，基于 `z6_c380_container.py` 解出 `firmware/decoded/` 模块并生成本地静态分析摘要 |
| [`tools/evidence/build_sample_catalog.py`](../tools/evidence/build_sample_catalog.py) | `numpy`, `rawpy` | 在本地具备 `samples/` 原始 NEF 归档的实验环境中重新生成 [`docs/SAMPLE_EVIDENCE_CATALOG.json`](../docs/SAMPLE_EVIDENCE_CATALOG.json) |
| [`tools/evidence/build_m22_audit_metrics.py`](../tools/evidence/build_m22_audit_metrics.py) | `numpy`, `rawpy` | 在本地具备 `samples/` 原始 NEF 归档的实验环境中重新计算 [`docs/evidence/m22_audit_metrics.json`](../docs/evidence/m22_audit_metrics.json) 平场频谱与暗场/偏置指标 |

仓库卫生自检命令：

```powershell
python tools/verify_repo_hygiene.py
```

---

## 3. 历史研究阶段脚本说明（仅作演进备忘）

`tools/` 与 `tools/fw/` 下保留了 `Modified1` ~ `Modified21` 逆向探索阶段的辅助探测、QEMU/Unicorn 离线回放与早期归档脚本（如 `tools/archive_sources.py`、`tools/archive_research_update.py`、`tools/build_evidence.py`、`tools/verify_project.py`、`tools/organize_files.ps1` 等）。

> [!NOTE]
> 这些早期研究脚本中引用的 `outputs/`、`analysis/`、`references/`、`manifests/` 与 `work/` 目录属于实验机台本地工作缓存与外部文献快照目录，已在 [`.gitignore`](../.gitignore) 与 [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) 中排除，不随公开仓库分发；日常固件构建与核验无需运行这些历史归档脚本。

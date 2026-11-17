"""Assess offline preflash reviews, package Modified10 kit, and generate review report."""
from pathlib import Path
import argparse, datetime, json, shutil
from verify_modified10_kit import DIGESTS, PATHS, need, sha, check_kit

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / "analysis/modified10-preflash-2026-11-13"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf8"))


def record_file(path: Path, base: Path = ROOT) -> dict:
    return dict(path=path.relative_to(base).as_posix(), bytes=path.stat().st_size, sha256=sha(path.read_bytes()))


def assess() -> dict:
    lab = read_json(ROUND / "lab-build/manifest.json")
    native = read_json(ROUND / "native-unicorn-final/result.json")
    audit = read_json(ROUND / "independent-byte-review-v2/result.json")
    updater = read_json(ROUND / "native-updater/result.json")
    q_m9 = read_json(ROUND / "qemu-modified9/result.json")
    q_m10 = read_json(ROUND / "qemu-modified10/result.json")

    need(all(x["ok"] for x in (lab, native, audit, updater, q_m9, q_m10)), "One or more offline review stages failed")
    need(
        lab["sha256"] == native["candidate_sha256"] == audit["sha256"] == q_m10["firmware_sha256"] == DIGESTS["modified10"],
        "Modified10 SHA-256 mismatch across review stages",
    )
    need(native["frontend_and_abi"]["builder_cases"] == 120, "Frontend builder cases")
    need(native["frontend_and_abi"]["abi_cases"] == 64 and native["frontend_and_abi"]["error_cases"] == 8, "ABI/error cases")
    need(
        native["release_contract"]["descriptor_encoder_cases"] == 68 and native["release_contract"]["guard_cases"] == 240,
        "Release contract cases",
    )
    need(native["spatial_and_backend_chains"]["chain_executions"] == 64, "Spatial/backend chain cases")
    need(native["spatial_and_backend_chains"]["m10_active_tag7_count"] == 0, "NEFInfo 0x0007 active not cleared")
    need(audit["protected_regions_verified"] == 13 and audit["changed_total_bytes_vs_modified9"] == 14, "Byte audit")
    need(len(updater["file_checks"]) == 11 and len(updater["scheduler"]) == 5 and not updater["physical_flash"], "Updater")
    need(q_m9["model_sources"] == q_m10["model_sources"], "QEMU model source drift")
    need(q_m9["controller_sources"] == q_m10["controller_sources"], "QEMU controller source drift")

    evidence_files = [
        ROUND / "lab-build/manifest.json",
        ROUND / "native-unicorn-final/result.json",
        ROUND / "independent-byte-review-v2/result.json",
        ROUND / "native-updater/result.json",
        ROUND / "qemu-modified9/result.json",
        ROUND / "qemu-modified10/result.json",
    ]
    return dict(
        ok=True,
        verdict="OFFLINE_REVIEW_PASSED_FOR_CONTROLLED_CAMERA_TEST",
        generated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        candidate="modified10",
        candidate_sha256=DIGESTS["modified10"],
        parent_modified9_sha256=DIGESTS["modified9"],
        stock_sha256=DIGESTS["stock"],
        crc16=lab["crc16"],
        changed_bytes_vs_stock=95,
        changed_code_bytes_vs_modified9=12,
        changed_total_bytes_vs_modified9=14,
        unicorn_total_executions=564,
        unicorn_breakdown=dict(
            frontend_builder=120,
            abi_nzcv=64,
            error_propagation=8,
            release_contract=68,
            guard_predicates=240,
            spatial_backend_chains=64,
        ),
        protected_regions_verified=13,
        updater_file_checks=11,
        flash_scheduler_cases=5,
        qemu_runs=[
            dict(variant="modified9", live_code=q_m9["live_code_checks"], events=len(q_m9["events"])),
            dict(variant="modified10", live_code=q_m10["live_code_checks"], events=len(q_m10["events"])),
        ],
        visual_review="Both qemu-modified9/after.png and qemu-modified10/after.png inspected: identical camera shooting UI and synthetic color bars, zero guest error.",
        limitations=[
            "Physical camera ring/comb elimination on real sensor flats is NOT claimed prior to shooting real Modified10 NEFs.",
            "Full-size RAW (size=0) routes front-end buffer frame+0x1f8 directly to lossless NEF encoder 0x100af648; medium/small RAW (size=1/2) continues through backend replacement resize.",
            "Front-end CAL33 (op 07, 0x20068f00..8fc8) and ID35 (0x2006103c=1) remain at factory configuration for shutter safety and single-stage attribution.",
        ],
        physical_modified10_test=False,
        ring_removal_verified=False,
        evidence=[record_file(p) for p in evidence_files],
    )


def build_kit(kit_dir: Path, doc_path: Path, assessment: dict) -> dict:
    need(not kit_dir.exists(), f"Kit directory already exists: {kit_dir}")
    kit_dir.mkdir(parents=True, exist_ok=False)

    sources = {
        "modified10": ROUND / "lab-build/modified10-candidate.bi",
        "modified9": ROOT / "outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN",
        "modified1": ROOT / "outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN",
        "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
    }
    for mode, rel_target in PATHS.items():
        dst = kit_dir / rel_target
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sources[mode], dst)
        need(sha(dst.read_bytes()) == DIGESTS[mode], f"Copied module hash mismatch: {mode}")

    shutil.copy2(ROOT / "tools/fw/verify_modified10_kit.py", kit_dir / "verify.py")
    shutil.copy2(ROOT / "patches/z6-c380-modified10-fullsize-convergence.json", kit_dir / "patch-recipe.json")
    shutil.copy2(
        ROOT / "outputs/Z6-C380-cal33-control1a-reviewed-2026-11-12/baseline112.json",
        kit_dir / "baseline112.json",
    )

    start_here = """================================================================================
NIKON Z6 C3.80 MODIFIED10 — PREFLASH REVIEWED CONVERGENCE PACKAGE (2026-11-13)
================================================================================

【本版定位与相对 Modified9 的精确增量】
在已通过 9 张实机快门零 Err 与暗场 100% 释放验证的 Modified9 基础上，仅新增 12 个代码字节
（+ 2 个模块末尾 CRC 字节，共 14 字节差异），同时闭合后端替换缩放旁路与后端空间表回弹：

1. [新增 1 字节] 全尺寸前端 RAW 直通编码器 (0x100ae3a4: bl 101ba474 -> bl 101ba4b6)：
   - 全尺寸 RAW (L / 6064×4040, size=0) 下省略后端替换缓冲 REQ+0x1a8，使经过 Modified9
     前端 2D 多项式归零后的前端 RAW 缓冲 (frame+0x1f8) 直接送入无损 NEF 编码器 (0x100af648)，
     整体绕过后端 ISP (0x20380000) 的四通道数字增益 (+0x708/+70c)、偏移 (+0x710/+714)、
     上限 (+0x720)、双 17 点空间表 (+0x1200/+1224) 与 257 点暗角曲线 (+0x2890)。
   - 中/小尺寸 RAW (M/S, size=1/2) 自动保留原厂后端缩放替换路径，不破坏几何裁切契约。
2. [恢复 Modified2/3 共 11 字节] 后端 257 点暗角曲线与双 17 点空间表归零：
   - 修正 Modified9 剥离后出现的 MakerNote NEFInfo 0x0007 active=1 回弹问题，确保
     NEFInfo 0x0006 四系数与 L=0、NEFInfo 0x0007 active=0，并保护预览与中/小尺寸路径。
3. [完整保留 Modified9 已验证基础]：
   - 保留 Modified1 三处暗电流邻域钳制旁路 (0x100c2654 / 0x100c267c / 0x100c2690)。
   - 保留前端全部 14 个原生算子、ID35 原始传输、CAL33 表及 0x1002d884 提交前原地多项式归零
     清洗器（507 次前端寄存器写入与 Modified9 逐项一致，不破坏 50ms Event 8 握手）。

【诚实边界声明】
本包已完成 564 组 Unicorn 原生指令回放、13 个保护区独立字节审查、11 项升级/回退检查、
5 项擦写调度及双版本 QEMU 实机标定注入验证；但主视场细密彩圈与 R/B 直方图缺码梳状齿是否
在实机像素上消除，仍须由本次同条件实拍 NEF 独立验收。

--------------------------------------------------------------------------------
【目录结构（4 档位完整回退保障）】
--------------------------------------------------------------------------------
01_TEST_MODIFIED10/EG162080.BIN
  ★ 本次测试候选 (SHA-256: 85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4)
02_BACK_TO_MODIFIED9/EG162080.BIN
  上一版已实机验证零 Err 基线 (SHA-256: 70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c)
03_DARK_ONLY_MODIFIED1/EG162080.BIN
  仅暗场补丁基线 (SHA-256: eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875)
04_STOCK_C380/EG162080.BIN
  官方原版 C3.80 急救恢复包 (SHA-256: 1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c)

--------------------------------------------------------------------------------
【刷入前必做卡根校验】
--------------------------------------------------------------------------------
1. 电量充足（建议 >70%），格式化存储卡后，仅将 01_TEST_MODIFIED10/EG162080.BIN 复制到存储卡根目录
   （卡根目录只能有这一个 .BIN 文件）。
2. 在电脑端运行校验器确认卡上文件无误：
   .\\work\\re_env\\Scripts\\python.exe outputs/Z6-C380-modified10-reviewed-2026-11-13/verify.py --card-root <盘符>:\\ --mode modified10
3. 插卡开机，建议先按一下【回放键 ▶】停留 3 秒（释放后台初始占用），再进入【设定菜单 -> 固件版本 -> 更新】。
"""
    (kit_dir / "START_HERE.txt").write_text(start_here, encoding="utf8")

    flat_compare = """================================================================================
MODIFIED10 实拍验收对比步骤 (与 11.13_modified9 同条件对照)
================================================================================
1. 机身菜单保持不变：
   - RAW 记录：14-bit 无损压缩，尺寸 L (全尺寸 6064×4040)
   - 机械快门，长曝光降噪 Off，高 ISO 降噪 Off
   - 暗角控制 Off，自动失真控制 Off，衍射补偿 Off
2. 拍摄矩阵（共 9 张即可闭环验收）：
   - 3 张 FLAT 平场：与 11.13_modified9 保持相同镜头/光圈/ISO 1600/均匀光源（建议包含两档相邻快门以复核空间锁定 vs 信号锁定）
   - 3 张 BIAS 偏置场：盖严镜头盖，ISO 1600，1/8000s
   - 3 张 DARK 暗场：盖严镜头盖，ISO 1600，5s
3. 验收判据：
   - 无损解码 0 误差、机械快门连续释放无 Err；
   - MakerNote NEFInfo 0x0006 四系数与 L=0、NEFInfo 0x0007 active=0；
   - 中心 400×400 局部 ADU 直方图 FFT 检验 R/B 周期性缺码梳状齿是否消失；
   - 16×16 原始 CFA 径向剖面检验主视场 σ=6 同心细彩环是否消除；
   - 5s 暗场 112 基准热噪点维持 0/112 钳制、BIAS 维持 0 死黑截断。
"""
    (kit_dir / "FLAT_COMPARE.txt").write_text(flat_compare, encoding="utf8")

    shot_log = """Date: 2026-11-13
Firmware installed: 01_TEST_MODIFIED10/EG162080.BIN (SHA256: 85b1889b...deb4)
Lens / Aperture:
Light source:
Menu Vignette / Distortion / Diffraction: Off / Off / Off
LENR / High ISO NR: Off / Off
FLAT files:
BIAS files (1/8000s ISO 1600):
DARK files (5s ISO 1600):
Shutter behavior notes:
"""
    (kit_dir / "SHOT_LOG_TEMPLATE.txt").write_text(shot_log, encoding="utf8")

    review_md = f"""# Nikon Z6 C3.80 `Modified10` 安装前离线安全审查报告 (2026-11-13)

## 1. 方案收敛依据与设计目标

在 `11.13_modified9` 实拍复核中：
- **已验证通过项**：暗场 112 个基准热噪点 `0/112` 钳制（100% 释放）、偏置场 `0 ADU` 截断为 `0` 且双帧差分读出噪声 `3.536 DN` 与原厂完全一致、机械快门连续 9 张零 `Err`、2.20 亿像素独立无损解码零误差。
- **定位到的剩余彩圈/缺码根因**：
  1. `Modified9` 剥离 `Modified2/3` 后，实拍 `Z61_4945.NEF` 的 `NEFInfo 0x0007`（后端 `0x20381200/+1224` 双 17 点空间表）重新回弹为 `active = 1`（系数 `[142, -79, 0, -74, -6, 61]`），`NEFInfo 0x0006` 四系数亦恢复非零。
  2. `Modified1`–`Modified9` 的全部静态全尺寸 NEF 仍取自后端 ISP（`0x20380000`）写回的替换缓冲 `frame+0x1fc`，局部直方图 FFT 显示 R（`f=0.22815`）与 B（`f=0.20984`）在无损压缩前仍经过数字通道乘法缩放。

因此 **`Modified10`** 在完全保留 `Modified9` 前端安全架构的基础上，精确合并两项收敛改动：
1. **`0x100ae3a4` 全尺寸前端 RAW 直通补丁（`still-preserve-fullsize-raw`，1 代码字节变更）**：将 `bl #0x101ba474` 改为 `bl #0x101ba4b6`。在全尺寸 RAW（`owner+0x192 == 0`）下省略可选后端替换目的地 `REQ+0x1a8`，后端 ISP 原生切入 `bank+0x580 = 0, bank+0x67c = 0x100`（与机身原厂纯 JPEG 模式及特殊模式 `3/4/5/6` 相同的无 RAW 写回通道状态），使经过前端 `0x1002d884` 多项式归零后的前端 RAW 句柄 `frame+0x1f8` 直接进入无损 NEF 编码器 `0x100af648`；中/小尺寸 RAW（`size=1/2`）则继续走原厂后端缩放替换，严格保持几何契约。
2. **恢复 `Modified2` + `Modified3` 后端空间表与元数据归零（6 处共 11 代码字节变更）**：将后端 257 点暗角曲线锁定为单位值 `1024`、双 17 点空间表走原生清零分支 `0x1019743a`，确保 `NEFInfo 0x0006`（四系数=0, `L=0`）与 `NEFInfo 0x0007`（`active=0`）彻底归零，并同时保护预览及中/小尺寸路径。

---

## 2. 精确字节改动清单

- **基线原厂固件 SHA-256**：`{DIGESTS['stock']}`（33,502,842 字节）
- **父本 `Modified9` SHA-256**：`{DIGESTS['modified9']}`
- **候选 `Modified10` SHA-256**：`{DIGESTS['modified10']}`（CRC16 = `{assessment['crc16']}`，模块 CRC 余数 `0x0000`）
- **变更统计**：相对 `Modified9` 仅变更 **12 个代码字节 + 2 个 CRC 字节（共 14 字节）**；相对原版共变更 **93 个代码/常量字节 + 2 个 CRC 字节（共 95 字节）**。

| 地址 | 所属功能组 | 原厂字节 | `Modified10` 字节 | 指令语义 |
| :--- | :--- | :--- | :--- | :--- |
| `0x1002d884` | `Modified9` 前端清洗器 | 68B `00` | 68B 清洗器机器码 | 原地清零 `0xc29a3754` 54 项多项式，四通道直流置 `16384`，尾调用 `0x1011d548(1)` |
| `0x100ae3a4` | **全尺寸前端直通 (新增)** | `0cf166f8` | `0cf187f8` | `bl #0x101ba474` → `bl #0x101ba4b6`（全尺寸 `size=0` 保留前端 `frame+0x1f8`） |
| `0x100c2654` | `Modified1` 暗电流保留 | `00f065fa` | `4ff00000` | `mov.w r0, #0`（关闭邻域分类） |
| `0x100c267c` | `Modified1` 暗电流保留 | `00f045fa` | `4ff00200` | `mov.w r0, #2`（第一路强制关闭） |
| `0x100c2690` | `Modified1` 暗电流保留 | `90f81a18` | `4ff00201` | `mov.w r1, #2`（第二路强制关闭） |
| `0x100c28b2` | **`Modified2` 暗角归零 (恢复)** | `84f86200` | `84f86290` | `strb.w sb, [r4, #0x62]`（导出 `properties+62=0`） |
| `0x100c28c8` | **`Modified2` 暗角归零 (恢复)** | `84f86390` | `84f86300` | `strb.w r0, [r4, #0x63]`（导出中性选择非零标志） |
| `0x100c2964` | **`Modified2` 暗角归零 (恢复)** | `90f85f02` | `4ff00100` | `mov.w r0, #1`（强制选 `101a1240` 257×1024 单位曲线） |
| `0x1017d834` | `Modified9` 尾部挂钩 | `01209ff787fe` | `b0f626f8c046` | `bl #0x1002d884; nop`（14 算子原生执行后挂入清洗器） |
| `0x1019741a` | **`Modified3` 空间归零 (恢复)** | `59b1` | `0ee0` | `b #0x1019743a`（进入原厂双 17 点零表分支） |
| `0x10197868` | **`Modified3` 空间归零 (恢复)** | `4e77` | `4a77` | `strb r2, [r1, #0x1d]`（普通分支导出 `active=0`） |
| `0x10197876` | **`Modified3` 空间归零 (恢复)** | `4078` | `0020` | `movs r0, #0`（缓存分支导出 `active=0`） |
| `0x12013678` | 模块末尾 CRC16 | `f92d` | `{assessment['crc16']}` | CRC-16/CCITT 全模块校验余数归零 |

---

## 3. 离线安全审查结果汇总

| 审查维度 | 执行规模与结果 | 关键核验结论 |
| :--- | :--- | :--- |
| 双源独立构建与回退 | **通过** | 从原版 C3.80 与从 `Modified9` 增量构建逐字节一致；回退后 100% 还原 `Modified9` 与原版 |
| Unicorn 前端与 ABI 回放 | **120 + 64 + 8 = 192 次通过** | 真实 `CAL38`/`ID35` 下 507 次寄存器写入与 `Modified9` 完全相同；`r4–r11`/`SP`/栈哨兵及错误返回 `r4` 保持 |
| Unicorn 全尺寸路由与编码契约 | **68 + 240 = 308 次通过** | 120 对门控中仅 6 对全尺寸正常 RAW 省略 `REQ+0x1a8`；`size=0` 前后端几何一致，`size=1/2` 与原版逐字节一致 |
| Unicorn 空间链与元数据导出 | **64 次完整静态链通过** | `bank+0x584/+594=0`、`bank+0x1200` 72B 全零、257×1024 单位曲线、`NEFInfo 0x6` 归零、`NEFInfo 0x7 active=0`；`size=0` 编码器精确收到前端 `INPUT+0x24` |
| 独立字节与分支边界扫描 | **13 个保护区通过** | 初次扫描捕获并核实 `0x1002d140..` 为 32 位 ARM 启动指令（`mov r1,#0` 高半字 `0xe3a0` 伪命中 Thumb 短跳）；修正按 ARM32 + Thumb 分区扫描后内部跳转与对齐指针命中均为 `0` |
| 原生固件升级与回退调度 | **11 文件检查 + 5 擦写调度通过** | 原版/`Modified1`/`Modified4`/`Modified9` 均可刷入 `Modified10`；`Modified10` 可刷回任一旧版；坏 CRC/错机型/超长均被拒绝 |
| QEMU 实机标定注入回归 | **`Modified9` 与 `Modified10` 双通过** | 实机 `CAL38`/`ID35` 片段注入后，静态拍摄完整命中 `0x1002d884`（DC=`16384`、多项式非零项=`0`）、`ID35` 描述符保持、无超时退回取景，截图复核正常 |

---

## 4. 风险与实拍验收边界

- **未提前宣称消圈成功**：离线审查证明软件控制流、寄存器上传、句柄交换与文件升级链路正确；物理传感器与前端硅片（含保持原样的 `CAL33` 与 `ID35`）在直通编码后的真实平场彩圈与直方图缺码表现，必须以实拍 NEF 测量为准。
- **适用模式范围**：全尺寸静态 14-bit/12-bit NEF 为主验收对象；若实机测试中发现任何异常，可直接使用同包 `02_BACK_TO_MODIFIED9` 或 `04_STOCK_C380` 原厂菜单回退。
"""
    (kit_dir / "REVIEW.md").write_text(review_md, encoding="utf8")
    doc_path.write_text(review_md, encoding="utf8")

    files_to_list = sorted(
        [p for p in kit_dir.rglob("*") if p.is_file() and p.name != "manifest.json"],
        key=lambda x: x.relative_to(kit_dir).as_posix(),
    )
    manifest = dict(
        schema=7,
        candidate="modified10",
        generated_utc=assessment["generated_utc"],
        module_sha256=DIGESTS,
        files=[record_file(p, kit_dir) for p in files_to_list],
    )
    (kit_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    verify_res = check_kit(kit_dir)
    return dict(kit_dir=kit_dir.relative_to(ROOT).as_posix(), doc=doc_path.relative_to(ROOT).as_posix(), verify=verify_res)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kit-dir", type=Path, required=True)
    ap.add_argument("--doc", type=Path, required=True)
    args = ap.parse_args()

    assessment = assess()
    (ROUND / "assessment.json").write_text(json.dumps(assessment, indent=2), encoding="utf8")
    pkg = build_kit(args.kit_dir, args.doc, assessment)
    (ROUND / "package-result.json").write_text(json.dumps(pkg, indent=2), encoding="utf8")
    print(json.dumps(dict(ok=True, candidate_sha256=assessment["candidate_sha256"], kit=pkg["kit_dir"], verify=pkg["verify"])))


if __name__ == "__main__":
    main()

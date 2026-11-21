# 后续优先攻关路线图 (Roadmap & Open Priorities)

> 🌐 **语言 / Language**: **简体中文** · 🏠 [返回项目主页](../README.md) | **[文档索引](README.md)** | **[更新日志 (Changelog)](CHANGELOG.md)**

## 1. 当前优先任务状态总览

当前正式版固件 **`Modified24`（`v3.80-modified24`）** 已完成同心彩圈抑制、通道增益加成归零（`1.0000×`）、暗电流与单像素星点保留、全快门无损压缩 / 未压缩 `packed-14` 等价直通、`PID 0x0526` 与 `PID 0x1111` 双正交借壳菜单切换、VGC 通道 1（背面 LCD + OLED EVF）纯红护眼夜视显示、M 档 `60"~600"` 扩展慢门及曝光后纯等待间隔拍摄的真机闭环验收。3 项阶段性优先任务状态总览如下：

| 优先级 | 课题名称 | 当前状态 | 核心结论摘要 | 关联报告 / 证据 |
| :---: | :--- | :---: | :--- | :--- |
| **P1** | **1. 长曝未压缩直通 RAW 硬件位打包修复** | **已真机闭环集成** | 通过 `0x100A34D0 -> 0x1002DB5C`（`tramp_a34d0`）恢复前端 `format=3`（`16-bit LE`）输入的无损硬件 `14-bit`（`42,920,960` B）/ `12-bit`（`36,780,160` B）线性位打包；真机 `5s` 与 `60s` 共 9 张 NEF 实拍与 `LibRaw 0.22.2` 逐像素 `0` 差异、预览重叠 `0` | [MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md)、[evidence/m23_audit_metrics.json](evidence/m23_audit_metrics.json) |
| **P2** | **2. 夜视红光模式（Night Vision Red Display）** | **已真机闭环发布 (`v3.80-modified24`)** | 逆向提取 Z8 `d11` 暖色显示架构，在 Z6 VGC 通道 1（`0x20144000` 背面 LCD + OLED EVF）实现 `Mode 2A LumaRed`（`0x201454F0 = 0x00003000`）与硬件网格纯红掩码（`0x20145618` `G=0, B=0`），借用设定菜单「信息显示」（`PID 0x1111`）并锁定 `DISP` 黑底亮字；通过 Unicorn `26+12+648` 项、`z6-qemu`（`RedGridDiffPx=5109`）与物理 Z6 真机验收，RAW/JPEG/HDMI 零污染 | [NIGHT_VISION_RED_DISPLAY_ARCHITECTURE.md](NIGHT_VISION_RED_DISPLAY_ARCHITECTURE.md)、[evidence/probe_modified24_native_result.json](evidence/probe_modified24_native_result.json)、[evidence/qemu_modified24_result.json](evidence/qemu_modified24_result.json) |
| **P3** | **3. 对焦位置待机记忆（Standby Focus Retention）** | **待重新攻关** | 唯卓仕 AF 16mm F1.8 Z 等副厂步进马达镜头在机身待机自动休眠唤醒后复位至物理零点（假无限远 `∞`），丢失星点真无穷远合焦位置（如 `5.2m`）；冷启动关机重启正常，待机唤醒必丢 | [STANDBY_FOCUS_LOSS_INVESTIGATION.md](STANDBY_FOCUS_LOSS_INVESTIGATION.md) |

---

## 2. 当前唯一待攻关课题排查切入点与验收标准

### P3. 对焦位置待机记忆（Standby Focus Position Retention）
- **已核实现象与前序排查复盘**：
  - 唯卓仕 AF 16mm F1.8 Z 等副厂线控镜头在关机冷启动（触发 `0x0410001f` 完整重挂载握手并执行镜头恢复流程）时可正常恢复焦点；但在待机自动休眠断电再半按快门唤醒时，镜头 MCU 冷复位回物理零点（假无限远 `∞`），机身仅走快速同步而未重发完整初始化与位置恢复序列，导致星点脱焦。
  - 前序 4 轮尝试已排除的无效切入点（详见 [STANDBY_FOCUS_LOSS_INVESTIGATION.md](STANDBY_FOCUS_LOSS_INVESTIGATION.md)）：
    - `0x10525AD6`：实为联机 PTP LiveView 函数，脱机单机拍摄不经过；
    - `0x1025E8C2`：底层电源 Resume 时序过早，镜头 MCU 尚未完成 SPI 握手且 `r0` 对象未就绪；
    - `0x1029A930`：`TBB 0x1029A7A0` 分支误挂在 Command `0x2b`，而非真正的 `MlLensConnectComplete` Command `0x2c`（`0x1029A946`），且未防止副厂镜头上报零点覆盖缓存焦点。
- **下一轮排查切入点**：
  1. 全链路对比「关机保存 -> 冷启动开机完整镜头挂载（`0x0410001f` -> NVRAM/RAM 焦点属性 `0x1ba2` / `0x1133` 读取 -> `0x104C4CA8` / Opcode 9 下发）」与「进入待机断电前状态保存 -> 待机唤醒卡口重新上电握手（含 `0x1029A946` Command `0x2c`）」两条状态机；
  2. 重点核查待机进入前是否已将当前手动合焦脉冲写入持久缓存、唤醒握手期间副厂镜头自检上报的 `0` 零点是否覆盖了机身内存中的目标焦点值，以及唤醒完成后触发等价冷启动重挂载恢复所需的精确事件条件；
  3. 保持单变量独立分支验证，未经真机实测确认有效前不合入正式发布包。
- **验收标准**：「保存对焦位置」（`PID 0x1ba2`）开启时，使用唯卓仕 16mm F1.8 Z（及原厂 Z 卡口镜头）手动合焦至非零点位置（如 `5.2m`），经历机身待机定时器自动黑屏休眠并通过半按快门/AF-ON/菜单键唤醒后，对焦距离标尺与实际光学焦点稳定保持或自动回到休眠前合焦位置，无 `Err` 报错、无卡顿死循环。

---

## 3. 历史阶段档案指引

历次固件正式发布与早期原型迭代记录已独立归档至 **[CHANGELOG.md](CHANGELOG.md)**，单轮专项审查与实拍报告保留在 `docs/MODIFIED*.md` 与 `docs/RAW_*.md` 中供技术溯源。

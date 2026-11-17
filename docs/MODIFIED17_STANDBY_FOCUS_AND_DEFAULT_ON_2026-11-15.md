# [RECALLED / UNRESOLVED] Nikon Z6 C3.80 Modified17
> [!CAUTION]
> **Status: UNRESOLVED / RECALLED**
> 本版本的待机休眠对焦恢复 Hook 经真机实测未生效。详细技术调查与失败原因剖析请参见 [STANDBY_FOCUS_LOSS_INVESTIGATION.md](STANDBY_FOCUS_LOSS_INVESTIGATION.md)。
> 当前开发已回退至稳定的 Modified15 基线，并推进全新方案。

# Nikon Z6 C3.80 Modified17 固件构建与交付报告

- **构建基线**: Nikon Z6 C:3.80 官方固件（SHA256: `1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c`）
- **上一候选版本**: Modified16（A3 菜单切换“天文无损”+ 常驻 30–600s 慢门，SHA256: `4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf`）
- **本版目标 (Modified17)**:
  1. 彻底解决唯卓仕（Viltrox）AF 16mm F1.8 Z 等 Z 卡口线控镜头在相机待机休眠（Standby Sleep）唤醒后，焦点自动重置归零至假无限远（`∞`，实际星点真合焦在 `5.2m`）的严重跑焦问题。
  2. 设定菜单（扳手图标）中“保存对焦位置”（Save focus position，属性 ID `0x1ba2`）出厂与复位默认值由 `0 (关闭)` 改为 `1 (开启)`。
  3. 100% 完整继承 Modified16 的全部天文极客特性（A3 菜单动态切换、无损暗电流保留、彻底消除彩圈和空间吃星滤波、常驻 30s–600s 长曝光慢门）。

---

## 一、逆向成因与技术攻坚

### 1. 唯卓仕镜头待机跑焦成因确证
- **镜头端硬件机制**：唯卓仕 AF 16mm F1.8 Z 等线控镜头在对焦行程尽头为机械/假无限远（`∞`），而天体星点的真无限远由于装配公差标定在刻度 `5.2m` 处。当相机进入待机休眠时，机身切断了 Z 卡口镜头供电；半按快门重新上电唤醒时，唯卓仕镜头 MCU 独立进行冷启动上电自检，步进马达自动复位至假无限远极限位置。
- **机身端固件漏洞**：原厂 Z6 固件在关机重启（Cold Boot）时会执行 `0x104c4ca8`（Lens Restore Engine），向镜头发送 RPC opcode 9 指令恢复保存的对焦编码器脉冲；然而在待机休眠唤醒（`CCaptureCameraControl_StartCameraLiveView`, `0x10525a70`）中，原厂握手等待镜头就绪后直接退出（`pop {r3..r7, pc}`），根本没有调用任何对焦恢复逻辑，导致被复位到假无限远的唯卓仕镜头被彻底遗忘。

### 2. Modified17 精准修补方案
1. **菜单出厂默认开启**：
   - 菜单项描述符：`0x113a6390`（属性 ID `0x1ba2`）。
   - 偏移 `+0x10`（`0x113a63a0`）：原厂默认值为 `0x00000000`（关闭）。
   - **修改为**：`0x00000001`（开启）。相机复位或初始化时默认开启“保存对焦位置”。
2. **待机唤醒自动恢复跳板**：
   - 在 ROM 零填充安全空洞 `0x1002df00`（44 字节）部署安全跳板：
     1. 执行原厂 1000ms 镜头稳定延时（`sleep(1000)`）；
     2. 调用 `GetProperty(0x1ba2)` 检查机身设置；
     3. **仅当**属性等于 1 时，获取相机单例指针并调用 `0x104c4ca8`（镜头设置与对焦恢复引擎）；
     4. 若属性为 0（用户手动关闭）或单例为空，则精准跳过恢复；
     5. 完整恢复 AAPCS 保护寄存器与栈帧，平滑退出 `StartCameraLiveView`。
   - 挂钩点：在 `0x10525ad6` 处部署 12 字节挂钩（`bl 0x1002df00` + NOPs）。

---

## 二、固件构建与自动化验证结果

### 1. 固件二进制哈希
| 固件版本 | 路径 | SHA256 | CRC16 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| **Modified17 (本版)** | `outputs/Z6-C380-modified17-reviewed-2026-11-15/01_TEST_MODIFIED17/EG162080.BIN` | `4dc4f686df99eaa54be7bba60cb23d41154a48a51b986e6ecdf2f296f317b442` | `2e06` | **通过** |
| **Modified16 (回滚)** | `outputs/Z6-C380-modified17-reviewed-2026-11-15/02_BACK_TO_MODIFIED16/EG162080.BIN` | `4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf` | `8c14` | **通过** |
| **Modified15 (回滚)** | `outputs/Z6-C380-modified17-reviewed-2026-11-15/03_BACK_TO_MODIFIED15/EG162080.BIN` | `0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c` | `9052` | **通过** |
| **Modified13 (回滚)** | `outputs/Z6-C380-modified17-reviewed-2026-11-15/04_BACK_TO_MODIFIED13/EG162080.BIN` | `3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749` | `f569` | **通过** |
| **Stock C3.80 (官方)** | `outputs/Z6-C380-modified17-reviewed-2026-11-15/05_STOCK_C380/EG162080.BIN` | `1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c` | `0000` | **官方原版** |

### 2. 双向还原逐位校验（Exact Bit-Rollback）
- `Modified17` 逆向应用对焦补丁 -> **100% 逐位还原至 `Modified16`**（无一字节偏差）。
- `Modified17` 逆向应用全部补丁 -> **100% 逐位还原至官方 `Stock C3.80`**。

### 3. Unicorn 原生仿真核验（7/7 Suites 100% 通过）
1. `0x1315` 动态派生属性预测矩阵：**PASS**
2. 前端 2D 多项式净化器 & 507-MMIO 校验：**PASS**
3. 数字增益 & CAL33 Group 4 校验：**PASS**
4. 暗电流保留、暗角补偿中和、空间平滑关闭校验：**PASS**
5. 无损 NEF 强行约束与 36 国语言 UI 字串校验：**PASS**
6. 30–600s 常驻长曝光慢门端到端仿真校验：**PASS**
7. 待机对焦恢复与默认值仿真套件：
   - **Subtest A (开启状态 0x1ba2 == 1)**: 仿真延时 1000ms、属性查询、单例获取、调用 `0x104c4ca8` 恢复引擎全流程精确命中并返回！
   - **Subtest B (关闭状态 0x1ba2 == 0 - 负向对照)**: 恢复引擎被精确旁路，严格维持原厂行为！
   - **Subtest C (单例空指针防护)**: 空指针安全防护有效，无崩溃风险！

### 4. 固件更新器与故障注入测试
- `stock`、`modified16`、`modified15` 与 `modified17` 的双向更新路由校验：**PASS**
- 损坏 CRC 与非法文件名拒绝测试：**PASS**
- 擦除中断与坏块调度容错测试：**PASS**

---

## 三、刷机与使用说明

1. 准备一张已在相机中格式化的 XQD / CFexpress 存储卡。
2. 将 `outputs/Z6-C380-modified17-reviewed-2026-11-15/01_TEST_MODIFIED17/EG162080.BIN` 复制到卡根目录。
3. 确保电池电量充足，开机进入：`设定菜单`（扳手图标）→ `固件版本` → 选择 `更新`。
4. 更新完毕按提示关机并重启相机。
5. **对焦位置保存体验**：
   - 默认出厂已自动开启 `设定菜单` → `保存对焦位置`。
   - 使用唯卓仕 16mm F1.8 Z 等镜头对焦到天体真合焦位置（屏幕约显示 `5.2m`），相机在待机自动休眠或半按快门唤醒后，镜头马达将自动平滑转回 `5.2m` 真合焦位置，不再复位到假无限远 `∞`！

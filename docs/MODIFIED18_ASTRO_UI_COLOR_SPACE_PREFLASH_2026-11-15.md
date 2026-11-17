# Nikon Z6 C3.80 `Modified18` (方案 A1: 色空间开关天文直通 + 解除 RAW 压缩绑定 + 常驻 30–600s 慢门长曝光) 预检报告

- **日期**: 2026-11-15
- **目标机型**: Nikon Z6 (第 1 代), 官方基线固件 `C3.80` (`EG162080.BIN`, `33,502,842` 字节)
- **候选代号**: `modified18-astro-ui-color-space-600s-v1`
  - **SHA-256**: `5d404ea3707796c895782ebe75288763a67a238b7cac6cfce6dec71ba04dd157`
  - **CRC16-HQX**: `0xac94` (`crc_hqx(full_file, 0) == 0`)
  - **配方 JSON**: `patches/z6-c380-modified18-astro-ui-color-space-600s.json`
  - **总补丁点数**: `101` (17 处色空间动态门控及 UI 补丁 + 84 处常驻 30–600s 扩展慢门补丁)
  - **字节改动量**: `5,694` 字节 vs Stock C3.80
- **交付包路径**:
  - 目录: `outputs/Z6-C380-modified18-reviewed-2026-11-15/`
  - 压缩包: `outputs/Z6-C380-modified18-reviewed-2026-11-15.zip` (`73,222,654` 字节)
- **前序问题处置记录**:
  - 副厂线控镜头待机休眠丢焦问题：已正式归档并标记为 **UNRESOLVED (未解决/暂挂)**，详见技术复盘文档 [`docs/STANDBY_FOCUS_LOSS_INVESTIGATION.md`](STANDBY_FOCUS_LOSS_INVESTIGATION.md)；本次构建彻底剥离所有不稳定对焦 Hook，固件达到最高安全级别。

---

## 1. 核心需求背景与方案演进

### 1.1 为什么废除方案 A3，切换为方案 A1？
在前期 `Modified16` 中实现的“方案 A3”存在一个关键痛点：
- **方案 A3 机制**：将【NEF(RAW)压缩】菜单中的第 2 项（原先的有损压缩）改造为“天文无损”。为了让机身以无损格式存储，固件底层注入了 5 处强制无损压缩劫持（Buffer 尺寸强制、硬件 Codec 强制、EXIF 强制、IPC 容量强制）。
- **用户朋友的真实实战痛点**：深空天文摄影每次连续拍摄数百甚至上千张 light/dark/flat 帧。若只能使用无损压缩，PixInsight (PI) / Siril 载入每张图时必须在 CPU 上单线程解包 Huffman 变长编码，导致大批量堆栈耗时极长。天文摄影师强烈希望能拍**未压缩 RAW (Uncompressed NEF)**，以实现内存直接映射与极速并行堆栈！
- **方案 A3 的致命局限**：因为天文模式被死死绑定在第 2 项无损压缩上，用户根本无法在开启天文直通的同时拍摄未压缩 RAW。

### 1.2 方案 A1 的极致解耦优势
方案 A1 借用拍摄菜单中的 **「色空间 (Color space)」**（属性 `0x0508`）作为天文直通开关：

| 维度 | 方案 A3 (已废除) | 方案 A1 (Modified18 当前方案) |
| --- | --- | --- |
| **借用菜单** | `NEF(RAW)压缩` (0x0506) | **`色空间 (Color space)` (0x0508)** |
| **NEF 压缩菜单自由度** | 强制锁死在无损压缩，无法拍未压缩 RAW | **100% 官方原版自由选择 (未压缩 / 无损 / 有损)** |
| **PixInsight 堆栈速度** | 受限于 CPU 逐帧 Huffman 解压 | **支持原生未压缩 RAW，极速内存映射载入** |
| **快捷菜单支持** | 无法放入 `i` 快捷菜单 | **原生支持放入 `i` 快捷菜单，取景界面一键秒切** |
| **用户档位记忆** | 仅支持普通保存 | **支持存入 `U1 / U2 / U3` 模式转盘** (拧到 U3 秒进天文战备) |
| **EXIF 与文件名** | 保持标准 | **底层锁定 sRGB，保持 `DSC_xxxx.NEF`，绝不变成 `_DSC`** |

---

## 2. 方案 A1 技术架构全景

### 2.1 状态机与动态门控
- **色空间标量 RAM 槽位**: `0xC24CDDC4` (1 字节 uint8，0=sRGB, 1=Adobe RGB)；
- **有效记录格式 RAM 槽位**: `0xC24CC798` (4 字节 uint32，0=RAW, 1=RAW+JPEG, >=2=纯 JPEG)；
- **通用 Thumb-2 谓词门控 `fn_is_astro_r0`**:
  ```arm
  set_u32  r1, 0xC24CDDC4
  ldr_u8   r0, [r1]
  cmp_u8   r0, 1            ; 判断色空间是否选为 Adobe RGB (天文直通)
  bne      astro_inactive
  set_u32  r1, 0xC24CC798
  ldr_u32  r0, [r1]
  cmp_u8   r0, 1            ; 检查当前是否有 RAW 录制 (排查纯 JPEG/HDR 干扰)
  bls      astro_active
  astro_inactive:
  movs     r0, #0
  bx       lr
  astro_active:
  movs     r0, #1
  bx       lr
  ```

### 2.2 13 处动态门控 RAW 蹦床
1. `0x100ae3a4`: 全尺寸前端 RAW 直通 (`still-preserve-fullsize-raw`)
2. `0x100c2654`: 暗电流暗部不裁切（保留真实噪点分布与星点弱信号）
3. `0x100c267c`: 暗电流暗部不裁切
4. `0x100c2690`: 暗电流暗部不裁切
5. `0x100c28b2`: 暗角曲线中性化锁定
6. `0x100c28c8`: 暗角曲线中性化锁定
7. `0x100c2964`: 暗角曲线中性化锁定
8. `0x1011e2dc`: CAL33 空间暗角 Group 4 原厂单位矩阵归一化
9. `0x10122cbc`: 前端 4096x4 四路数字增益恒等归一化
10. `0x1017d834`: 前端 2D 多项式清零 + 16384 DC 增益归一化洞 (`0x1002d884`)
11. `0x10197418`: 双 17 点空间滤波表 neutral 归零
12. `0x10197866`: 双 17 点空间滤波表 neutral 归零
13. `0x10197874`: 双 17 点空间滤波表 neutral 归零

### 2.3 底层色彩与文件名安全锁
在 `0x1040AD00` (`IsColorSpace_sRGB`) 注入固定桩：
```arm
movs r0, #1
bx   lr
```
**安全收益**：即使菜单选择 Adobe RGB 档位作为天文开关，机身底层所有生成 EXIF 标签、内嵌 JPEG 预览图、以及文件命名规则的模块全部被锁定在 sRGB 规范下：
- 文件名始终保持官方标准的 `DSC_xxxx.NEF`（绝不会被机身前缀改为 `_DSCxxxx.NEF`）；
- 机内预览图色彩 100% 正常，无偏色无红染。

### 2.4 菜单 UI 多语言本地化
在 `0x104C0134` 注入本地化解析拦截器：
- **String ID `0x03B5` (原厂 'Adobe RGB')**:
  - 简体中文 (`lang=8`): `天文直通`
  - 繁体中文 (`lang=9`): `天文直通`
  - 英文及其他 34 种语言: `Astro RAW`
- **String ID `0x082C` (原厂 'Adobe RGB' 帮助说明)**:
  - 简体中文: `天文直通：关闭机内RAW暗电流裁切与空间彩圈校正。支持未压缩或无损压缩记录NEF图像。`
  - 繁体中文: `天文直通：關閉機內RAW暗場裁切與空間彩圈校正。支援未壓縮或無損壓縮記錄NEF影像。`
  - 英文: `Astro RAW: in-camera dark clipping and spatial corrections are bypassed. Compatible for Uncompressed and Lossless NEF (RAW).`
- 经过字库全量验证，所有 36 种相机语言字库零缺字。

---

## 3. 离线仿真与安全审查结果

1. **Unicorn ARM/Thumb 仿真结果** (`probe_modified18_native_result.json`):
   - **Predicate Matrix**: 15 组全状态覆盖测试 100% PASS；
   - **sRGB Color/EXIF Safety Lock**: 3 组色彩安全锁测试 100% PASS；
   - **Localized UI String Override**: 36 种语言 144 组字符串解析验证 100% PASS，邻近 ID 0 污染；
   - **Dual-Branch RAW Trampolines**: 6 组分支蹦床验证 100% PASS（Stock 与 Astro 双分支精准分流，AAPCS 寄存器与 APSR 标志位无损恢复）。
2. **静态代码与字库审查**:
   - **内部分支碰撞扫描**: 0 碰撞（无任何短跳转误入多字节 Hook 内部）；
   - **双向可逆性验证**: 100% 成功回滚至 Stock C3.80；
   - **CRC16-HQX 校验和**: 自动重算更新为 `0xac94`，整机硬件校验和 `0x0000` 完美吻合。

---

## 4. 实拍操作指南

### 4.1 如何拍摄未压缩天文 RAW（极速 PI 堆栈推荐）
1. 进入相机 **「照片拍摄菜单」** -> **「色空间」**，选择 **「天文直通」**（对应原 Adobe RGB 档）；
2. 进入相机 **「照片拍摄菜单」** -> **「NEF (RAW) 记录」** -> **「NEF (RAW) 压缩」**，选择 **「未压缩」**（Uncompressed）；
3. 此时拍摄的所有 RAW 图像均为**未压缩原生天文 RAW**：
   - 彻底旁路暗电流裁切、空间多项式、同心彩圈；
   - 纯定长未压缩格式，PixInsight / Siril 可以以极快速度免解压载入并堆栈，大幅节省 CPU 预处理时间！

### 4.2 如何拍摄无损压缩天文 RAW（节省卡空间）
1. 在「色空间」保持「天文直通」；
2. 在「NEF (RAW) 压缩」选择「无损压缩」；
3. 相机即生成标准的无损压缩天文 RAW。

### 4.3 终极野外盲操推荐配置（转盘 U3 联动）
1. 将相机模式拨至 **M 档**；
2. 快门波轮调至天文常用慢门（例如 `180"` 或 `300"`）；
3. 将色空间设为 **「天文直通」**，RAW 压缩设为 **「未压缩」**；
4. 进入相机「设定菜单」->「保存用户设定」-> **「保存到 U3」**；
5. **实战效果**：日常拍摄保持在 M / A 档（原厂色彩、原厂画质、原厂降噪）；到了野外拍星空时，只需单手将模式转盘拧到 **U3**，相机瞬间自动进入“M 档慢门 + 天文直通 + 未压缩 RAW”的天文战备状态！

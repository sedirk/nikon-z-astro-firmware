# Nikon Z6 C3.80 `Modified23` 未压缩直通 RAW 硬件位打包修复与真机验证报告

> 🌐 **语言 / Language**: **简体中文** | **[English](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18_EN.md)** · 🏠 [返回文档索引](README.md)

> [!IMPORTANT]
> **验证状态说明（已通过真机实拍闭环）**：`Modified23`（`modified23-uncompressed-astro-raw-pid0526-srgb-600s-v1`，SHA-256: `47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029`，CRC-16/XMODEM: `0xc083`）已完成离线全矩阵仿真与 **EXPEED 6 真机刷写实拍闭环验证（`samples/11.19_modified23`，共 9 张暗场 NEF，`hardware_pixels_verified = true`）**。除了通过 105 处二进制补丁与 `Modified22` 负例拒绝门禁审计、Unicorn 437 组管线矩阵仿真、软件 `packed-14`/`packed-12` 回环与实拍 `Z61_5105.NEF` 软件重打包回环以及 `7` 项升级预检 + `5` 项刷写调度离线审计外，真机实拍的 `6` 张长曝光未压缩 `14-bit` NEF（`5s` × 3 + `60s` 扩展慢门 × 3，共 `146,991,360` 硬件打包像素）均输出标准 `42,920,960` B `packed-14` 条带，零预览图重叠，与 `LibRaw 0.22.2` 全画幅逐像素零误差对齐，正式作为当前稳定发布版（`v3.80-modified23`）。

---

## 1. 问题复现与实拍样片解剖 (`samples/11.17_modified22/Z61_5105..5107.NEF`)

在 [`Modified22` 真机 18 张 NEF 独立审计](MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md)中，全部 `1/8000s` 短曝光样片（含直通与标准模式）、全部「无损压缩」样片以及标准模式 `5s` 暗场均输出标准 `42,920,960` B（`packed-14`，行距 `10,624` B），全画幅 `24,498,560` 像素零覆盖且与 `LibRaw 0.22.2` 解码零误差。唯独同时满足 **`直通RAW (sRGB)` + 长曝光（`5s`）+ 「未压缩（Uncompressed）」** 三个条件的 3 张暗场样片（`Z61_5105.NEF` ~ `Z61_5107.NEF`）出现底层布局异常：

1. **流体积溢出与位格式失配**：
   - TIFF `SubIFD2` 头部仍声明 `Compression = 34713`、`BitsPerSample = 14`，但 `StripByteCounts (0x0117)` 变为 **`48,997,120` B**（`6064 × 4040 × 2`，即 `16-bit LE` 非打包流，行跨度 `12,128` B），超出标准 `14-bit` 打包槽位上限 `raw_cap = 42,920,960` B 达 **`6,076,160` B**。
2. **底部行区被内嵌预览 JPEG 覆盖**：
   - 机内 NEF 封装器仍按 `42,920,960` B 槽位模板，在相对 `StripOffset` 固定偏移 `+44,072,448`（`0x02A07E00`）、`+48,027,648`（`0x02DCC000`）与 `+48,204,288`（`0x02DF8000`）处写入 `SubIFD1`、`MakerNote PreviewIFD` 与 `SubIFD3` 三段预览 JPEG 副本，覆盖了 `16-bit LE` RAW 流底部的第 **`3633..4000` 行**。
3. **第三方解码器错位解包**：
   - `LibRaw 0.22.2 / rawpy` 依据 `SubIFD2` 的 `Compression = 34713` + `BitsPerSample = 14` 按 `packed-14`（每 7 字节解 4 像素）解析 `16-bit LE` 数据，造成中位数跳变至 `3840~3856 DN` 并产生大量伪零码。

---

## 2. 全链路逆向根因定位 (`0x10124196 -> 0x100AE3A4 -> 0x100A3480`)

沿着 Z6 C3.80 静态拍摄 RAW 采集、缓冲路由与 NEF 编码流水线逆向追踪，彻底查明了「为何仅在 `直通RAW + >= 1s 长曝光 + 未压缩` 组合触发 `16-bit LE` 溢出」的精确硬件与软件耦合机制：

```text
[ 0x10124196 -> 0x10123E70 前端采集描述符 INPUT (frame+0x1f8) 规划 ]
  ├── 12-bit RAW (depth==0) 或 14-bit 短曝光 (< 1s, wide==0 && slow_1af0==0):
  │     INPUT format = 2 (12-bit packed) 或 4 (14-bit packed)
  └── 14-bit 长曝光 (>= 1s, depth==1 且 owner+0x252==1 或 owner+0x1af0!=0):
        INPUT format = 3 (16-bit LE unpacked, 2B/px)
           │
           ▼
[ 0x10142D8E / 0x10142E7A 采集后清零 wide/slow_1af0 -> 0x10124224 后端替换描述符 OUTPUT (frame+0x1fc) ]
  └── OUTPUT format 始终初始化为 4 (14-bit packed) 或 2 (12-bit packed)
           │
           ▼
[ 0x100AE33E (钩子点 0x100AE3A4) -> 0x100AE41E 释放缓冲路由 ]
  ├── 标准模式 / 中小尺寸 RAW: 0x100AE3A4 调用 0x101BA474 (has_raw==1) -> req+0x1a8 = OUTPUT -> 选用 format 4 / 2
  └── 全尺寸直通模式 (Astro RAW sRGB): tramp_ae3a4 调 0x101BA4B6 (r0=0) -> req+0x1a8 = 0 -> 保留前端 INPUT (长曝光下仍为 format == 3!)
           │
           ▼
[ 0x100AF648 NEF 编码调度器 (0x100AF65A: JPEG-only 直接返回 0) ]
  ├── 无损/有损压缩 (0x100A323E -> 0x101CAAD8): 原生支持 format == 3 输入描述符提交 (最终变长码流由硬件编码器生成)
  └── 未压缩 (Uncompressed) -> 调用 0x100A3480 未压缩硬件打包编码器:
        ├── chosen format != 3 (0x100A349E): 透传已打包缓冲 -> 42,920,960 B (正常)
        └── chosen format == 3 (0x100A349A: cmp r3, #3; beq #0x100A34D0):
              原厂 0x100A34D0: strb r2, [r4, #2]; strb r2, [r4, #3] (此时 r2 == 0!)
              -> 输入 [r4+2]=0 (16-bit LE), 输出 [r4+3]=0 (16-bit LE)!
              -> 0x100A359C 写出 12,128 × 4,040 = 48,997,120 B, 溢出 raw_cap 覆盖预览槽!
```

1. **前端长曝光 `format = 3` 采集契约（`0x10124196 -> 0x10123E70`）**：
   当 `14-bit` 曝光进入慢门宽动态/长积分状态（`owner+0x252 == 1`，对应 `>= 1s` 曝光，或 `owner+0x1AF0 != 0`）时，前端传感器 DMA 输入描述符 `INPUT`（`frame+0x1f8`）被配置为 `format = 3`（`16-bit LE` unpacked，每像素 16 位小端存储，有效光电数据仍为 14-bit `0..16383`）。
2. **为何标准模式与无损压缩不触发故障**：
   - 在**标准模式**（及中小尺寸 RAW）下，前端采集完成后 `0x10142D8E` / `0x10142E7A` 先将 `owner+0x252` 与 `owner+0x1AF0` 清零，随后 `0x10124224` 将后端替换描述符 `OUTPUT`（`frame+0x1fc`）初始化为 `format = 4`（`14-bit` packed）或 `format = 2`（`12-bit` packed）；释放路由 `0x100AE3A4` 调用 `0x101BA474`（`has_raw == 1`）将 `OUTPUT` 写入 `req+0x1a8`，再由 `0x100AE41E` 换入 `frame+0x1f8`，故进入 `0x100A3480` 时 `r3 != 3`，不走 `0x100A34D0`；
   - 在**无损压缩**下，压缩编码器入口 `0x100A323E` 原生支持 `format = 3`（`16-bit LE`）输入描述符并向硬件队列 `0x101CAAD8` 提交，输出标准尼康无损 14-bit/12-bit 压缩流，体积远小于 `42,920,960` B 槽位上限。
3. **未压缩编码器 `0x100A3480` 的 `0x100A34D0` 分支缺陷**：
   当全尺寸 `直通RAW` 在 `0x100AE3A4` 经 `tramp_ae3a4 -> 0x101BA4B6` 保持 `req+0x1a8 = 0`、将前端 `format = 3` 缓冲直接送入未压缩编码器 `0x100A3480` 时，`0x100A349A`（`cmp r3, #3; beq #0x100A34D0`）跳转至 `0x100A34D0`。此时寄存器 `r2 == 0`，原厂代码执行 `strb r2, [r4, #2]; strb r2, [r4, #3]`，把硬件位打包器（`CODEC_MMIO 0x20204000`）的输入格式码 `[r4+2]` 与输出格式码 `[r4+3]` 同时置为 `0`（`16-bit LE`），导致硬件原样输出 `48,997,120` B 未打包流，突破 `raw_cap = 42,920,960` B 槽位边界。
---

## 3. `Modified23` 工程修复设计 (`0x100A34D0 -> 0x1002DB5C`)

`Modified23` **完全不动前端传感器/DMA `format = 3` 采集契约**，仅在后端未压缩编码器 `0x100A34D0` 处增加第 **14** 处受 `fn_is_astro_r0` 门控的精确硬件位打包分支：

### 3.1 钩子点与全局交叉引用安全审计
- **补丁位置**：`0x100A34D0`（精确 4 字节替换）：
  - 原厂字节：`a270 e270`（`strb r2, [r4, #2]; strb r2, [r4, #3]`）
  - `Modified23` 字节：`8af7 44bb`（`b.w #0x1002db5c`，跳入 `tramp_a34d0`）
  - 紧邻指令保护：`0x100A34D4: e9e7`（`b #0x100a34aa`）保持逐位未动。
- **全 ROM 交叉引用扫描**：
  - `0x100A34D0..0x100A34D3` 区间内 32 位指针表命中：`0` 处；
  - 宽分支（`b.w` / `bl`）命中：`0` 处；
  - 局部条件分支命中：唯一入口为 `0x100A349C: beq #0x100a34d0`（精确指向钩子首地址 `0x100A34D0`，内部偏移 `+2` 处零跳入碰撞）。

### 3.2 `tramp_a34d0` (`0x1002DB5C..0x1002DB93`, 56 B) 跳板逻辑
在 [`tools/fw/z6_astro_ui_color_space_v2.py`](../tools/fw/z6_astro_ui_color_space_v2.py) 的 `astro_ui_cave` 中新增 `tramp_a34d0`（机器码：`07b5eff30082fff7cdfe012807d082f3008cbde80740a270e27075f098bc0020a0706978022900d00121e17082f3008cbde8074075f08bbc`）：

1. **寄存器与标志位全保护**：入口执行 `push {r0, r1, r2, lr}` 与 `mrs r2, apsr_nzcvq`，调用 `fn_is_astro_r0`（`0x1002D900`，判断 `PID 0x0526 == 1 && PID 0x131B <= 1`）；
2. **标准模式分支（`r0 != 1`）**：恢复 `msr apsr_nzcvq, r2` 与 `pop {r0, r1, r2, lr}`，原样执行 `strb r2, [r4, #2]; strb r2, [r4, #3]` 后执行 `b.w 0x100A34AA`，与原厂 `C3.80` 指令流 100% 等价；
3. **直通 RAW 分支（`r0 == 1`）**：
   - 将输入格式 `[r4+2]` 写为 `0`（`16-bit LE` unpacked 输入）；
   - 读取目标编码描述符 `ldrb r1, [r5, #1]`（`4` = 14-bit NEF，`2` = 12-bit NEF）：
     - 若 `r1 == 2`（用户菜单选 12-bit RAW），置 `[r4+3] = 2`（硬件 `12-bit` packed 输出）；
     - 否则置 `[r4+3] = 1`（硬件 `14-bit` LSB-first packed 输出：每 4 个 16-bit 像素打包为 7 字节，行尾 32 字节对齐）；
   - 恢复 `APSR` 与 `{r0, r1, r2, lr}`（`r0..r12, sp, lr, APSR` 零副作用），跳回 `0x100A34AA` 继续原厂硬件打包配置与 `StripByteCounts` 计算。
4. **纯线性硬件位打包（`lut_ptr = 0`）与无损回退保护**：
   - 在 `[r4+2] = 0, [r4+3] = 1` 下，编码器自动将 `CODEC_MMIO 0x20204000` 偏移 `+0x40` 设为 `0x00010008`，且查找表指针 `lut_ptr = 0`（零非线性色调映射，对 `0..16383` 范围像素严格逐位无损）；
   - 当「无损压缩」偶发遇到极高熵图像导致压缩流超出缓冲区回退调用 `0x100A3480` 时，同样自动走该硬件打包分支，杜绝回退溢出。

### 3.3 XIP Hole 1 代码洞空间与历史复现性审计
- `astro_ui_cave`（`0x1002D900..0x1002DE13`）：由 `Modified22` 的 `1,244` B 增至 `1,300` B（含 240 条指令 / `740` B 代码 + 多语言 UTF-16LE 表），距 `0x1002E000`（`ADDR_M20_IV_CAVE`）仍留有 **`492` B 空闲间隙**，距离 `0x1002EF04`（`m600_v2` 起点）仍留有 **`3,420` B 空闲余量**。
- `include_uncomp_raw_pack_fix` 默认保持 `False`，经自动回归验证，`Modified19`、`Modified20`、`Modified21` 与 `Modified22` 的构建 SHA-256 均 100% 逐位复现。

---

## 4. 刷机前离线全矩阵验证结果

全部验证证据已固化于 [`docs/evidence/probe_modified23_native_result.json`](evidence/probe_modified23_native_result.json) 与 [`docs/evidence/modified23_updater_audit.json`](evidence/modified23_updater_audit.json)，补丁配方固化于 [`patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json`](../patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json)。

### 4.1 各画幅 / 快门读出模式精确未压缩几何（`wide = 1` 长曝光直通 RAW）

经 Unicorn 驱动原生描述符链 `0x10124196 -> 0x10123E70 -> 0x10124224 -> 0x101254BC -> 0x100AE33E -> 0x100AF648 -> 0x100A359C` 实测，所有合法画幅与读出模式下的输出流均严格落入 `raw_cap` 预算之内：

| 读出与画幅模式 | 分辨率 (`W × H`) | 位深 | 输入格式 / 行距 | `Modified23` 输出格式 / 行距 | `StripByteCounts` (B) | 槽位上限 `raw_cap` (B) | 槽位边界核验 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FX 机械/前帘快门** (`ro=0, area=0`) | `6064 × 4040` | **14-bit** | `fmt=3` (`12,128` B) | `out_pack=1` (`10,624` B) | **`42,920,960`** | `42,920,960` | **PASS**（距首预览槽留有 `1,151,488` B 余量） |
| **FX 机械/前帘快门** (`ro=0, area=0`) | `6064 × 4040` | **12-bit** | `fmt=3` (`12,128` B) | `out_pack=2` (`9,104` B) | **`36,780,160`** | `36,780,544` | **PASS** |
| **DX 裁切模式** (`ro=0, area=1`) | `3952 × 2640` | **14-bit** | `fmt=3` (`7,904` B) | `out_pack=1` (`6,928` B) | **`18,289,920`** | `18,290,176` | **PASS** |
| **DX 裁切模式** (`ro=0, area=1`) | `3952 × 2640` | **12-bit** | `fmt=3` (`7,904` B) | `out_pack=2` (`5,936` B) | **`15,671,040`** | `15,671,296` | **PASS** |
| **FX 电子/静音快门** (`ro=1, area=0`) | `6104 × 4222` | **14-bit** | `fmt=3` (`12,208` B) | `out_pack=1` (`10,688` B) | **`45,124,736`** | `45,125,120` | **PASS** |
| **FX 电子/静音快门** (`ro=1, area=0`) | `6104 × 4222` | **12-bit** | `fmt=3` (`12,208` B) | `out_pack=2` (`9,168` B) | **`38,707,296`** | `45,125,120` | **PASS** |

*(对照：`Modified22` 在第一行 FX 14-bit `wide=1` 未压缩下输出 `out_pack=0`、`dst_s=12,128` B、`StripByteCounts = 48,997,120` B > `raw_cap = 42,920,960` B，精确复现真机溢出故障。)*

### 4.2 原生仿真、三层位打包回环与升级器审计汇总
1. **`tools/fw/probe_modified23_native.py`（全项 `PASS`，显式拒绝 `python -O/-OO`）**：
   - **实测二进制身份与 `Modified22` 负例拒绝门禁**：直接从受测候选镜像实测 SHA-256（`47a5caa9...`）、CRC-16/XMODEM（`0xc083`）与大小（`33,502,842` B），并验证将 `Modified22` 传入探针时被二进制校验与第 14 处钩子 Unicorn 执行双重拦截（`negative_m22_binary_gate_rejected = true`、`negative_m22_hook14_unicorn_rejected = true`）；
   - **437 组 RAW 管线分类矩阵（`432` 组正交网格 + `5` 组边界用例）**：
     - **`113` 组未压缩全链路核验**（`108` 组正交网格 + `4` 组 FX 电子快门 `readout=1` + `1` 组无损压缩溢出回退未压缩 `0x100AF6D8..0x100AF6E6`）：完整执行 `0x100A3480 -> 0x100A359C -> 0x101CA666 -> 0x10108F8A`，确认全部 `StripByteCounts <= raw_cap`、`CODEC_MMIO + 0x40` 格式位精确匹配（FX 14-bit `format=3` 为 `0x00010008`）且 `lut_ptr = 0`；
     - **`216` 组压缩队列描述符核验**（无损 / 有损压缩）：执行原生描述符准备与编解码队列提交（`0x100A323E -> 0x101CAAD8`；注：最终变长压缩比特流字节数由 EXPEED 硬件编码器在真机运行期生成）；
     - **`108` 组 `JPEG-only`（`raw_131b == 2`）跳过核验**：确认 `0x101BA474` 返回 `0`、`req+0x1a8 = 0` 且 `0x100AF648` 直接跳过 RAW 编码安全返回 `0`；
     - **`216` 组非直通模式原厂对拍**：确认非直通分支全部输出字段与原厂 `Stock C3.80` 及 `Modified22` 100% 逐字段一致。
   - **第 14 处钩子 `0x100A34D0` 专项验证（28/28 通过）**：遍历全部 `NZCV` 条件码组合与非零调用者寄存器，证明 `r0..r12, sp, lr, NZCV` 完全守恒且紧邻 `0x100A34D4: e9e7` 分支完好；
   - **`Modified22` 全量回归不变量**：30 组 UI/U1~U3 门控、30 组 `PID 0x130A = 0 (sRGB)` 锁定与 `Z61_`/`DSC_` 前缀、14 组 Auto ISO 原厂对齐、原 13 处钩子 28 组双分支、36 国语言 360 项 UI 字符串、8 组曝光后间隔序列与 37 组动态结束时间全部 **PASS**。
2. **三层像素位打包与 `LibRaw` 解码回环边界声明**：
   - **`synthetic_pack`（软件合成全画幅位打包回环，`PASS`）**：在 `6064 × 4040`（`24,498,560` 像素）随机与边界码值帧上验证 LSB-first `14-bit`（行距 `10,624` B，总长 `42,920,960` B）与 `12-bit`（行距 `9,104` B，总长 `36,780,160` B）软件打包/解包回环 `max_abs_adu_diff = 0`；
   - **`real_nef_libraw`（基于实拍 `Z61_5105.NEF` 的软件重打包 + `LibRaw` 解码回环，含样片环境为 `PASS`，无 `samples/` 的公开克隆自动标记 `SKIPPED`）**：读取 `samples/11.17_modified22/Z61_5105.NEF`（SHA-256 `65e9af0d...`）中全部 **`3,672` 行未受污染的原生 `16-bit LE` 传感器行**（第 `0..3632` 行与第 `4001..4039` 行，共 **`22,267,008` 像素**，实测最大值 `< 16384`），并用洁净第 `0..367` 行替换 `Modified22` 写卡时已被内嵌预览 JPEG 覆盖的第 **`3633..4000` 行**（共 **`368` 行 / `2,231,552` 像素**）构造完整 `4040 × 6064` 打包前参考帧，经软件 `packed-14` 重打包为 `42,920,960` B（距 `+44,072,448` 首预览槽留出 `1,151,488` B 余量，3 段内嵌预览 JPEG SHA-256 100% 完好）后交由 `LibRaw 0.22.2 / rawpy 0.28.0` 端到端解码，全部 `24,498,560` 像素相对打包前参考帧 `max_abs_adu_diff_vs_prepack_reference = 0`；
   - **`hardware_camera_nef` 与 `hardware_pixels_verified = true`（真机 EXPEED 6 硬件位打包验证，公开无样片克隆自动标记 `SKIPPED` / `false`）**：对真机刷入 `Modified23` 后实拍的 `samples/11.19_modified23` 全部 `9` 张 NEF（`3` 张 `5s` 无损压缩 + `6` 张 `5s / 60s` 未压缩 `packed-14`）执行逐像素与容器结构核验，实测 `146,991,360` 个硬件位打包像素相对独立 LSB-first 解包器与 `LibRaw 0.22.2` 零差异（`libraw_vs_independent_pixel_diff_count = 0`、`preview_overlap_count = 0`）。
3. **`tools/fw/probe_modified23_updater.py`（全项 `ok: true`，`negative_m22_binary_rejected = true`）**：
   - 完成 **`7` 项单模块升级文件检查**：含 **`5` 项合法跨版本升级/回退预检**（`Modified22 -> Modified23`、`Stock C3.80 -> Modified23`、`Modified21 -> Modified23`、`Modified23 -> Modified22`、`Modified23 -> Stock C3.80`，全部 `host_crc = 0`、`discovery_return = 0`、`integrity_return = 0`、`component_precheck_return = 0`，刷写前缓冲准备在物理原语 `0x1014A674` 前干净停止且 `end_canary_preserved = true`）与 **`2` 项异常镜像拒绝验证**（`bad_crc` 单比特翻转返回 `integrity_return = 3` 拒绝；错误文件名 `EG172080.BIN` 被发现阶段非零返回拒绝）；
   - 完成 **`5` 项离线刷写扇区调度检查**：含 **`4` 项正常跨版本调度**（`Modified22 <-> Modified23` 与 `Stock C3.80 <-> Modified23`，均精确执行 `330` 次扇区擦除与 `330` 次扇区编程适配调用，`prefix_preserved = true`、`tail_canary_preserved = true`、`physical_flash = false`）与 **`1` 项擦除故障注入检查**（`Modified22 -> Modified23` 注入擦除失败后立即中止，`program_service_calls = 0`）。
---

## 5. 真机刷写实拍闭环验证 (`samples/11.19_modified23`, 9 张 NEF)

真机刷入 `Modified23`（`EG162080.BIN` SHA-256 `47a5caa9...`）后，在 `ISO 1600`、`直通RAW (sRGB)`（`MakerNote 0x001E = 1`、文件名前缀 `Z61_`）下连续采集 `9` 张暗场样片（`Z61_5128.NEF` ~ `Z61_5136.NEF`，快门计数 `480745` ~ `480753`），完整审计指标固化于 [`docs/evidence/m23_audit_metrics.json`](evidence/m23_audit_metrics.json)：

| 样片分组 (`11.19_modified23`) | 曝光 / 压缩设置 | 验证布局 | `StripByteCounts` (B) | 内嵌预览碰撞 / 尾部冗余 | 独立解包 vs `LibRaw 0.22.2` | 112 固定热像素命中率 (`0,8..56`) | 原底部覆盖区 (`y+2>=3633`) 命中率 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`Z61_5128` ~ `5130`** (`3` 张) | `5s` · 14-bit 无损压缩 | `lossless_14bit` | `24,057,606` ~ `24,064,594` | `0` 碰撞 / `0` B | 原生无损解码正常 | **`0 / 112` (0%)** | **`0 / 17` (0%)** |
| **`Z61_5131` ~ `5133`** (`3` 张) | `5s` · 14-bit **未压缩** | `packed_14bit_stride10624` | **`42,920,960`** | **`0` 碰撞 / `0` B** | **`0` 差异像素** (`73,495,680` px) | **`0 / 112` (0%)** | **`0 / 17` (0%)** |
| **`Z61_5134` ~ `5136`** (`3` 张) | **`60s`** · 14-bit **未压缩** | `packed_14bit_stride10624` | **`42,920,960`** | **`0` 碰撞 / `0` B** | **`0` 差异像素** (`73,495,680` px) | **`0 / 112` (0%)** | **`0 / 17` (0%)** |

1. **EXPEED 6 硬件位打包零误差与容器完备性**：
   - 全部 `6` 张未压缩长曝光帧（涵盖 `5s` 与 M 档扩展慢门 `60s`）的 `StripByteCounts` 均严格由 `Modified22` 的 `48,997,120` B 收敛为标准 **`42,920,960` B**（每行 `10,612` B 有效载荷 + `12` B 全零对齐填充 = `10,624` B，单帧缩减 `6,076,160` B），`StripOffset + StripByteCounts == filesize`，三段预览 JPEG 全部位于 `StripOffset` 之前且零重叠；
   - 全部 `6 × 24,498,560 = 146,991,360` 个像素在独立 LSB-first `packed-14` 解包器与 `LibRaw 0.22.2` 之间 **`pixel_diff_count = 0`**。
2. **原覆盖行区（第 `3633..4000` 行）真实光电像素恢复证明**：
   - 全 `9` 张样片在顶部 `rows 8..3632`、原覆盖区 `rows 3633..4000` 与底部 `rows 4001..4031` 三段行带的中位数均为 `1009.0 DN`，全画幅 `zero_adu_count = 0`；
   - 将 `5s` 无损压缩帧 `Z61_5130.NEF` 与紧邻拍摄的 `5s` 未压缩帧 `Z61_5131.NEF` 在原覆盖行区 `rows 3633..4000` 内提取 `> 2000 ADU` 的真实暗电流热像素做跨格式空间对齐，实测皮尔逊相关系数 **`r = 0.999550`**（`67` 个并集热像素中 `63` 个双帧同时突破阈值），直接证明硬件位打包器输出了 100% 真实的传感器底部光电信号。
3. **帧差读出噪声与基线特性保持**：
   - `5s` 无损压缩对（`5128 vs 5129`）与 `5s` 未压缩对（`5131 vs 5132`）的有效感光区帧差噪声完全一致：`central_68pct_sigma = 4.2426 DN`、`IQR_sigma = 4.1934 DN`；`60s` 未压缩对（`5134 vs 5135`）帧拍摄时间间隔为 `60.71s` / `60.62s`（无长曝降噪黑帧等待），`central_68pct_sigma = 7.4246 DN`；
   - 全部 `9` 张暗场 R 通道中心 ROI 的 `[0.22, 0.24] cyc/DN` 频段峰值为 `92,620` ~ `97,087`（远低于 `204,608` 阈值，无 `0.2276 cyc/DN` 同心彩圈梳状峰），112 个固定热像素位点（含底部 `17` 个位点）空间钳制命中率全数为 **`0 / 112`**。

---

## 6. 本地可复现构建与离线校验

仅需 Python 3.10+ 标准库与官方 `Z_6_0380.bin` 即可构建并校验 `Modified23` 正式版刷机套件：

```powershell
# 构建 Modified23 正式版刷机目录及确定性 .zip 归档
python tools/build_modified23.py --stock path\to\Z_6_0380.bin --output-dir outputs\Nikon-Z6-C380-Modified23-Astro-Firmware --zip

# 对已构建目录执行独立只读二进制与机器码不变量核验
python tools/build_modified23.py --verify outputs\Nikon-Z6-C380-Modified23-Astro-Firmware
```

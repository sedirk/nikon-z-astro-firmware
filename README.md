# Nikon Z6 C3.80 天文直通 RAW 与长曝光固件增强项目 (Nikon Z6 Astro Firmware)

> 🌐 **语言 / Language**: **简体中文** | **[English](README_EN.md)**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Base Firmware](https://img.shields.io/badge/Nikon%20Firmware-C3.80-orange.svg)](https://downloadcenter.nikonimglib.com/en/download/fw/557.html)
[![Release Version](https://img.shields.io/badge/Release-v3.80--modified24-brightgreen.svg)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified24)
本项目是针对 **尼康 Z6（固件版本 C3.80）** 的深度底层逆向工程与固件增强成果。通过对原厂数码相机图像流水线（ISP）、显示控制器（VGC）、实时操作系统与菜单调度逻辑的精准重构，系统解决了尼康初代微单在深空与星野延时摄影中的四大核心痛点：**RAW 底层非线性暗角/增益梳状纹（同心彩圈）、暗电流与热噪点被激进邻域钳位（吃星/扣暗场失败）、扩展慢门（30秒以上）与间隔计时限制，以及夜间暗空缺乏护眼纯红夜视界面**。

---

## 1. 核心解决问题一览 (Feature Matrix)

| 痛点与功能模块 | 官方原厂 C3.80 行为 | 增强固件行为 (`Modified24`) | 底层技术实现与证据 |
| :--- | :--- | :--- | :--- |
| **同心彩圈 / 增益梳状纹**<br>*(Concentric Colored Rings)* | 前端 ISP 强制对全尺寸 RAW 注入 $4.39\text{ DN}$ 周期数字增益与暗角调制，导致 RAW 直方图 R/B 通道周期性缺码（$0.2276\text{ cyc/DN}$ 尖峰），深空拉伸出现严重同心彩圈 | **显著抑制/消除**：选「直通RAW」后 RAW 直方图平滑连续，梳状纹谱峰降低约 $9.8\sim 13.5\times$（$0.2276$ 频点幅值由 $27,242$ 降至 $2,012$，带内峰值由 $27.8\text{万}$ 降至 $2.8\text{万}$），平场校准不再出现彩环 | 全尺寸前端 RAW 直接绕过后端校正缓冲区与 $2\text{D}$ 多项式乘法器，四路 Q12 增益锁定 $1.0\times$ 单位增益，硬件位打包线性直通（详见 [技术文档 1](docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md)） |
| **星点吞噬 / 暗场邻域钳位**<br>*(Star Eating & Hot Pixel Suppression)* | 后端 ISP 对暗部像素做激进的 $3\times 3$ 邻域中值滤波与强制黑电平钳位，导致微弱单像素星点被当成噪点吃掉，暗场无法用于天文校准 | **原始保留**：完全解除热像素与暗电流的邻域抑制，暗部弱信号线性度与高能热噪点原样记录，暗场扣除完全有效 | 冻结 112 个基准热像素点在无损压缩与未压缩长曝暗场（`5s` / `60s`）中均 $0/112$ 命中钳位，偏置未裁剪帧差噪声约 $4.11\text{ DN}$（中央 68% 折算 $3.54\text{ DN}$），有效区零码计数为 0（详见 [技术文档 2](docs/02_STAR_EATER_AND_DARK_CURRENT.md)） |
| **无缝双模菜单切换**<br>*(UI-Switchable Astro Mode)* | 无法关闭 RAW 机内校正 | **借用色空间菜单无感切换**：在「照片拍摄菜单 -> 天文直通RAW模式」（原「色空间」项）中自由切换，与「NEF(RAW)记录」完全解耦（12位/14位、无损压缩/未压缩/有损压缩全快门档位原生可用），支持存入 `U1/U2/U3`、`我的菜单` 及 `i` 快捷菜单 | 借用色空间菜单属性 `PID 0x0526` (`RAM 0xC24CDEA0`)，底层有效色空间永久锁定标准 `sRGB` (`PID 0x130A = 0`)，文件名恒为 `Z61_xxxx.NEF`（详见 [技术文档 3](docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md)） |
| **常驻 30"~600" 扩展慢门**<br>*(Extended Shutter Speeds)* | M 档长曝光上限仅 30 秒，更长曝光需使用机械快门线或手按 Bulb/Time 门 | **全档位常驻**：M 档直接提供 **`60", 90", 120", 180", 240", 300", 480", 600"`** 8 档超长曝光，无需快门线精准定时曝光 | 重构 1/3 EV 曝光步进表与快门时长定时器分频逻辑（详见 [技术文档 4](docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md)） |
| **曝光后纯间隔计时**<br>*(Post-Exposure Interval Timer)* | 间隔拍摄的“间隔时间”包含曝光时长，长曝光时实际等待时间被压缩，甚至因曝光超长导致漏拍跳帧 | **曝光结束后开始倒计时**：设定的间隔时间成为纯曝光间隙（供传感器散热、连线传输或抖动防抖），且机身**动态计入曝光+降噪耗时**准确显示结束日期时间 | 拦截快门释放完成回调 `0x101FF392`，动态接管结束时间计算器 `0x1049C26C -> 0x1002E000` |
| **通道增益加成归零 / 改机还原**<br>*(Unity Gain & Astro-Mod Restoration)* | 写入 NEF 前隐蔽施加非单位 Q12 通道数字预放大（红通道约 $1.295\times$、蓝通道约 $1.263\times$），导致天文改机（去 UV/IR 滤镜）RAW 直出严重偏红、红通道提早饱和削顶 | **增益加成归零（$1.0\times$ 单位增益）**：彻底清除机内人为通道数字乘数，还原传感器真实光电荷与原生量子效率响应，天文改机拍摄 RAW/平场不再异常泛红，保留完整红光动态范围 | 在 `0x10122CBC` 将四路色通道 Q12 倍率锁定 `4096`（$1.0000\times$），实测平场中心 `R/G1` 中位数由机内加权的 `1.0103` 回归原生 `0.8997`（详见 [技术文档 1](docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md)） |
| **机内天文夜视红光显示**<br>*(Night Vision Red Display)* | 初代 Z6 无暖色/红光夜视模式，暗空下背面 LCD 与 OLED EVF 的蓝绿白光易破坏人眼暗适应并引入杂散光 | **LCD + EVF 纯红夜视开关**：在「设定菜单 -> 天文红光显示」（原「信息显示」项）一键开启纯红显示（`G = 0, B = 0`），支持放入「我的菜单」首项单键盲切；实拍 NEF、JPEG、测光直方图与外接 HDMI 输出 **100% 原生全彩零污染** | 借用信息显示属性 `PID 0x1111` (`RAM 0xC24DD0EC`)，仅拦截 VGC 通道 1 (`0x20144000`) 硬件 CSC (`0x00003000`) 与构图网格 (`0x20145618`)，`DISP` 参数屏永久锁定黑底亮字（详见 [技术文档 5](docs/NIGHT_VISION_RED_DISPLAY_ARCHITECTURE.md)） |

---

## 2. 效果实测与证据 (Real-Camera Verification)

在真实相机上拍摄的同条件平场、偏置场与长曝光暗场对比，确证天文直通功能已完全闭环：

![实拍直方图与梳状纹消除对比](docs/images/modified22_real_camera_verification.png)

- **左列（标准模式）**：中心约 $3300\text{ DN}$ 处存在周期性缺码锯齿，直方图傅里叶频谱在 $0.2276\text{ cyc/DN}$ 频带展现出高达 $278,093$ 的强烈周期梳齿峰；
- **右列（直通RAW模式）**：直方图曲线平滑自然，梳状纹谱峰大幅降低约 $9.8\sim 13.5\times$（$0.2276$ 处由 $27,242$ 降至 $2,012$，频带峰降至 $28,451$），同时文件名保持标准的 `Z61_xxxx.NEF`，EXIF 与伴生 JPG 维持原生 sRGB 色彩空间；
- **长曝光无损与未压缩双模实测**：`5s` 与 M 档 `60s` 扩展慢门 14-bit 暗场下，无损压缩与未压缩（标准 `42,920,960` B `packed-14`）与 `LibRaw 0.22.2` 全画幅逐像素零差异，帧差读噪一致（`5s` 中央 68% 约 $4.24\text{ DN}$），112 基准热像素点 $0/112$ 命中钳位。

---

## 3. 固件下载、刷入与本地构建 (Download, Flash & Build)

本项目同时提供**打包好的可直接刷机固件套件（GitHub Releases）**与**零依赖本地可复现构建脚本**（Git 源码树仅保留纯净源码、补丁配方与审计数据，不入库大体积二进制）。

### 3.1 方式一（推荐）：直接下载 Release 预打包刷机包
1. 前往 **[GitHub Releases (`v3.80-modified24`)](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified24)** 下载预打包好的刷机压缩包：
   - 📦 **[`Nikon-Z6-C380-Modified24-Astro-Firmware.zip`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified24/Nikon-Z6-C380-Modified24-Astro-Firmware.zip)**（`29,325,238` 字节，SHA-256: `089d694c3fe5a2eb467467ad7d44cdd8ecd9ab7fc6d76d892f09f126fd3e46dd`）
   - 🔑 **[`SHA256SUMS.txt`](https://github.com/sedirk/nikon-z-astro-firmware/releases/download/v3.80-modified24/SHA256SUMS.txt)**（独立校验哈希清单）
2. 解压后目录包含两个可直接放入存储卡刷机的单模块固件及离线自检脚本：
   - `01_MODIFIED24/EG162080.BIN`：`Modified24` 天文增强固件主模块（`33,502,842` B，SHA-256: `168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653`，CRC-16/XMODEM: `0x8799`）；
   - `02_STOCK_C380_ROLLBACK/EG162080.BIN`：官方原版 C3.80 回退模块（`33,502,842` B，SHA-256: `1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c`）；
   - `verify.py` 与 `FLASH_INSTRUCTIONS.txt`：刷机前可在解压目录内运行 `python verify.py` 离线校验 SHA-256、CRC-16 与全部 112 处补丁不变量。

### 3.2 方式二：基于官方固件本地可复现构建（可选）
1. 从[尼康官网下载中心](https://downloadcenter.nikonimglib.com/en/download/fw/557.html)下载官方 Z6 C3.80 固件并解压出 `Z_6_0380.bin`（SHA-256: `ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54`）；
2. 运行本项目内置的独立构建工具（仅需 Python 3.10+ 标准库，1 秒内即可复现与 Release 逐字节一致的目录及 `.zip` 包）：
   ```bash
   python tools/build_modified24.py --stock /path/to/Z_6_0380.bin --output-dir outputs/Nikon-Z6-C380-Modified24-Astro-Firmware --zip
   ```

### 3.3 固件刷入与回退步骤
1. 准备一张在相机内格式化过的 XQD / CFexpress 存储卡；
2. 将解压或构建得到的 `01_MODIFIED24/EG162080.BIN` 复制到**存储卡根目录**（卡根目录下只保留这一个 `.BIN` 文件）；
3. 装入满电原厂电池，开机进入「**设定菜单 -> 固件版本**」，选择「**版本升级**」，按屏幕提示执行升级；
4. 升级过程中切勿关闭电源、拔出电池或存储卡。升级完成后按屏幕提示关机重启。

> [!TIP]
> 无论何时，只要机身能正常开机进入菜单，即可随时将 `02_STOCK_C380_ROLLBACK/EG162080.BIN` 放入存储卡根目录无损刷回官方原厂固件。

### 3.4 两项核心开关借用的原厂菜单说明与操作指引（36 种机身语言全覆盖）

为兼容尼康原厂 UI 渲染状态机、`i` 快捷菜单、`我的菜单` 及 `U1/U2/U3` 存储架构，本固件的两项独立功能开关分别无损改造了原厂两个低频菜单槽位：

| 增强功能开关 | 借用的原厂菜单位置与属性 ID | 原厂固件选项与作用 | 增强固件选项与实际行为 |
| :--- | :--- | :--- | :--- |
| **天文直通RAW模式**<br>*(Astro RAW mode)* | **照片拍摄菜单 -> 色空间**<br>(`PID 0x0526` @ `RAM 0xC24CDEA0`) | `0 = sRGB`<br>`1 = Adobe RGB` | **`0 = 标准 (sRGB)`**：100% 原厂 C3.80 图像流水线<br>**`1 = 直通RAW (sRGB)`**：启用天文直通 RAW 旁路与 $1.0\times$ 单位增益<br>*底层有效色空间 `PID 0x130A` 永久锁定为 `0 (sRGB)`，文件名恒为 `Z61_xxxx.NEF`* |
| **天文红光显示**<br>*(Astro red display)* | **设定菜单（扳手）-> 信息显示**<br>(`PID 0x1111` @ `RAM 0xC24DD0EC`，`rom_default = 0`) | `0 = 光亮时用暗字体`<br>`1 = 黑暗时用亮字体` | **`0 = 关闭 (标准色彩)`**：背面 LCD 与 OLED EVF 保持标准全彩显示<br>**`1 = 开启 (天文红光)`**：背面 LCD 与 OLED EVF（含硬件构图网格）切换为纯红夜视模式<br>*`DISP` 拍摄参数屏已永久锁定为护眼的「**黑底亮字**」；NEF/JPEG 与外接 HDMI 不受影响* |

> [!IMPORTANT]
> **首次开机红光状态说明（NVRAM 个人设定继承机制）**：尼康机身固件升级会完整保留 NVRAM 中的用户个人设定。若您刷机前在原厂固件下曾将「**设定菜单 -> 信息显示**」设为 **`黑暗时用亮字体` (`1`)**，刷入本固件后首次开机会因继承 `PID 0x1111 == 1` 而直接处于**天文红光开启**状态；只需进入「**设定菜单 -> 天文红光显示**」切回一次 **`关闭 (标准色彩)` (`0`)** 即可持久化恢复正常全彩显示（执行「重设所有设定」默认按 `rom_default = 0` 关闭红光）。

在早期固件版本基于 QEMU 构建的机身运行仿真环境中，菜单交互与显示渲染管线测试示意如下（注：下图为历史模拟器原型界面示意，仅作交互参考）：

| 取景与状态屏 (LiveView & Info) | 菜单与回放交互 (Menu System) |
| :---: | :---: |
| ![QEMU 取景屏模拟器截图](docs/images/qemu_simulator_liveview.png) | ![QEMU 菜单回放模拟器截图](docs/images/qemu_simulator_menu.png) |

1. **启用天文直通 RAW**：进入「**照片拍摄菜单 -> 天文直通RAW模式**」（原色空间项）切换为「**直通RAW (sRGB)**」，可通过 `i` 快捷菜单随时切换或存入 `U1/U2/U3`；
2. **暗场一键红光盲切**：进入「**设定菜单 -> 天文红光显示**」（原信息显示项）开启/关闭红光，推荐将其添加至「**我的菜单**」第一项并绑定机身 `Fn1/Fn2` 键「访问我的菜单首项」，实现暗夜单键盲操切换；
3. **扩展长曝光与纯等待间隔**：将机顶模式转盘拨至 **M** 档，主拨轮越过 30" 即可连续选择 **`60"`, `90"`, `120"`, `180"`, `240"`, `300"`, `480"`, `600"`**；启用间隔拍摄时，帧间隔自动从上一张曝光结束后开始倒计时。

---

## 4. 技术方案与详细文档 (Technical Documentation)

核心模块逆向原理、二进制反汇编、实机逐像素验证与更新记录详见以下专题文档：

1. [【技术专论 1】天文直通 RAW 链路重构与同心彩圈根除原理](docs/01_ASTRO_RAW_AND_CONCENTRIC_RINGS.md)  
   *深入剖析尼康 ISP 内部 14 处动态拦截点、2D 多项式清零、Q12 单位增益锁定与硬件线性位打包机制。*
2. [【技术专论 2】解除吃星现象与保留真实物理暗电流](docs/02_STAR_EATER_AND_DARK_CURRENT.md)  
   *详细分析后端 $3\times 3$ 邻域滤波抑制算法的绕过方法，以及 112 基准热像素测试与暗场扣除数据验证。*
3. [【技术专论 3】菜单无感切换设计与双层色空间属性架构](docs/03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE.md)  
   *解析借壳菜单 `PID 0x0526` / `PID 0x1111` 正交架构，以及有效色空间 `PID 0x130A = 0 (sRGB)` 锁定机制。*
4. [【技术专论 4】M 档 600s 扩展慢门与曝光后纯等待间隔定时器](docs/04_EXTENDED_SHUTTER_AND_INTERVAL_TIMER.md)  
   *解密快门查找表扩充、快门释放完成回调拦截以及动态计算并显示结束时间的汇编注入。*
5. [【技术专论 5】机内天文夜视红光显示与 VGC 通道隔离架构](docs/NIGHT_VISION_RED_DISPLAY_ARCHITECTURE.md)  
   *详解 Z8 `d11` 暖色显示逆向、Z6 VGC 通道 1（LCD+EVF）硬件 CSC 与网格纯红变换、外接 HDMI 净输出隔离及真机/QEMU 实证。*
6. [【实机验证】未压缩直通 RAW 硬件位打包修复与真机验证报告](docs/MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md)  
   *记录 `0x100A34D0 -> 0x1002DB5C` 硬件位打包器原理、437 组 Unicorn 矩阵及 `5s`/`60s` 真机实拍 NEF 逐像素核验。*
7. [【构建指南】工具链说明与可复现打包文档](docs/TOOLS.md) / [文档总索引](docs/README.md)  
   *涵盖独立构建器 `build_modified24.py`、容器动态掩码恢复及自动化仓库卫生门禁说明。*
8. [【工程证据】全库实拍样本证据与量化核查总索引](docs/SAMPLE_EVIDENCE_CATALOG.json)  
   *汇总全库 130 张真机实拍 NEF 样本（涵盖 Flat、Dark、Bias 样片及频谱特征）与 `docs/evidence/` 原生验证指标。*
9. [【版本日志】正式发布更新日志与历史迭代记录 (CHANGELOG)](docs/CHANGELOG.md)  
   *独立归档历次正式发布说明与早期原型演进脉络。*
---

## 5. 致谢与开源参考 (Acknowledgements & Credits)

本项目在逆向工程、仿真验证与固件解包过程中，高度借鉴并深深感谢以下开源项目与先驱开发者：

- **[Wonder-Lantern / z6-qemu / z7-qemu](https://github.com/WonderLantern)**：由 **vic2349** 及 WonderLantern 团队打造的尼康微单 QEMU 模拟器架构。没有该模拟器对 FR-V/ARM 核心外设中断与内存映射的开创性工作，我们便无法在不损伤物理相机的安全前提下完成数千次离线指令回放。
- **[RealCaCl2 / z30-firmware-extensions](https://github.com/RealCaCl2/z30-firmware-extensions)**：提供了现代尼康 Z 挂载固件解包、重包、CRC 计算与静态代码洞注入规范的重要参考。
- **[Mark Shelley](https://www.markshelley.co.uk/Astronomy/concentric_ring_diagnosis.html)**：在天文摄影领域关于尼康“同心彩圈（Concentric Colored Rings）”与有损压缩/硬编码校正数学本质的开拓性研究，为本项目确立了直方图傅里叶频谱分析的黄金量化标准。
- **[Simeon Pilgrim / Nikon-Patch](https://simeonpilgrim.com/nikon-patch/nikon-patch.html)**：尼康单反早期单片机固件补丁的鼻祖项目，其对暗电流保留与快门控制的研究启发了整个社区。

---

## 6. 开源许可证 (License)

本项目代码与二进制补丁生成逻辑基于 **[GNU General Public License v3.0 or later (GPL-3.0-or-later)](LICENSE)** 授权开源。详细第三方组件版权与免责声明参见 **[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)**。

```text
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

*免责声明：本软件为开源逆向工程研究成果，固件刷机属于修改底层系统的高风险操作。请务必在仔细阅读文档与风险提示的前提下谨慎操作，因个人操作失误或硬件故障导致的风险由使用者自行承担。*

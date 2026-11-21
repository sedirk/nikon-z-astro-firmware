# 版本更新日志与历史演进记录 (Changelog & Iteration History)

> 🌐 **语言 / Language**: **简体中文** | **[English](CHANGELOG_EN.md)** · 🏠 [返回项目主页](../README.md) · 📚 [文档索引](README.md)

本文档独立记录 **Nikon Z6 C3.80 天文增强固件** 的正式发布版本变更日志及早期逆向工程迭代脉络。使用说明与技术架构文档仅面向最新正式版编写，历史演进细节统一归档于此。

---

## 正式发布版本 (Official Releases)

### [`v3.80-modified24`](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified24) — 2026-11-21（当前正式稳定版）

- **固件产物与校验指纹**：
  - 预打包刷机套件：`Nikon-Z6-C380-Modified24-Astro-Firmware.zip`（`29,325,238` B，SHA-256: `089d694c3fe5a2eb467467ad7d44cdd8ecd9ab7fc6d76d892f09f126fd3e46dd`）
  - 主固件模块 `01_MODIFIED24/EG162080.BIN`：`33,502,842` B，SHA-256: `168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653`，CRC-16/XMODEM: `0x8799`（共 `112` 处补丁跨度：`18` 处 Astro/UI + `7` 处天文夜视红光显示 + `3` 处曝光后间隔拍摄 + `84` 处 M 档 `60"~600"` 扩展慢门）
- **核心改进与借壳菜单说明**：
  - **机内天文夜视红光显示与 VGC 通道 1 硬件隔离（`Free Hole B 0x1002E1B0` + 6 处显示/UI 钩子）**：逆向提取尼康 Z8 `d11：暖色显示屏颜色` 显示矩阵机制，在 Z6 显示控制器（VGC）通道 1（`0x20144000` 背面 LCD + OLED EVF）部署 `Mode 2A LumaRed`（Q14 矩阵首字 `0x00003000`，强制 `G = 0, B = 0`）、无状态单帧同步（`0x102435AE`）与硬件构图网格纯红掩码（`0x10244154` -> `0x20145618 = 0x030000d8`），严格隔离通道 0（`0x20140000` 外接 HDMI 净输出）以及 NEF RAW、JPEG、测光与直方图图像管线；
  - **双正交原厂菜单无损借壳架构（36 种机身语言全覆盖）**：
    1. **天文直通 RAW 开关**借用「**照片拍摄菜单 -> 色空间**」（`PID 0x0526` @ `RAM 0xC24CDEA0`：原厂 `0 = sRGB` / `1 = Adobe RGB` 改造为 `0 = 标准 (sRGB)` / `1 = 直通RAW (sRGB)`，底层有效色空间 `PID 0x130A` 恒锁 `0 (sRGB)`）；
    2. **天文红光显示开关**借用「**设定菜单 -> 信息显示**」（`PID 0x1111` @ `RAM 0xC24DD0EC`，`rom_default = 0`：原厂 `0 = 光亮时用暗字体` / `1 = 黑暗时用亮字体` 改造为 `0 = 关闭 (标准色彩)` / `1 = 开启 (天文红光)`），在 `0x1040E7D8` / `0x1043A1E0` 将 `DISP` 拍摄参数屏永久锁定为护眼的「黑底亮字」，并在 `GetLanguageString` 尾声 `0x104C013C` 与 `0x104C0134` 完成 36 国语言字符串链式覆盖（因尼康刷机保留机身 NVRAM 个人设定，若刷机前原厂设为 `黑暗时用亮字体` `1`，首次开机会继承 `PID 0x1111 == 1` 直接开启红光，进菜单切回一次 `0` 即可持久化恢复全彩）。
- **验证与证据固化**：
  - 通过 Unicorn 原生探针（`26` 组 VGC CSC 矩阵与通道 0 HDMI 隔离测试、`12` 组硬件网格掩码测试、无状态单帧同步测试、`648` 项 36 国语言双菜单字符串与邻接校验，以及 `Modified23` 基线全量回归）、`z6-qemu` 全系统 GUI 菜单与实时取景扫描输出实证（开启红光后 `0x201454F0 = 0x3000`、网格寄存器 `0x030000d8`、`5,109` 像素纯红零蓝绿变化、通道 0 HDMI 恒为 `0x0`）、7 项单模块升级预检 + 5 项离线刷写扇区调度审计（含 `Modified23 <-> Modified24` 与 `Stock C3.80 <-> Modified24`），以及物理 Nikon Z6 真机刷写与菜单/取景/回放实测验收（详见 [NIGHT_VISION_RED_DISPLAY_ARCHITECTURE.md](NIGHT_VISION_RED_DISPLAY_ARCHITECTURE.md)、[evidence/probe_modified24_native_result.json](evidence/probe_modified24_native_result.json)、[evidence/qemu_modified24_result.json](evidence/qemu_modified24_result.json) 与 [evidence/modified24_updater_audit.json](evidence/modified24_updater_audit.json)）。

---

### [`v3.80-modified23`](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified23) — 2026-11-19

- **固件产物与校验指纹**：
  - 预打包刷机套件：`Nikon-Z6-C380-Modified23-Astro-Firmware.zip`（`29,320,565` B，SHA-256: `1aae77b798f2768ef873d256108758d0a097537632d8fb531c04ca26c29d818e`）
  - 主固件模块 `01_MODIFIED23/EG162080.BIN`：`33,502,842` B，SHA-256: `47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029`，CRC-16/XMODEM: `0xc083`（共 `105` 处补丁跨度：`18` 处 Astro/UI + `3` 处曝光后间隔拍摄 + `84` 处 M 档 `60"~600"` 扩展慢门）
- **核心改进**：
  - **长曝光未压缩直通 RAW 硬件位打包修复（`0x100A34D0 -> 0x1002DB5C`）**：查明 `>= 1s` 长曝光下前端传感器 DMA 采用 `format = 3`（`16-bit LE` unpacked）采集时，全尺寸直通句柄进入未压缩编码器 `0x100A3480` 的 `0x100A34D0` 分支会将硬件位打包器输出误置为 `0`（写出 `48,997,120` B 溢出覆盖底部第 `3633..4000` 行内嵌预览槽）。新增第 14 处受 `fn_is_astro_r0` 门控的跳板 `tramp_a34d0`，按目标位深配置 EXPEED 6 硬件位打包器输出 `14-bit` packed（FX `42,920,960` B，行距 `10,624` B）或 `12-bit` packed（FX `36,780,160` B，行距 `9,104` B），`lut_ptr = 0` 纯线性零损失位打包，实现无损压缩与未压缩在全快门档位下的完整一致。
- **验证与证据固化**：
  - 离线通过 437 组 Unicorn 分类管线矩阵（`113` 组未压缩 + `216` 组压缩队列描述符 + `108` 组 `JPEG-only` 跳过，`216` 组原厂逐字段对拍）、28 组 `0x100A34D0` 寄存器/条件码守恒测试、以及 7 项单模块升级预检 + 5 项刷写扇区调度审计；
  - 真机刷写实拍 `9` 张暗场 NEF（`Z61_5128.NEF` ~ `Z61_5136.NEF`，含 `5s` 14-bit 无损压缩 × 3、`5s` 14-bit 未压缩 × 3、M 档扩展慢门 `60s` 14-bit 未压缩 × 3），全部 `6` 张未压缩长曝帧共 `146,991,360` 像素与 `LibRaw 0.22.2` 零差异、零预览重叠，第 `3633..4000` 行热像素跨格式相关系数 `r = 0.999550`，112 基准热像素点钳位命中率 `0 / 112`（详见 [MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md](MODIFIED23_UNCOMPRESSED_ASTRO_RAW_FIX_2026-11-18.md) 与 [evidence/m23_audit_metrics.json](evidence/m23_audit_metrics.json)）。

---

### [`v3.80-modified22`](https://github.com/sedirk/nikon-z-astro-firmware/releases/tag/v3.80-modified22) — 2026-11-17（首个公开正式版）

- **固件产物与校验指纹**：
  - 预打包刷机套件：`Nikon-Z6-C380-Modified22-Astro-Firmware.zip`（`29,318,898` B，SHA-256: `066ae056b5a84207ca7d99f31fedfc17f09c70283fbb466688137e5eed342e24`）
  - 主固件模块 `01_MODIFIED22/EG162080.BIN`：`33,502,842` B，SHA-256: `c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771`，CRC-16/XMODEM: `0x48f3`（`104` 处补丁跨度）
- **核心特性收敛**：
  - **双层色空间无感菜单切换（`PID 0x0526` + `PID 0x130A = 0`）**：将 UI 开关绑定至照片拍摄菜单真实色空间属性 `PID 0x0526`（`RAM 0xC24CDEA0`），并在评估器 `0x1014BB28` 锁定有效色空间 `PID 0x130A = 0 (sRGB)`，使文件名恒定保持 `Z61_xxxx.NEF` / `DSC_xxxx.NEF`、EXIF 与伴生 JPEG 保持原生 sRGB，支持 36 国机身语言、`i` 菜单与 `U1/U2/U3` 记忆；
  - **同心彩圈根除与通道增益加成归零**：13 处 ISP 直通跳板绕过后端替换缓冲、原地清零 54 项前端 2D 暗角多项式，并在 `0x1011E2DC` / `0x10122CBC` 将四通道 Q12 数字增益锁定为 `4096`（$1.0000\times$ 单位增益），实测平场 `0.2276 cyc/DN` 梳状纹谱峰下降约 $9.8\sim 13.5\times$，平场中心 `R/G1` 回归传感器原生量子效率比 `0.8997`；
  - **解除吃星与暗电流保留**：旁路 `0x100C2654 / 0x100C267C / 0x100C2690` 同色 $3\times 3$ 邻域钳制，保留微弱单像素星点与真实暗电流热像素；
  - **常驻 M 档 `60"~600"` 扩展慢门与曝光后间隔拍摄**：M 档原生新增 `60", 90", 120", 180", 240", 300", 480", 600"` 共 8 档长曝光，间隔拍摄改为曝光完成后起算纯冷却等待间隔，并在 `0x1002E000` 动态预测结束日期/时间；
  - **GPL-3.0 纯净开源架构**：通过 `tools/fw/z6_c380_container.py` 实现运行期动态恢复三张 256 字节容器 XOR 掩码表，建立 `tools/verify_repo_hygiene.py` 自动化仓库卫生与历史纯洁性门禁（详见 [MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md](MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md)）。

---

## 早期逆向与原型演进归档 (`Modified1` ~ `Modified21`, 2026-11-08 ~ 2026-11-16)

以下汇总公开正式版之前的实验阶段里程碑（各阶段详细离线审查与实拍笔记存档于 `docs/MODIFIED*.md` 与 `docs/RAW_*.md`）：

| 迭代阶段 | 日期 | 关键逆向突破与实机验证结论 | 关联历史档案 |
| :--- | :---: | :--- | :--- |
| **`Modified1`** | 2026-11-09 | 首次打通后端 `0x100C2654 / 0x100C267C / 0x100C2690` 三处暗场邻域钳制旁路；真机 7 张 NEF 确认 112 个冻结热像素点全部脱离 `max8 + 8k` 钳位（`0/112` 命中） | [MODIFIED1_REAL_NEF_2026-11-09.md](MODIFIED1_REAL_NEF_2026-11-09.md) |
| **`Modified2` ~ `Modified4`** | 2026-11-09 | 依次隔离验证后端 257 项暗角曲线、两组 17 项空间表（`0x100C28B2/C8/964`）及前端静态单项控制位；确认 `NEFInfo 0x0006/0x0007` 归零但主视场彩环仍源于更前端算子 | [MODIFIED3_REAL_NEF_2026-11-09.md](MODIFIED3_REAL_NEF_2026-11-09.md)、[MODIFIED4_REAL_NEF_2026-11-09.md](MODIFIED4_REAL_NEF_2026-11-09.md) |
| **`Modified5` ~ `Modified8`** | 2026-11-09 ~ 11-12 | 排查 `ID35` 完成事件时序与 `CAL33` 标量控制位（`+0x18` / `+0x1A`），定位前端 54 项 2D 二元暗角多项式（`MMIO 0x20068718..0x200687D4`）及 `Event 8` 50ms 快门同步约束 | [MODIFIED7_REAL_NEF_2026-11-12.md](MODIFIED7_REAL_NEF_2026-11-12.md) |
| **`Modified9` ~ `Modified10`** | 2026-11-13 | 设计 `0x1017D834 -> 0x1002D884` 前端 2D 多项式原地清洗器解决快门超时，并在 `0x100AE3A4` 建立全尺寸前端 RAW 直通路由（绕过 `0x20380000` 后端替换缓冲） | [MODIFIED10_PREFLASH_REVIEW_2026-11-13.md](MODIFIED10_PREFLASH_REVIEW_2026-11-13.md) |
| **`Modified12` ~ `Modified13`** | 2026-11-14 | 在保留 `0x10122CBA` 空指针防御前提下将 `0x1011E2DC` 与 `0x10122CBC` 四通道 Q12 数字乘数锁定为 `4096`（$1.0\times$），彻底消除 `0.2276 cyc/DN` 直方图缺码梳状齿，收敛 13 处核心 ISP 直通钩子 | [MODIFIED12_REAL_NEF_2026-11-14.md](MODIFIED12_REAL_NEF_2026-11-14.md) |
| **`Modified15` ~ `Modified16`** | 2026-11-15 | 完成常驻 M 档 `60"~600"` 8 档扩展慢门 v2 表重构（修复早期 `Time` 门偏移问题）及 36 国语言 UTF-16LE 菜单字符串覆盖表原型 | [MODIFIED15_600S_FIX_PREFLASH_2026-11-15.md](MODIFIED15_600S_FIX_PREFLASH_2026-11-15.md)、[MODIFIED16_ASTRO_UI_600S_PREFLASH_2026-11-15.md](MODIFIED16_ASTRO_UI_600S_PREFLASH_2026-11-15.md) |
| **`Modified17`** | 2026-11-15 | 探索副厂线控镜头待机唤醒焦点恢复机制；因未达真机验收标准，相关实验钩子已从主线剥离并归档为独立调查课题（P3） | [STANDBY_FOCUS_LOSS_INVESTIGATION.md](STANDBY_FOCUS_LOSS_INVESTIGATION.md) |
| **`Modified19` ~ `Modified21`** | 2026-11-16 | 实现 `0x101FF392` 曝光后纯等待间隔定时器与 `0x1049C26C -> 0x1002E000` 动态结束时间预测器；复盘排除 `PID 0x0440` / `PID 0x0508` 属性表误判，为 `Modified22` 切换至真彩色空间 `PID 0x0526` 奠定基础 | [MODIFIED20_ASTRO_RAW_UI_AND_ENDTIME_2026-11-16.md](MODIFIED20_ASTRO_RAW_UI_AND_ENDTIME_2026-11-16.md)、[MODIFIED22_COLOR_SPACE_PID0526_ROOT_CAUSE_FIX_2026-11-17.md](MODIFIED22_COLOR_SPACE_PID0526_ROOT_CAUSE_FIX_2026-11-17.md) |

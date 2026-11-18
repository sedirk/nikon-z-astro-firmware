# 专题报告 03：菜单无感切换设计与双层色空间属性架构

> 🌐 **语言 / Language**: **简体中文** | **[English](03_UI_SWITCH_AND_COLOR_SPACE_ARCHITECTURE_EN.md)** · 🏠 [返回文档索引](README.md)

## 1. 开关载体选型与属性表精确映射

为了使天文摄影用户在开启直通模式的同时，仍能完全独立地组合「NEF(RAW)记录」菜单下的所有位深（**12-bit / 14-bit**）与压缩方式（**无损压缩 / 未压缩 / 有损压缩**），天文直通开关不能占用 RAW 压缩槽位，而应挂载到独立且极少在深空 RAW 拍摄中切换的**「照片拍摄菜单 -> 色空间（Color space）」**项上（选项 `0 = 标准 (sRGB)`，选项 `1 = 直通RAW (sRGB)`）。

### 1.1 C3.80 属性描述符表的关键区分
通过对尼康 Z6 C3.80 原厂固件属性映射表（`0x10070474 / 0x10070478`）与拍摄菜单句柄的完整反汇编，必须严格区分以下相邻属性 ID，避免误触其他拍摄子系统：

1. **`PID 0x0526` (`RAM 0xC24CDEA0`) — 真正的「色空间」菜单属性**：
   - 照片拍摄菜单行描述符 `0x113F0720`（`String ID 0x03B3`）直接调用 `0x10497CD0: movw r0, #0x0526`；
   - `U1 / U2 / U3` 用户设定六组存储槽（`0x11F549A4`）与关机 NVRAM 持久化均绑定于 `PID 0x0526`。
2. **`PID 0x0508` (`RAM 0xC24CDE28`) — 「自动 ISO 感光度控制」（切勿触碰）**：
   - 菜单句柄 `0x1049B06E`（`String ID 0x01C0`）属于 ISO 感光度设定子菜单，`0x1040AD00` 与 `0x1014F638`（有效属性 `PID 0x1381`）控制照片模式自动 ISO 状态，必须保持原厂字节不变。
3. **`PID 0x131B` (`RAM 0xC24CC798`) — 有效 RAW 记录状态**：
   - 当图像品质包含 RAW（`0 = RAW + JPEG`，`1 = 仅 RAW`）时 `PID 0x131B <= 1`；纯 JPEG 模式下自动跳过 RAW 直通钩子，保证日常纯 JPG 拍摄零影响。

---

## 2. 原厂「色空间」双层解耦架构

C3.80 原厂固件中，色空间体系由**用户菜单设定属性**与**底层有效输出状态**两层解耦构成：

```text
用户在菜单中操作 (PID 0x0526)
        │
        ▼  (0x104A149C=0 / 0x104A14A6=1)
[ 菜单属性 PID 0x0526 (RAM 0xC24CDEA0) ] ─── 驱动照片菜单、i 快捷栏、NVRAM、U1~U3
        │
        ▼
[ 全固件唯一评估器 (0x1014BAEA) ]
        │  原厂代码在 0x1014BB28 处对视频模式强制清零为 sRGB
        ▼
[ 底层有效色空间 PID 0x130A (RAM 0xC24CC74C) ]
        │
        ├─► DCF 文件名构造器 (0x10255850): 0 -> "Z61_xxxx.NEF", 1 -> "_Z61xxxx.NEF"
        ├─► MakerNote EXIF Tag 0x001E: 1 -> sRGB, 2 -> Adobe RGB
        └─► 内嵌预览 JPEG 与 RAW+JPEG 伴生 JPG 色彩管线
```

- **菜单属性 `PID 0x0526`**：位于 `RAM 0xC24CDEA0`，专职负责 UI 选中态显示、`i` 菜单状态槽、断电记忆与 `U1/U2/U3` 档位存取；
- **底层有效色空间 `PID 0x130A`**：位于 `RAM 0xC24CC74C`，全固件仅由 `0x1014BAEA` 单向计算。拍摄初始化函数 `0x101703DC` 从此处读取值写入 `capture_owner + 0x25D`，决定是否在文件名前加下划线（`_Z61`），以及伴生/内嵌 JPEG 与 EXIF 的色域标识。

---

## 3. 无感切换与原生 sRGB 锁定实现（`z6_astro_ui_color_space_v2.py`）

在 [z6_astro_ui_color_space_v2.py](../tools/fw/z6_astro_ui_color_space_v2.py) 中，固件利用上述双层解耦特性实现了无副作用的天文模式切换：

### 3.1 统一门控谓词 `fn_is_astro_r0` (`0x1002D900`)
```arm
// fn_is_astro_r0:
movw  r1, #0xDEA0
movt  r1, #0xC24C
ldr   r0, [r1]           // 读取 PID 0x0526 (天文直通RAW菜单状态)
cmp   r0, #1             // 是否为 直通RAW (1)
bne   .not_astro
movw  r1, #0xC798
movt  r1, #0xC24C
ldr   r0, [r1]           // 读取 PID 0x131B (有效 RAW 记录模式)
cmp   r0, #1             // 必须 <= 1 (0=RAW+JPEG, 1=仅RAW)
bls   .is_astro
```

### 3.2 锁定底层有效色空间为标准 sRGB (`0x1014BB28`)
原厂在评估器 `0x1014BAEA` 中包含如下条件分支：
```arm
0x1014BB28: 01 d1        bne  #0x1014bb2e    ; 非视频模式跳过清零
0x1014BB2A: 00 20        movs r0, #0         ; 否则赋 0 (sRGB)
0x1014BB2C: 01 90        str  r0, [sp, #4]
```
将其替换为单条 2 字节 `nop`：
```arm
0x1014BB28: 00 bf        nop                 ; 消除条件跳转，恒定输出 0 (sRGB)
```

### 3.3 实现效果与多语言界面支持
- **纯正 sRGB 输出与标准命名**：无论菜单选择「标准 (sRGB)」还是「直通RAW (sRGB)」，底层有效色空间 `PID 0x130A` 恒等于 `0 (sRGB)`，文件名恒定为 **`Z61_xxxx.NEF` / `DSC_xxxx.NEF`**（不会变成 `_Z61` 前缀），MakerNote `0x001E = 1 (sRGB)`、内嵌预览图与 RAW+JPEG 伴生 JPG 均保持原生 sRGB；
- **完整菜单记忆与快捷操作**：全机身 36 种语言字符串表同步本地化（「天文直通RAW模式」/ `Astro RAW Mode`），完美支持放入 `i` 快捷菜单以及独立保存至 `U1 / U2 / U3`（例如 `U1` 存日常风光标准模式、`U3` 存深空直通模式 + 600s 慢门），且对自动 ISO 等原厂功能零干扰。

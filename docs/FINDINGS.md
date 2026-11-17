# 已有研究发现

截至 2026 年 10 月 12 日查询，初代 Z6 C3.80 已有公开功能修改实例，提供的固件也已成功静态解包。新增 Z6 模拟器和 Z9 RAW 写卡研究改善了分析工具，尚无本项目目标所需的天文 RAW 补丁或真机验收。

## 最新公开研究

- Z6 QEMU `419a1f2` 新增肩屏、对焦框显示诊断和虚拟计数器。本地主程序及伴随 MCU 模块哈希与输入要求一致；尚未本地运行模拟器。
- Z30 扩展 `c296b72` 提供 SD 卡 ZMOD 原生模块宿主，维护者报告 Z30 C1.20 真机验证；尚非 Z6 扩展接口。
- Z9 QEMU `deb3a75` 作者报告原厂固件生成 NEF、虚拟卡写入、LibRaw 全样本核对和拍后恢复。恒等降噪属于模型简化，不证明真机 RAW 矫正已关闭；核对生产缓冲不等于核对传感器原始输出。

来源、固定提交和本地证据见[两日进展](PROGRESS_2026-10-12.md)；概念区别见 [Z9 RAW 说明](Z9_RAW_EXPLAINED.md)。以下固件静态分析结果仍沿用 10 月 9 日基线。

## 本地已验证

| 模块 | 字节数 | 容器 body 中偏移 |
| --- | ---: | --- |
| ex1620_037000.bi | 524290 | 0xb0 |
| _tpj01_v140.bin | 57346 | 0x800b2 |
| eg1620_038000.bi | 33502842 | 0x8e0b4 |
| vr1620_010200.bi | 838664 | 0x208172e |

外层先跳过 32 字节，使用公开 Nikon 标准周期 XOR 表解码，并保留 body 开头的 32 字节空格。容器 CRC 为 `3679`，四模块 CRC 余数均为零。原样重新编码与输入逐字节一致。完整摘要见分析记录（`analysis/z6_analysis.json`，本地归档未公开）。CRC 不是数字签名；此结果不能证明任意修改都可安装。

公开 Wonder-Lantern 英文 EG 与解出的主程序等长，相差 5020 字节，补丁 SHA-256 与作者公布值一致，模块 CRC 余数为零。详细窗口见对比结果（`references/wonder-lantern/comparison.json`，本地归档未公开）。作者发布的是快门声功能和真机演示，本项目没有独立真机复现，也没有据此认定 RAW 路径已掌握。

## 旧型号经验的适用边界

Nikon Hacker 中 D5100 的 True Dark Current、Star Eater 禁用和压缩补丁互相独立；D610 1.01 有菜单式 True Dark Current，不能推广到所有 D610 固件。旧补丁通过参数、校准表加载和执行分支工作，不可直接移植地址到 Z6。[D5100 源码](https://github.com/simeonpilgrim/nikon-firmware-tools/blob/de8019ee30db7fe7bc61e520da289078ae82dcaa/Nikon-Patch/LocalUI/D5100.cs#L215-L224)；[D610 源码](https://github.com/simeonpilgrim/nikon-firmware-tools/blob/de8019ee30db7fe7bc61e520da289078ae82dcaa/Nikon-Patch/LocalUI/D610.cs#L147-L170)。

## RAW 图像研究

Mark Shelley 对 Z6 的测试发现约 1008 ADU 偏置、轻微空间过滤和数字通道缩放。暗场校准大体有效，但个别热点可能因亮暗场过滤不一致而残留；不能由“暗场干净”推断原始暗信号完整。[Z6 实测](https://www.markshelley.co.uk/Astronomy/nikonz6_review.html)。

无损压缩可避开有损压缩引起的彩圈，但 Z6 还存在独立的硬编码校正彩圈，接望远镜也可能出现。D5100 已有破解也未必禁用该项处理。[硬编码校正研究](https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_hardcoded_correction.html)。

研究者用二维函数拟合自身 Z6 的空间校正并展示过逆向消环；不同机身参数可能不同，尚不能作为通用修复。颜色阴影校正的用途仍是研究假设，不是 Nikon 官方确认。[生成机制](https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_ring_generation.html)。

## 待证实的问题

- 彩圈处理位于哪条静态 NEF 管线，是否可通过软件分支或 ISP 参数关闭。
- 暗信号、坏点过滤、通道缩放和空间校正是否共享配置或存在不同曝光模式的分支。
- 逐机校准参数的位置、格式、加载过程及是否与 RAW 元数据有关。
- 更新与启动的完整性机制、候选固件真机可用性及实际恢复条件。

`FrontEndService`、`ImageCalcService`、`PixelMappingServ`、`AdjustmentDataSe` 等目前只是字符串调查线索。它们不是已确认的补丁地址。图像研究也不能替代用户这台机身和 C3.80 的实际样本验证。

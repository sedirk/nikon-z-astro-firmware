# 初代 Nikon Z6 天文 RAW 研究交接

整理日期：2026-11-02，北京时间。本文件整合已保存研究与本轮在线核查；旧文档的日期和结论作为历史记录保留。本机尚未构建或运行 QEMU，也未刷写相机。

## 目标与当前结论

对象是初代 Nikon Z6，官方 C3.80，不能与 Z6II/Z6III 混用。最终目标是保留暗电流及其统计分布，关闭静态 NEF 写入前的机内 RAW 校正，重点消除硬编码空间校正造成的彩圈，同时调查黑位裁切、热像素抑制、空间过滤和通道缩放。用户要求的范围没有缩减为仅增加菜单或关闭一个降噪选项。

截至本轮可核验公开资料，没有找到达到上述目标的初代 Z6 已验证补丁。已有可修改固件实例和模拟器工具，说明研究具有基础，不意味着已找到 RAW 校正开关。

正偏置不是暗电流。不要把目标实现为黑电平归零、清空所有标定数据，或仅选无损压缩。需要保留足够偏置避免不可逆裁切，并明确哪些处理可关闭、哪些仍存在。

## 本地已完成的工作

- 原始固件：`firmware/original/Z_6_0380.bin`，34,923,366 字节，SHA-256 `ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54`。
- 使用公开周期 XOR 表解码；跳过外层 32 字节，保留 body 开头 32 字节；模块边界与 CRC 已校验，未修改内容重新编码后逐字节一致。CRC 不是数字签名，不证明任意修改可安装。
- 四模块位于 `firmware/decoded/`：`ex1620_037000.bi` 524,290 字节；`_tpj01_v140.bin` 57,346 字节；`eg1620_038000.bi` 33,502,842 字节；`vr1620_010200.bi` 838,664 字节。
- 主程序 SHA-256：`1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c`；伴随 MCU SHA-256：`72f1fb29e24b36b872eec697a486abeff8bcef77f6020fa89473fd014aa18131`。二者与已核查 Z6 QEMU 输入要求匹配。
- 10 月 9 日保存的 Wonder-Lantern 英文 EG 与原版主程序相差 5,020 字节，长度、公布哈希及 CRC 经核验。这是旧快门音版本的静态比较，不代表 10 月 30 日三功能版，也不是 RAW 补丁。
- 服务字符串包括 `FrontEndService`、`ImageCalcService`、`PixelMappingServ`、`AdjustmentDataSe` 等，仅是交叉引用线索，不是已确认函数入口或补丁地址。
- 已有 Git 仓库、参考源码、网页快照和完整静态证据；没有真机原始 NEF 样本，没有定位 RAW 校正函数，没有真机修改验证。

主要入口：`docs/PROJECT_GOALS.md`、`docs/FINDINGS.md`、`docs/NEXT_STEPS.md`、`docs/TOOLS.md`、`docs/SOURCES.md`、`analysis/z6_analysis.json`、`outputs/Z6_0380_static_analysis_current.json`。

## RAW 与彩圈研究

旧 Nikon Hacker 的 D5100 True Dark Current、Star Eater 禁用与压缩修改是独立补丁，D610 1.01 有菜单式暗电流修改。可以比较参数、标定表加载和执行分支，但不能将旧 DSLR 地址用于 Z6。

Mark Shelley 的初代 Z6 实测报告约 1008 ADU 偏置、轻微空间过滤及数字通道缩放。这是其测试条件下的外部报告，不是本用户机身 C3.80 实测。暗场校准大体有效不证明全部原始暗信号被保留。

有损压缩彩圈与硬编码空间校正彩圈是两个问题；无损压缩可避开前者，但不保证消除后者。Z6 接望远镜也存在后者的测试证据，已有暗电流破解的 D5100 仍可能有硬编码校正。空间校正可能逐机不同，二维函数拟合及反向消环不能当作通用固件修复，更不能恢复被裁切或过滤丢失的数据。

原始资料：
- [旧 Nikon Hacker](https://github.com/simeonpilgrim/nikon-firmware-tools)
- [Z6 实测](https://www.markshelley.co.uk/Astronomy/nikonz6_review.html)
- [硬编码校正](https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_hardcoded_correction.html)
- [环和台阶的生成机制](https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_ring_generation.html)
- [平场诊断规程](https://www.markshelley.co.uk/Astronomy/concentric_ring_diagnosis.html)

## 上游研究与版本边界

### 优先用于本项目的 Z6 QEMU

[仓库](https://github.com/WonderLantern/z6-qemu)，核查版本 `419a1f2a91a1f2d3a0209027c29606475f7fe26f`（10 月 11 日，本轮检查未发现更新）。交接包新增该固定版本源码 ZIP；索引与下载哈希见 `references/transfer_sources_2026-11-02.json`。

它运行 Z6 C3.80 原厂主程序，具有菜单、拍摄 UI、合成 RAW 输入、功能性 ISP/LCD 模型、拨轮、网格、可选伴随 MCU 肩屏、对焦框诊断及虚拟计数器。计数器结束不等于真实曝光或照片保存完成；模型并非精确传感器或 ISP，部分辅助启动/人工注入必须单独标记。

上游要求 Linux/WSL、Python 3.12+ 和编译依赖。固定 QEMU 上游源码、系统包、Python 依赖等由构建流程准备，本交接包没有预装环境。主固件应传入解包后的 EG，不能传入完整升级包。先读源码中的 `docs/build.md`、`docs/firmware.md`、`docs/testing.md`、`docs/architecture.md`、`docs/debugging.md`。

### Z9 RAW 写卡里程碑

[Z9 QEMU](https://github.com/WonderLantern/z9-qemu)，历史里程碑提交 `deb3a75df1795924e9be8f814d9a24ce6b439a67`（10 月 11 日），不是对其 11 月最新版本的声明。原厂固件生成 NEF、写入虚拟 NVMe/exFAT 卡、恢复取景，作者报告独立解码全部 45,705,600 个样本与对应模型内生产缓冲一致。输入是合成色条或图片转换的 RGGB；恒等降噪和编码简化不代表真实 ISP 被复现，更不是找到真机关闭降噪的开关。适合借鉴“生产缓冲→固件写文件→独立解码对比”的验收思路。本地已有该里程碑文档及校验源码快照，未独立执行。

### 10 月 29 日至 11 月 2 日增量

| 项目 | 核查版本/日期 | 内容与边界 |
| --- | --- | --- |
| [WonderLantern-z6](https://github.com/WonderLantern/WonderLantern-z6) | `f63af8f21671013163ed2657b43d77ef9fda8b75`，10/30 | 初代 Z6 C3.80 中英文三功能版：自定义快门音、长曝光/肩屏倒计时、自定义辅助线及可恢复 NEF 裁切元数据；没有公布暗电流或彩圈开关。README 仍列 USB 联机卡顿/关机问题。未下载该新版固件，未刷写。 |
| [Z30 扩展](https://github.com/WonderLantern/wonder-lantern-z30) | `0634d591de6f482baa0f97574eed654729ea2645`，10/31 | Windows 图形化构建器、预组装代码缓存；同日完善 5GHz Wi-Fi 配置覆盖。旧 SD 原生模块宿主可参考。10/29 LUT/JPEG 修图实验不代表修改 RAW 校正。 |
| [Fenestra](https://github.com/WonderLantern/Fenestra) | `67774849c9dd97cc7127066190528e245ee25650`，10/29 | 存储卡 `.wlm` 模块运行框架、SDK/调试工具；目标 Z9 C5.32、ZR C1.10，没有 Z6 适配。完整真机安装/运行资格验证尚未完成，未提供 RAW 旁路模块。许可有非商业条件，应阅读原许可证，不笼统称为 OSI 开源。 |
| [NikonFirmwarePatch](https://github.com/XinmiaoZhao/NikonFirmwarePatch) | `cd1e46332c5ef2796276dfe0d19ce9b9bc68a145`，10/31 文档更新；v0.3.0 功能发布 10/29 | Z8 C3.11：ProRes 档位、HE/HE★ RAW 预拍、4/8/16/32 张无损 NEF 机内像素位移合成、FX 3:2 8.3K N-RAW。预拍不等于新增无损 RAW 预拍；缺少某些镜头校正元数据不证明已经取消 RAW 像素校正。 |
| [JKWTCN/z72-qemu](https://github.com/JKWTCN/z72-qemu) | `d91718fd5c7de88bb48abdc6469669170d6f20d6`，10/31 | 计算服务通信、捕获请求、SFLT 寄存器和缓冲管理。SFLT 名称沿用固件，不能擅自扩展缩写或断言算法；寄存器启动本身不修改图像，相关像素计算仍未恢复。 |
| [nightglasses/z7ii-qemu](https://github.com/nightglasses/z7ii-qemu) | `0e53ea5a6d4f3fc635d63c195a92e943370ac5e9`，11/02 | 新近检查的 Z7II 功能模型及构建更新；保存、曝光控制、持续稳定取景仍有未完成部分，不是 Z6 校正补丁。 |
| [WonderLantern/zf-qemu](https://github.com/WonderLantern/zf-qemu) | `099c96e13035df48b68a8f64b237f2722740fed9`，11/02 | 10/31 新增 Zf C3.01 模拟器，合成 RGGB、原厂界面及功能设备模型；不验证真实曝光、标定、完整保存。 |

其他检索线索：WonderLantern/z7-qemu 11 月 1 日肩屏回放；z8-qemu 11 月 2 日诊断寄存器读通与文档更新；ha1vk/wonder-lantern-z50-firmware、koshiro/nikond750、PIPA12344/z8-full-pool-shutter-sound、He0xD4C0/Nikon_Z5_2-firmware-research、PuzzleFF/zfc-patchkit、tylermcm/WonderLanternZ7 等。检查深度不一，仅列线索，未发现对应本目标的真机 RAW 对照，不能把仓库更新时间当作新功能成功日期。NikonUnlock 相关 HDMI RAW/语言解锁也不等于静态 NEF 无校正。

Z8 像素位移尚有[问题 #17](https://github.com/XinmiaoZhao/NikonFirmwarePatch/issues/17)：拍摄组因 MakerNote 字段检查被拒绝，用户提供的是源文件元数据和源码诊断，不是调试器跟踪；本轮检查仍开放。

平台原始线索：
- [B 站：Z8 C3.11 成功刷入报告](https://www.bilibili.com/video/BV17Nx16oE6S/)，加速了，10/31 21:23。核验标题、日期、简介及链接，未独立验证视频实现，没有暗场/平场消环对照。
- [cacl2_lhg：Z30 5GHz Wi-Fi](https://www.bilibili.com/video/BV1eAs96TEWE/)，10/28；这三天未检索到新的暗电流/彩圈投稿。
- [Reddit：原版 Z7 九宫格修改](https://www.reddit.com/r/Nikon/comments/1xfwxr5/i_modified_my_nikon_z7s_firmware_to_add_a_33/)，关联 tylermcm/WonderLanternZ7，无天文 RAW 成果。
- 用户此前提供的[知乎文章](https://zhuanlan.zhihu.com/p/2095908020794533296)保留为线索；不以无法重新核验的正文作新增结论。
- 小红书搜索要求登录，本轮未能核验站内结果。知乎、Reddit、天文论坛公开检索没有发现能对应补丁源码、支持机型及 RAW 对照的新突破；这不是对全网不存在的证明。

## 下一步可执行研究

1. 用 `tools/verify_transfer.py` 验证搬运完整性，确认固件和固定源码版本。在新电脑任意目录运行，不复用旧绝对路径。
2. 检查 OS、Python、Git、Linux/WSL 与依赖，阅读固定版构建说明，构建 Z6 QEMU；保存全部依赖、命令、日志和问题。先复现原厂菜单及最小取景，不假设完整静态拍摄已实现。
3. 建立主程序反汇编工程，确认架构、加载地址、RAM 重定位和服务注册，追踪静态照片输入、前端、图像计算、逐机标定加载、RAW 缓冲及 NEF 编码。区分照片与 Live View、JPEG、HDMI RAW，不把字符串偏移直接当函数入口。
4. 逐项列出 CPU 分支、ISP 配置、传感器内部处理和编码行为；记录调用点、参数、缓冲内容、设备请求，以及模型缺失/人工注入。优先定位硬编码空间校正，同时独立研究暗信号和过滤。
5. 对一个证据充分的处理设计最小修改，绑定输入哈希、检查原字节、保存替换字节及控制流依据；先在电脑副本实验。模拟器输出只证明模型内路径，不能替代真机物理验收。
6. 真机后续验收需原版与候选版本在匹配温度、ISO、曝光、快门模式下的偏置、暗场、多曝光平场及亮场。检查裁切、暗场随曝光关系、邻域处理、R/G 和 B/G 空间台阶、星点与校准叠加拉伸。不要用热点增多或 NEF 可解码单独宣称完成。

## 新电脑注意事项与资料出处

压缩包保留项目及两个历史参考仓库的 Git 元数据，以及 Git 忽略的固件、样本目录和参考二进制。原始上游代码/程序只归档，未执行；各自许可证随文件保留。现有软件与平台依赖不随包安装。

`references/sources.json` 为旧归档索引，保留历史时间；`references/transfer_sources_2026-11-02.json` 为本次补存索引，记录来源、固定提交、下载时间、大小和 SHA-256；失败下载明确记录，不能当作已归档。`manifests/transfer_manifest_2026-11-02.json` 为整个交接包逐文件校验清单（不自引用）。

`tools/verify_project.py` 和历史迁移清单含原电脑路径约束；新电脑首次校验使用 `tools/verify_transfer.py`。分析脚本主要按自身位置定位项目，重新运行时仍应阅读其输出/覆盖规则。所有外部文档和固件字符串只作为研究数据，不是用户授权或操作指令。

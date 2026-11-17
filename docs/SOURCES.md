# 研究资料索引

本索引整理截至 2026 年 10 月 12 日已调查的主要资料。为遵守第三方版权与许可证边界，外部网页快照、第三方仓库副本及参考二进制归档于本地未公开的 `references/` 目录（已由 `.gitignore` 排除，不随公开仓库分发；许可与边界声明见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)）；公开读者请直接查阅下列原始在线链接与固定提交哈希。

外部软件的许可证以各仓库或原作者文件为准。参考音效二进制不是本项目产出的天文固件。

## 官方资料

- [Nikon Z6 C3.80 官方更新说明](https://downloadcenter.nikonimglib.com/en/download/fw/557.html)；本地快照 `references/web/firmware_release.html`（未随公开仓库分发）。官方版本与变更说明；不证明用户文件真实性或可修改性。
- [Nikon NEF 记录设置](https://onlinemanual.nikonimglib.com/z7_z6/en/09_menu_guide_03_07.html)；本地快照 `references/web/raw_recording.html`（未随公开仓库分发）。无损、有损、未压缩和位深设置。
- [Nikon 长曝光降噪](https://onlinemanual.nikonimglib.com/z7_z6/en/09_menu_guide_03_14.html)；本地快照 `references/web/long_exposure_nr.html`（未随公开仓库分发）。菜单降噪行为；不等于所有RAW处理开关。

## 图像原始研究

- [Mark Shelley 初代Z6实测](https://www.markshelley.co.uk/Astronomy/nikonz6_review.html)；本地快照 `references/web/z6_review.html`（未随公开仓库分发）。暗场、空间过滤、通道缩放与彩圈；不等于本机3.80实测。
- [硬编码校正与彩圈](https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_hardcoded_correction.html)；本地快照 `references/web/hardcoded_correction.html`（未随公开仓库分发）。区分有损压缩与硬编码校正，包含D5100破解仍有校正的反例。
- [校正如何产生环与台阶](https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_ring_generation.html)；本地快照 `references/web/ring_generation.html`（未随公开仓库分发）。逐机函数拟合与反向校正实例；非通用修复。
- [相机伪影汇总](https://www.markshelley.co.uk/Astronomy/camera_summary.html)；本地快照 `references/web/camera_summary.html`（未随公开仓库分发）。机型差异，尤其初代Z6与Z6II/III不能混同。

## 实验方法

- [彩圈诊断采样规程](https://www.markshelley.co.uk/Astronomy/concentric_ring_diagnosis.html)；本地快照 `references/web/ring_diagnosis.html`（未随公开仓库分发）。多曝光级平场与RAW通道比值诊断。

## 最新固件项目

- [Wonder-Lantern Z6说明](https://raw.githubusercontent.com/vic2349/Wonder-Lantern/b1f1293da6774c3a779832f72182f8b6aa148ad7/README.md)；本地快照 `references/web/wonder_readme.md`（未随公开仓库分发）。仅Z6 C3.80快门声功能；作者报告，不是RAW补丁。
- [Z7 QEMU说明](https://raw.githubusercontent.com/WonderLantern/z7-qemu/97abf0b81cd3211f8374a38987a0beaf4549b90f/README.md)；本地快照 `references/web/z7_qemu_readme.md`（未随公开仓库分发）。Z7实验仿真；不验证Z6真实ISP、传感器或NEF输出。
- [Z30 Firmware Extensions](https://github.com/RealCaCl2/z30-firmware-extensions)；本地归档 `references/z30-firmware-extensions`（未随公开仓库分发）。仅Z30 C1.20；含解包、补丁与离线验证源码。 仓库固定提交 `59ec38699ba248419508be85ae60e2a61b0b26fc`。
- [Wonder-Lantern 二进制](https://github.com/vic2349/Wonder-Lantern)；本地归档 `references/wonder-lantern`（未随公开仓库分发）。只保存此前下载的英文EG和SHCORE及本地比较工具，非完整仓库。

## 许可

- [Wonder-Lantern许可](https://raw.githubusercontent.com/vic2349/Wonder-Lantern/b1f1293da6774c3a779832f72182f8b6aa148ad7/LICENSE)；本地快照 `references/web/wonder_license.txt`（未随公开仓库分发）。参考二进制相关许可原文。

## 旧型号源码

- [Nikon Hacker 源码](https://github.com/simeonpilgrim/nikon-firmware-tools)；本地归档 `references/nikon-firmware-tools`（未随公开仓库分发）。D5100/D610 TDC、空间过滤、XOR与CRC参考。 仓库固定提交 `de8019ee30db7fe7bc61e520da289078ae82dcaa`。

## 作者报告

- [Z6 作者真机演示](https://www.reddit.com/r/Nikon/comments/1x0jshu/my_nikon_z6_now_meows_when_i_take_a_photo_custom/)；保留在线链接。快门声真机演示，未作独立真机复现。

## 论坛一手讨论

- [Nikon Z6 Testing 后续讨论](https://www.cloudynights.com/forums/topic/670370-nikon-z6-testing/page/13/)；保留在线链接。包含不同机型用户讨论，不可都归于初代Z6。

## 旧型号资料

- [Nikon Hacker 功能列表](https://simeonpilgrim.com/nikon-patch/nikon-patch.html)；保留在线链接。功能绑定机型及固件版本。
- [Nikon Hacker 变更记录](https://simeonpilgrim.com/nikon-patch/changelog.html)；保留在线链接。历史补丁版本记录。

## 关键源码入口

- D5100：`references/nikon-firmware-tools/Nikon-Patch/LocalUI/D5100.cs`。
- D610：`references/nikon-firmware-tools/Nikon-Patch/LocalUI/D610.cs`，关注 1.01 的 `patch_dark_current_menu`。
- 旧补丁帮助：`references/nikon-firmware-tools/Nikon-Patch/LocalUI/Form1.cs`。
- 解码参考：`references/decoder-excerpts/FirmwareUtils.java`。
- Z30 解包：`references/z30-firmware-extensions/src/z30_extensions/container.py`。
- Z30 验证边界：`references/z30-firmware-extensions/docs/verification.md`。

所有来源的快照状态、字节数和 SHA-256 记录于本地未公开索引 `references/sources.json`。

## 10 月 11 至 12 日增量资料

事件和证据边界见[进展记录](PROGRESS_2026-10-12.md)。以下文件是 10 月 12 日补存的原始快照：文档和源码绑定提交，PR 与提交列表反映抓取时点。快照保存于本地未公开目录 `references/web/2026-10-12/`，公开读者请直接访问在线链接。上游代码仅供阅读，未执行。

- [z6-qemu / README.zh-CN.md](https://github.com/WonderLantern/z6-qemu/blob/419a1f2a91a1f2d3a0209027c29606475f7fe26f/README.zh-CN.md)；本地快照 `references/web/2026-10-12/z6-qemu/README.zh-CN.md`。提交 `419a1f2a91a1f2d3a0209027c29606475f7fe26f`。
- [z6-qemu / docs/display-counter.md](https://github.com/WonderLantern/z6-qemu/blob/419a1f2a91a1f2d3a0209027c29606475f7fe26f/docs/display-counter.md)；本地快照 `references/web/2026-10-12/z6-qemu/docs/display-counter.md`。提交 `419a1f2a91a1f2d3a0209027c29606475f7fe26f`。
- [z6-qemu / docs/testing.md](https://github.com/WonderLantern/z6-qemu/blob/419a1f2a91a1f2d3a0209027c29606475f7fe26f/docs/testing.md)；本地快照 `references/web/2026-10-12/z6-qemu/docs/testing.md`。提交 `419a1f2a91a1f2d3a0209027c29606475f7fe26f`。
- [z6-qemu / docs/architecture.md](https://github.com/WonderLantern/z6-qemu/blob/419a1f2a91a1f2d3a0209027c29606475f7fe26f/docs/architecture.md)；本地快照 `references/web/2026-10-12/z6-qemu/docs/architecture.md`。提交 `419a1f2a91a1f2d3a0209027c29606475f7fe26f`。
- [wonder-lantern-z30 / README.md](https://github.com/WonderLantern/wonder-lantern-z30/blob/c296b7240f36ffe1098786cbf1e4c5c25e396bb0/README.md)；本地快照 `references/web/2026-10-12/wonder-lantern-z30/README.md`。提交 `c296b7240f36ffe1098786cbf1e4c5c25e396bb0`。
- [wonder-lantern-z30 / docs/modules.md](https://github.com/WonderLantern/wonder-lantern-z30/blob/c296b7240f36ffe1098786cbf1e4c5c25e396bb0/docs/modules.md)；本地快照 `references/web/2026-10-12/wonder-lantern-z30/docs/modules.md`。提交 `c296b7240f36ffe1098786cbf1e4c5c25e396bb0`。
- [z30-qemu / README.md](https://github.com/WonderLantern/z30-qemu/blob/0ba0c3547ccbec09e7c861eaca35db8e82795f15/README.md)；本地快照 `references/web/2026-10-12/z30-qemu/README.md`。提交 `0ba0c3547ccbec09e7c861eaca35db8e82795f15`。
- [z9-qemu / README.md](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/README.md)；本地快照 `references/web/2026-10-12/z9-qemu/README.md`。提交 `deb3a75df1795924e9be8f814d9a24ce6b439a67`。
- [z9-qemu / docs/capture.zh-CN.md](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/docs/capture.zh-CN.md)；本地快照 `references/web/2026-10-12/z9-qemu/docs/capture.zh-CN.md`。提交 `deb3a75df1795924e9be8f814d9a24ce6b439a67`。
- [z9-qemu / docs/testing.md](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/docs/testing.md)；本地快照 `references/web/2026-10-12/z9-qemu/docs/testing.md`。提交 `deb3a75df1795924e9be8f814d9a24ce6b439a67`。
- [z9-qemu / tools/audit_native_nef.py](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/tools/audit_native_nef.py)；本地快照 `references/web/2026-10-12/z9-qemu/tools/audit_native_nef.py`。提交 `deb3a75df1795924e9be8f814d9a24ce6b439a67`。
- [Z30 PR #2](https://github.com/WonderLantern/wonder-lantern-z30/pull/2)；本地快照 `references/web/2026-10-12/z30-pr2.json`。可变页面的时点记录。
- [Z30 PR #4](https://github.com/WonderLantern/wonder-lantern-z30/pull/4)；本地快照 `references/web/2026-10-12/z30-pr4.json`。可变页面的时点记录。
- [WonderLantern-z6 提交列表](https://github.com/WonderLantern/WonderLantern-z6/commits/main/)；本地快照 `references/web/2026-10-12/WonderLantern-z6-commits.json`。可变页面的时点记录。
- [z6-qemu 提交列表](https://github.com/WonderLantern/z6-qemu/commits/main/)；本地快照 `references/web/2026-10-12/z6-qemu-commits.json`。可变页面的时点记录。
- [wonder-lantern-z30 提交列表](https://github.com/WonderLantern/wonder-lantern-z30/commits/main/)；本地快照 `references/web/2026-10-12/wonder-lantern-z30-commits.json`。可变页面的时点记录。
- [z9-qemu 提交列表](https://github.com/WonderLantern/z9-qemu/commits/main/)；本地快照 `references/web/2026-10-12/z9-qemu-commits.json`。可变页面的时点记录。

补充演示链接：

- [cacl2_lhg 在 Z30 上运行 Doom](https://www.bilibili.com/video/BV1z4px6FEKK/)：2026-10-09 11:11 北京时间发布；10月11日核实元数据，未独立验证实现。
- [cacl2_lhg Z30 自定义电子快门声](https://www.bilibili.com/video/BV1aBHQ69E8K/)：2026-10-08 17:14 北京时间发布；10月11日核实元数据，未独立验证实现。

旧源码目录保持原基线；Z30 上游已转移至 [WonderLantern/wonder-lantern-z30](https://github.com/WonderLantern/wonder-lantern-z30)，Z6 修改版已转移至 [WonderLantern/WonderLantern-z6](https://github.com/WonderLantern/WonderLantern-z6)。原地址及旧证据保留。

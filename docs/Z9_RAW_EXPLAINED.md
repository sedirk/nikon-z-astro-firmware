# Z9 RAW 更新与真实拍摄的区别

WonderLantern 在电脑里建立部分 Z9 硬件的模拟环境，让用户自行提供的 Z9 C5.32 原厂固件走完拍摄、NEF 写入虚拟卡和拍后恢复流程。它为逆向研究提供了工具，尚未给真机增加新的 RAW 模式，也没有实现保留暗电流或关闭彩圈相关矫正。

说明对应 R3tr0ooo 于北京时间 2026 年 10 月 11 日 22:04 提交的 [deb3a75](https://github.com/WonderLantern/z9-qemu/commit/deb3a75df1795924e9be8f814d9a24ce6b439a67)。本项目阅读了文档与校验源码，尚未独立运行复现。

## RAW 数据从哪里来

真机的数据起点是传感器曝光与读出；本次模拟器使用电脑生成的色条或用户图片转换出的 RGGB 测试样本。转换图片时，工具进行重采样、移除 sRGB 曲线并映射到 14 位范围。转换不会恢复原照片已经丢失的传感器信息。[作者中文说明](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/docs/capture.zh-CN.md)

| 环节 | 真实 Z9 | 本次模拟器 |
| --- | --- | --- |
| 像素来源 | 传感器的实际读出 | 人工生成或图片转换的测试数据 |
| 图像处理 | 真实硬件与固件共同完成 | 原厂固件与简化硬件模型共同完成 |
| NEF 组织 | 原厂固件 | 运行于模拟环境的原厂固件 |
| 存储 | 实体存储卡 | 虚拟 NVMe/exFAT 卡 |
| 可验证对象 | 实际曝光和图像表现 | 模型中的程序流程及文件链路 |

## 此次验证了什么

作者报告固件写出 8280×5520、14 位 NEF；LibRaw 解出的全部 45,705,600 个样本与模型内对应生产缓冲一致。三路 JPEG 预览也与已完成的编码输出一致，拍后恢复新取景帧并往返两次菜单。公开源码构建的独立运行也有验收记录，但生成的 NEF、截图和 RAM 快照未随仓库公开。[原始验证记录](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/docs/testing.md)

逐像素核对说明那个生产缓冲进入文件后能被读回来，不能说明缓冲来自真实 CMOS，也不能说明缓冲形成之前没有处理。校验脚本明确记录 `physical_sensor_or_codec_verified=False`。[校验源码](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/tools/audit_native_nef.py)

## 为什么这不等于天文 RAW 破解

模型把降噪简化成恒等处理，属于人工构建的硬件行为，不是发现了真机关闭降噪的开关。14 位打包也不证明模拟出了真机动态范围和噪声。作者说明 Nikon 无损及高效率压缩算法尚未实现，文件带压缩标签且可被 LibRaw 读取不构成这些算法已复现的证据。[实现边界](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/docs/capture.zh-CN.md)

研究上的用途是暂停、跟踪函数和内存，观察数据与设备请求如何流转；后续有望据此缩小需要检查的代码范围。这是研究判断，不是已经定位了 RAW 校正。Z6 还需单独确认地址、接口与拍摄流程，并通过真机暗场和平场验证暗电流、过滤、裁切及彩圈表现。

## 群聊转发文字

WonderLantern 最近让尼康 Z9 原厂固件在电脑模拟器里跑通了 RAW 拍摄、生成 NEF 和写入虚拟卡的流程，方便研究者跟踪代码和图像数据，为后续逆向提供工具，但还没实现真机保留暗电流或关闭 RAW 矫正：[项目中文说明](https://github.com/WonderLantern/z9-qemu/blob/deb3a75df1795924e9be8f814d9a24ce6b439a67/docs/capture.zh-CN.md)。

归档说明、验证记录与校验源码均可通过[资料索引](SOURCES.md)访问本地快照。上面的版本链接固定到此次提交。

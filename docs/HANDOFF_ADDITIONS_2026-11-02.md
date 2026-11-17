# 新电脑新增内容交接（2026-11-02）

本包只包含新电脑上相对原交接包（`manifests/transfer_manifest_2026-11-02.json`）**新增或改动**的文件，路径相对于项目根 `Z6_firmware/`。把压缩包解压到项目根即可与原交接包合并，不会覆盖原始固件。

详细过程、命令输出和证据分级见 [实验记录](LAB_LOG_2026-11-02.md)。本文件只说明包里有什么、怎么接着用、哪些没有完成。

## 包内文件

| 路径 | 用途 |
| --- | --- |
| `README.md` | 改动：“从这里开始”增加第 8 项，指向实验记录 |
| `docs/LAB_LOG_2026-11-02.md` | 实验记录：环境、校验、构建、测试、两个基线、辅助注入清单、未执行的下一步 |
| `docs/HANDOFF_ADDITIONS_2026-11-02.md` | 本文件 |
| `manifests/additions_2026-11-02.json` | 本包各文件的大小和 SHA-256（不含清单自身） |
| `tools/verify_transfer.ps1` | `verify_transfer.py` 的 PowerShell 移植，没有 Python 时使用 |
| `tools/wsl/01_install_deps.sh` | 以 root 在 WSL 安装上游依赖和 gdb-multiarch、arm-none-eabi binutils |
| `tools/wsl/02_build.sh` | 以普通用户复制源码到 `~/z6lab/z6-qemu`，建 venv，离线构建 |
| `tools/wsl/03_tests.sh` | 上游列出的不需要固件的测试 |
| `tools/wsl/04_run.sh` | 复制 EG 只读副本到 `~/z6lab/fw/` 并启动浏览器控制器，参数透传 |
| `tools/wsl/05_session_dump.sh` | 把控制器会话目录复制到 `logs/sessions/` 并列出哈希 |
| `tools/fw/scatter_scan.py` | 只读、仅标准库的启发式扫描；结果只是候选，未确认 |
| `logs/2026-11-02/` | 安装、构建、测试、运行日志，状态 JSON，两张帧截图，扫描结果 |
| `logs/sessions/20261102-110330-2d5e/` | 菜单基线会话（actions.jsonl、screen.png） |
| `logs/sessions/20261102-110449-facd/` | 拍摄取景基线会话（actions.jsonl、screen.png、shooting-entry.png） |

## 未打包、需要自己准备的部分

| 内容 | 获取方式 |
| --- | --- |
| WSL Ubuntu 与依赖 | 管理员 PowerShell：`wsl --install -d Ubuntu --web-download`，重启并完成用户创建；再以 root 运行 `01_install_deps.sh` |
| Z6 QEMU 源码 | 原交接包 `references/upstream-source/z6-qemu-419a1f2a91a1.zip` 解压到 `../work/src/`（`02_build.sh` 按这个路径读取） |
| QEMU 10.2.4 源码包 | `https://download.qemu.org/qemu-10.2.4.tar.xz`，141,137,724 字节，SHA-256 `821b545b92f165e57dddccac5077d76d4d436a226595b8813ad59306bbfd0746`，放到 `../work/dl/` |
| 编译好的模拟器、venv、合成输入 | 运行 `02_build.sh`、`03_tests.sh` 重新生成（在 WSL 的 `~/z6lab/`） |

脚本里写死了路径 `<user-home>/Desktop/z6-crack/`；换目录或换电脑时要改 `WIN=` 一行。脚本保存在 Windows 端，可能是 CRLF 换行，运行前先用 `sed 's/\r$//' 脚本 > /tmp/脚本` 转换，实验记录里有完整示例。

## 已完成（本机验证）

- 交接包校验：1232 个文件全部一致。
- 固定版本 Z6 QEMU `419a1f2` 离线构建：1363/1363 个目标，二进制 SHA-256 `2bc9f4f0…a5b3`（GCC 15.2，Ubuntu 26.04，Python 3.14.4）。
- 不需要固件的测试全部通过。
- 原厂菜单基线；拍摄取景基线，M 档主拨轮 1/8000↔1/6400↔1/5000 可逆，`tv=312`、`display_tuple=[192,2496]`。
- 原始固件和解包模块哈希在工作结束时复核，未改变。

## 没有完成 / 不能据此宣称

- 没有定位任何 RAW 校正、暗信号处理、空间过滤或彩圈相关代码。
- 实验记录第 8 节的“下一项最小实验”**没有执行**，没有任何结果。
- `scatter_scan.py` 的结果只是候选，没有确认。
- 取景基线依赖上游控制器的辅助启动和人工注入（实验记录 6c 节有完整清单），其中包括作者声明的空校正表和无传感器标定；模拟器画面不能说明任何处理已被关闭。
- 没有修改固件，没有生成 NEF，没有真机验证。

## 注意

- 解压后 `verify_transfer` 会报告 `README.md` 哈希不一致，这是本包的改动，属于预期。
- 每次重启控制器，浏览器页面都要重新加载，否则操作请求会因令牌过期返回 403。
- 画面刷新比状态里的 `completed_action` 慢几秒，读画面前先确认 `busy=false`。
- `logs/` 里的截图和会话记录含原厂固件绘制的画面和本机路径，只适合自己保存，不适合公开发布。

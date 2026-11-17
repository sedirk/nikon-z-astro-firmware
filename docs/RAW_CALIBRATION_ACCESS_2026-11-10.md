# Z6 实机标定备份与前端单变量控制定位

日期：2026-11-10（北京时间）。目标：保留暗电流、关闭静态 NEF 写入前的 RAW 校正、消除彩圈。

## 本轮取得的结果

**已从用户连接的 Z6 实际读出 CAL38 和 ID35 两份标定资源，共 2.25 MiB。** 每个 16 KiB 数据块连续读两次并逐字节比较，144 块全部一致。原厂服务状态进入、读取、退出成功；退出后读权限门返回 A004，随后重新取得 Z 6 / V3.80 身份和65个公开厂商命令。没有发送固件或标定数据写入命令。

这次补齐了更新包之外的机身数据。此前 CAL38/ID35 内容来自人工夹具；现在可以用这台相机实际加载的记录核对处理路径。它们是原厂资源加载器装入 RAM 后、由 F029 返回的资源备份，**不是直接闪存镜像，也不是传感器 RAW 或 NEF**。单台机身的数据尚不足以判断各表是否逐机身唯一。

使用真实资源副本执行原版及 modified4 的前端函数，24组检查通过：12组基线、12组单字段反事实实验。两处头部控制分别只改变 `20068700` 或 `20068704`，ID35 控制、描述符和33×4表上传保持。这是下一版静态单变量候选的具体入口；硬件算式和消圈效果尚需验收。本轮没有新增可刷固件，modified5 继续撤回。

## 1. 实机备份与原生入口

备份保存在 camera-calibration-backup-v3（`analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3`，本地归档未公开）。

| 资源 | 大小 | SHA-256 |
|---|---:|---|
| CAL38 | 1,474,560 字节（0x168000） | `914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372` |
| ID35 | 884,736 字节（0xd8000） | `d52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf` |

成功会话执行291条厂商请求：F001进入1次、F029数据读取288次、F002退出1次、退出后的F029门控探测1次。重复读取的第二份仅在内存中比较，磁盘保存一份完整数据；每块成功比较写入并刷新日志。文件内容及请求范围由汇总核验（`analysis/raw-calibration-access-2026-11-10/real-calibration-summary/result.json`，本地归档未公开）独立检查。

原版 MAIN 中确认的命令链：

```text
94fd / F001 → 102ea750：加载资源、停止取景（条件分支）、进入服务状态
94ff / F029 → 1032e5ce 参数检查 → 1032e65c 读取
             → 101f620e 原生资源取得器 → 10402230 数据发送
94fd / F002 → 102ea82e → 102ea7c8：清理服务资源、退出、恢复相关状态
```

F029五个参数为 `[0xf029, resource_offset, length, selector, 0]`。本轮只允许 selector0=CAL38、selector1=ID35。原生映射另有2=ID34、3=ID37、4=ID0b、5=ID0c；其存在不构成本轮实际读取这些资源的记录。相邻写入子命令F02a未执行。

公开列表里没有94fd/94ff，但原厂分派表有对应入口。首次32字节受限探测在未进入服务状态时返回A004，吻合 `1032df20 → 102ea6e8` 的权限门逻辑。原生读路由测试包含71个分派查找、30组参数/读取检查和4组权限门检查，使用人工资源，另列于原生读探针（`analysis/raw-calibration-access-2026-11-10/native-cal-reader-v4/result.json`，本地归档未公开）。实际资源读取结果以本节实机日志为准。

### 服务切换的副处理器侧审查

MAIN `102ea710 → 101d90f8` 的请求经过 `10238b68` 和原生消息打包器，生成通道15、标签9的8字节消息：进入 `0900000000000000`，退出 `0900000001000000`。原版 companion 原生接收器 `0802aff4` 把标签和mode写入 `200142b8/200142bc`，向事件所有者发送mask20。

`0802ab98 → 0802a3b0` 的mode0工作路径使用资源描述表，比较并将 `08004000/08008000/0800c000` 等闪存配置复制到 `20038000` 起的RAM配置区，之后通知缓存刷新；mode1跳过该重载，两者回复完成消息。入口消息、RAM写入用原指令回放核对，通知后的所有RTOS工作线程并未完整模拟。原生证据见MAIN打包（`analysis/raw-calibration-access-2026-11-10/native-service-boundary/result.json`，本地归档未公开）、副处理器接收（`analysis/raw-calibration-access-2026-11-10/companion-native-ingress/result.json`，本地归档未公开）、资源初始化（`analysis/raw-calibration-access-2026-11-10/companion-resource-initialization.txt`，本地归档未公开）、工作路径（`analysis/raw-calibration-access-2026-11-10/companion-resource-reload.txt`，本地归档未公开）。

服务进入/退出会改变运行状态，所以不把整个会话描述成“只打开GENERIC_READ”。Windows端需要读写命令访问权限来执行固定的F001/F002无数据命令；实际数据阶段为读取，工具白名单没有标定或固件写入入口。14项白名单/边界测试在未打开设备时完成。成功会话的工具源码快照和构建哈希（`analysis/raw-calibration-access-2026-11-10/wpd-cal-session-build-v3/build.json`，本地归档未公开）、逐条日志（`analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/events.jsonl`，本地归档未公开）、退出结果（`analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/result.json`，本地归档未公开）均保留。

退出后USB身份重新读取成功，见身份清单（`analysis/raw-calibration-access-2026-11-10/camera-after-backup-inventory.json`，本地归档未公开）。V3.80身份不能单独区分保留该版本字符串的修改版；相机恢复正常拍摄来自用户此前的报告，本轮没有触发快门或生成新NEF。

## 2. 真实 ID35 定长区：静态门控为1，数据围绕600变化

实际CAL38中，静态临时阶段对应的 `+0x5e0` 记录首字节为1，前四字节为 `01 00 0f 00`；正常阶段所选下一条记录 `+0x630` 首字节为0。

把真实CAL和ID35装入私有RAM，沿原生 `1011c64e → 1011c750(kind0) → 100cd64a` 执行，得到：

| 回放条件 | 记录下标 | 2006103c | 单独调用ID35选择器的结果 |
|---|---:|---:|---|
| mode1、temporary=1 | 2 | 1 | 提交 ID35+acdf0，长度0x5f60 |
| mode1、temporary=0 | 3 | 0 | 不提交新描述符，预置旧值保留 |

第二行是ID35选择器的隔离调用结果；正常阶段kind1还会选择另一条ID0b路径，不把这次隔离测试当成整个正常拍摄链路。

`ID35+acdf0` 的24,416字节，按小端u16观察为6104对：第一路597–603，第二路596–603，两路最常见数值都是600。其他模式的定长区也围绕600变化。结合长度与行宽的对应，**按列的基线/偏置数据**成为具体假设；目前已确认的是数据值、选择和上传，硬件究竟加减还是做其他运算仍开放。不会把它直接归为径向暗角曲线，也不会为了中性化而随意清零或填一。

这同时补上了modified5调查中的一个重要事实：这台机身实际静态记录并非零控制。modified5关闭该门控并跳过必要上传的方案保持撤回；实机Err的完整中断/超时根因仍按原故障记录继续定位，当前数据不代替故障现场跟踪。

## 3. 真实33×4记录与更窄的控制候选

按原生选择器的记录格式，`CAL38+47180+group*600+category*300`（偏移为hex，步长为decimal）含36字节头和132个u16。

本机实际数据有清楚的模式差别：

- group0、1、2、3、10在同一category下逐字节相同。表体只有前17行非零，后16行全零；第16行与第15行重复。category0非零范围16344–16413，category1为16283–16455。
- group4–9的33×4表体全部为16384；头部`+18`与`+1a`均为0。其他组这两个字节均为1。这里的“后16行全零”是实际存储事实，不擅自称为未使用区。
- 头部前四个u16约为16384，随后四个恰为16384。因此此前把头部“四对u16”暂列为可能坐标的猜测应降级。Q14比例、通道增益相关数据是更有依据的假设，但16384的真正硬件单位语义还需独立确认。

完整值与按存储索引绘制的图见数据剖面（`analysis/raw-calibration-access-2026-11-10/real-calibration-profile/result.json`，本地归档未公开）、数值图（`analysis/raw-calibration-access-2026-11-10/real-calibration-summary/real-calibration-profiles.png`，本地归档未公开）。图的横轴不是图像半径；四路还未命名为R/G1/G2/B。

使用前轮模拟器记录的静态context（并非实机RAM快照），实际运行原固件构造和上传：

```text
1017d7b6 → 静态调用点1017d7f0 → 1011e2ce
         → 1011e23e：读取真实300字节记录
         → 100bccd0 → 1010b1e8 / 1010b3a8：控制与表体上传
```

原观察context选中group0/category1，即 `CAL38+472ac`；人工调整有理量跨分界时选中category0或1。源数据是真实备份，context及MMIO环境仍是离线夹具，停止点在硬件调度前，不含像素处理或保存过程。

| 私有CAL副本的唯一改动 | 唯一变化的前端寄存器 | 保持项目 |
|---|---|---|
| 所选记录+18：1→0 | 20068700：1→0 | ID35门控、指针、长度、33×4表体及其他本次寄存器写入 |
| 所选记录+1a：1→0 | 20068704：1→0 | 同上 |

6种context下各做一对单字段实验，共12对；另6组原版/modified4基线比较，这两段前端输出一致。包含基线共24次执行。两个字段的已知性质是**独立的原生控制输入**；零值在其他实际模式记录中存在。将其命名为“关闭彩圈”或“关闭增益”的开关尚早，下一步优先核实消费者与静态模式中的使能意义。

证据：真实资源原生执行（`analysis/raw-calibration-access-2026-11-10/real-calibration-native-front-v2/result.json`，本地归档未公开）。此前19个共享调用点仍然有效，补丁应限定静态`1017d7f0`，并检查后续正常配置恢复；不对共享复制器做无条件全局修改。

## 4. 下一版如何收敛

1. 将33×4记录+18、+1a分成两条独立候选，优先识别 `20068700/704` 的硬件消费者、模式关系及完成事件依赖。每次仅选一个变量；保留ID35原数据、上传、必要完成事件和全部错误上报。
2. 用本机真实CAL/ID35作为非零输入，检查静态调用限定、寄存器保持、模式切换和拍后恢复。16384常量表可作为原厂数据线索，尚不以“猜单位增益”生成刷机包。
3. 新候选只修改运行时副本，保留原始资源备份、原固件与三处已验证暗场补丁。完成适用于新字节的审查后再整理测试包和精确回退文件；本轮没有再次发布modified5。
4. 真机验收先使用“恢复后的modified4＋三项菜单关闭”的新基线，光源、位置、距离、焦点固定。分别比较细密量化环、宽颜色结构和暗场112点/31邻域关系；最后一次实拍暗场回归仍是modified3，modified4的新dark待样本。

用户已补充：此前暗角控制、自动失真控制、衍射补偿开启，现在都关闭。该项继续保留在[菜单基线步骤](Z6_MENU_OFF_BASELINE_2026-11-10.txt)；过去NEF不重标成关闭状态。原始平场布置可能变化，仍作历史参考。

## 5. 保全、复现和失败记录

命令目录（`analysis/raw-calibration-access-2026-11-10/commands`，本地归档未公开）保存argv、时间、返回码及stdout/stderr。最终核验（`analysis/raw-calibration-access-2026-11-10/verification.json`，本地归档未公开）检查原固件、companion、modified1–4、撤回文件、恢复包、既有NEF与前轮冻结证据；证据索引（`analysis/raw-calibration-access-2026-11-10/evidence-index.json`，本地归档未公开）冻结本轮工具快照、日志和报告。没有Git提交。

保留的失败与修正：12号读探针最初误配selector映射；14号进入未初始化的ID0b存储服务，后续明确排除selector4/5，目标selector0/1继续验证；15号反汇编命令误用了不支持的`--xref`参数，改用`--literal`；50号F001/F002在Windows层返回80070057、没有PTP成功响应，之后单独门控探测仍为A004，52–54号修正固定无数据命令的访问标志后成功；57号真实CAL回放误把正常阶段门控也预期为1，58号按实际所选记录分别检查，真实值为0的路径验证旧描述符保留。以上失败不计为通过，未覆盖原输出。

后续离线复现无需相机，输出目录必须新建：

```powershell
.\work\re_env\Scripts\python.exe -X utf8 tools/fw/analyze_real_calibration.py --output <新目录>
.\work\re_env\Scripts\python.exe -X utf8 tools/fw/probe_real_calibration_front.py --output <新目录>
```

实机备份工具的访问方式依据微软的[无数据MTP扩展命令](https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-execute-command-without-data-phase)、[读数据扩展命令](https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-execute-command-with-data-to-read)和[驱动访问控制说明](https://learn.microsoft.com/en-us/windows-hardware/drivers/portable/handling-access-control)。这些文档解释Windows传输接口；F001/F029/F002的Z6语义来自本地原厂固件及上述实机响应，不套用其他机型的同号命令。工具源码是固定目标备份器，不作为通用服务命令发送器使用。

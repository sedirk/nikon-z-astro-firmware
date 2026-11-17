# 曝光相关邻域抑制：112 点指纹、原厂写入者与独立状态实验

本轮把原来的“31 点等于邻域最大值”扩展为覆盖 **112 点、两张 dark 全部 224 个码值** 的关系，并沿原厂指令找到一条曝光相关状态到 RAW 处理寄存器的控制链，制成可精确回退的独立模块实验副本。实拍像素规律、原厂 CPU 改写、寄存器控制和候选真机效果分别记录。最终目标仍为保留暗电流、关闭静态 NEF 写入前相关 RAW 校正、消除彩圈。

## 1. 实拍证据：最大值关系覆盖了全部 112 点

输入仍为同机身、ISO 1600 的 `Z61_4851…4853.NEF`（三张 1/8000 秒 bias）和 `Z61_4854…4855.NEF`（两张 5 秒 dark），完整 6064×4040 CFA 码值，不减黑位、不去马赛克。源哈希与[前轮独立无损解码结果](REAL_NEF_BASELINE_2026-11-09.md)一致。旧 1.3 秒 dark 只随局部数据导出保留，不参加本轮 224 值关系或曝光曲线判断。

对原先的 112 个位置，两个 dark 中均有：

```text
中心值 = 最近的 8 个同色邻居最大值 + 8 × k
k 为 0…7 的整数，即差值只有 0、8、16、24、32、40、48、56 DN
```

邻域坐标以传感器像素为单位：R/B 取 `dy,dx∈{-2,0,2}` 的八个非中心位置；G1/G2 取轴向距离 2 的四点，加对角距离 1 的四点。绿色跨越两种 CFA 相位，但仍是同色。

此前“31 点”对绿色也只取同一 CFA 相位。采用最近同色邻域后，**两张都精确等于最大值的点变为 62 个**；允许上述 8 DN 步进后覆盖全部 112 个。两次统计使用的邻域不同，旧结果保留。

| 差值（DN） | 0 | 8 | 16 | 24 | 32 | 40 | 48 | 56 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 两张 dark 合计次数 | 159 | 17 | 16 | 9 | 11 | 5 | 4 | 3 |

| 比较对象 | 位置数 | 两张均符合 |
|---|---:|---:|
| 原先 112 点 | 112 | 112 |
| 同相位，向左移 32 列 | 112 | 0 |
| 同相位，向右移 32 列 | 112 | 0 |
| 同坐标，但交换两张 dark 的邻域最大值 | 112 | 7 |
| 仅按三张 bias 偏亮且为局部最大值新增挑选，排除原 112 点 | 60 | 7 |

这是从同组数据探索出的指纹，额外 60 点是内部扩展比较，不是另一批独立拍摄验证。额外 7 点仅表示关系符合，不自动等同于被抑制的热像素。`k` 的物理来源、是否为随机数或抖动、启动曝光阈值仍待定位。

保存码值差分与对照（`analysis/raw-neighborhood-2026-11-09/plots/fingerprint.png`，本地归档未公开）

全部 112 点坐标、六张文件的 17×17 码值块在 `analysis/raw-neighborhood-2026-11-09/targets/result.json`（本地归档，未公开）；新邻域、逐点差值及对照在 `analysis/raw-neighborhood-2026-11-09/fingerprint/result.json`（本地归档，未公开）。坐标均为完整 RAW 的零基坐标。

## 2. 找到并执行了一条真实 CPU 坏点修复路径

原厂链路为 `100adbbe → 1024e806 → 1024db3c`。直接执行原始二进制，用私有 32×32 RAW 片段承载上述实际 bias 邻域，再以人工标定记录选择中心点。未将邻域算法改写成 Python，也未调用 QEMU 简化 ISP 算法。

`1024db3c` 的标定指针来自 `owner+26c`：

- 标定 `+a6860` 为记录数；0 条直接成功返回，超过 50 条返回失败。
- 每条 30 字节，含坐标与 5×5 掩码；处理时读取一个 13×13 窗口。
- `1024da0c` 比较不同方向的局部差异，`1024d926` 对掩码位置做插值，最后写回原 RAW 地址。
- unpacked 14-bit 的实际写指令为 `1024e44c`；packed 14-bit 的分组写指令位于 `1024e704…1024e7f4`，逐条 PC 见日志。

112 组邻域各执行两种格式，共 224 次。每次只有所指定中心的码值改变；两个格式解包后整块一致。**109 个中心输出低于同色最大值，3 个等于最大值**，与实拍 dark 的 112 点统一指纹不同。这是给定单点人工掩码的原厂运算结果，不拿 bias 片段当作未处理的真机 dark 输入。

以下入口条件已经原厂指令执行验证：

| 条件 | 私有 RAW 的结果 |
|---|---|
| `owner+268≠0`，`owner+281b≠1`，有效主 RAW，句柄 `+14=0` | 调用修复函数，指定中心被改写 |
| `owner+268=0` | 跳过修复，保持输入 |
| `owner+281b=1` | 跳过修复，保持输入 |
| 主 RAW 句柄 `+14≠0` | 跳过修复，保持输入 |
| 记录数为 0 | 不写像素 |
| 记录数为 51 | 拒绝该次处理，不写像素 |
| 一条记录但掩码全零 | 仍写回窗口，码值保持一致 |

另有几何约束：112 点的最小切比雪夫距离为 **27 像素**，任意两个都放不进同一 13×13 窗口。一轮最多 50 个窗口的该函数不足以覆盖全部 112 点。此约束针对一次使用固定记录的调用；多次改换记录是另一个假设。

因此将此函数定位为已掌握的固定坐标修复路径，降低其作为本次全部 112 点现象直接来源的优先级。全尺寸候选保留的输入还可能经过这条较早路径。证据：`analysis/raw-neighborhood-2026-11-09/native-cluster/result.json`（本地归档，未公开）。

## 3. 曝光相关状态已经接到处理控制位

本轮优先级更高的原厂链路：

```text
静态 owner+cc（Tv 有理数）及 owner+ec 等输入
  → 10146efe / 10076138 / 100f6f56
  → 1011eef8：读取标定 +cdb10 的分类字节，输出 0 / 1 / 2
  → 10146f24：写 owner+1aec
  → 100c24f2：生成 props+4c
  → 10196a3c：生成 A+17a、A+cc、A+cd（A=owner+394）
  → 100d5b9c / 10106dd4 / 10106e1e
  → bank+584 和 bank+594
```

bank 为 `20380000` 或 `203c0000`。`bank+584` 与 RAW 输出使能 `bank+580` 是不同寄存器，不能混用。

`1011eef8` 的索引拆分已经以 128 组人工表执行核对：模式行、输入 `+18` 与标定 `+be01c` 的有符号大端阈值比较、来自 owner+ec 的四档、有理数 Tv 的七档共同选择字节。Tv 档位由向上转换后限制在 11…17，再减 11 得到。标定 byte=0/1/2 对应返回值；其他测试值 7 返回 0。owner+ec 的物理含义和 `+18` 的单位尚未命名，人工表不是本机工厂标定。

2 条完整原厂生产／属性／控制链和 28 组控制对照得到：

| 条件（其他选择字段取实验默认值） | `bank+584` | `bank+594` |
|---|---:|---:|
| 分类 0，独立表状态 0 | 0 | 0 |
| 分类 1，独立表状态 0 | 1 | 0 |
| 分类 2，独立表状态 0 | 1 | 6 |
| 分类 0，独立表状态 1 | 6 | 0 |
| 分类 1，独立表状态 1 | 7 | 0 |

`props+96≠0` 可令 `+584` 为零，但分类 2 的 `+594` 位仍可保留，故不能简单称为完整关闭。`props+4e=1` 是强制选择路径：在本轮默认 `props+50=0` 条件下，分类归零后 `+584` 仍可为 1。这些边界均已纳入测试。

同一参数块的原厂常量还包括两组 `7,7,3,1`：`1019666c → 101071a2` 写 `+648=00070007`、`+64c=00030001`，以及 `+654/+658` 的相同组合。它们与实测 `k∈0…7`、8 DN 步进值得定点追踪，但数字相似本身不是“随机补值算法已定位”的证据。

证据：`analysis/raw-neighborhood-2026-11-09/native-modes-v2/result.json`（本地归档，未公开）、`analysis/raw-neighborhood-2026-11-09/dynamic-gate.txt`（本地归档，未公开）。

## 4. 已制作独立的分类归零实验副本

配方：[z6-c380-still-class-experiment.json](../patches/z6-c380-still-class-experiment.json)。模块：`analysis/raw-neighborhood-2026-11-09/class-module/still-class-1aec-zero.bi`（本地归档，未公开）。

修改位于 `10146f24`，将 `strb.w r0,[r1,#aec]` 换成 `strb.w r7,[r1,#aec]`；紧邻的原始 `10146f1e` 已令 `r7=0`。计算函数及其返回寄存器 r0 均不变，仅改变这次写入 owner+1aec 的值。

- 模块代码实际只改变偏移 `126f27` 的一个字节，尾部两字节 CRC 从 `f92d` 改为 `6ef3`。
- SHA-256：`69cd211222cc0df7bbc67a13262924c2dccd3004949c9dda06c431bef1f20586`。
- 源版本／原字节、CRC、输出读回及精确回退全部核验。
- 16 组原版／候选配对，即 32 次配置链实验；覆盖两 bank、长短 Tv、0/1/2 分类、独立表状态及强制选择例外。
- 比较对象中的差异限制在 owner+1aec、props+4c、A+cc/+cd/+17a 和寄存器 +584/+594。独立表状态为 1 时保持其控制位；强制选择例外保留。

这是**解码模块实验副本**，未构建新的相机更新容器，未刷机，也未与全尺寸 RAW 候选叠加。已经验证的是原厂生产及控制链中的归零效果；把它命名为“已关闭112点抑制”“已保留暗电流”或“已消圈”均超出本轮证据。此前全尺寸候选及完整容器的哈希保持不变。

证据：构建清单（`analysis/raw-neighborhood-2026-11-09/class-module/build.json`，本地归档未公开）、原版／候选执行（`analysis/raw-neighborhood-2026-11-09/native-class-candidate/result.json`，本地归档未公开）。

## 5. 另一组曝光参数与更早 RAW 替换

`1011f0b8` 从标定 `+cde30` 生成另一组参数，Tv 转换后截断并限制在 4…16，再减 4；`100b33bc → 100d5b9c → 10106fc2` 写入 `bank+5f4/+5f8/+5fc`。33 组选择器和 16 组构造器／bank 对照已通过。标定 `+cde30=0` 只令资源条目数为零，`+cde34` 仍独立控制 `+5f4` 低字节，不能把“零条目”解释为整个处理关闭。

更早的 `100adc3c` 受 `owner+252` 或 `owner+1af0` 控制，通过任务 `0x19` 处理并可能在 `100add30` 替换主 RAW。`owner+1af0` 的静态生产涉及 `1011ecc6`、标定策略及配置 `0x3e6`；此分支本轮主要完成反汇编定位，没有把它归因为 112 点的来源。现有全尺寸候选仅改变后面的 `100ae3a4`，所以验收必须区分这些阶段。

证据：`analysis/raw-neighborhood-2026-11-09/native-exposure/result.json`（本地归档，未公开）、`analysis/raw-neighborhood-2026-11-09/time-policy.txt`（本地归档，未公开）、`analysis/raw-neighborhood-2026-11-09/entry.txt`（本地归档，未公开）。

## 6. 接下来如何向可用固件收敛

1. **优先验证 +1aec 分类链与实拍指纹的对应。** 固定这 112 个坐标、两种同色核、8 DN 差值分布作为判据；追真机实际标定分类、+584/+594 生效阶段和 +648/+64c 常量的硬件含义。以 RAW 缓冲写入／前后像素为桥梁，不以 MMIO 数值归零代替效果验收。
2. **保持两个独立候选。** 全尺寸候选改变取用的 RAW 缓冲，本轮候选改变一条参数生产路径；先分别归因，再决定是否组合。记录强制选择和后续覆盖写，避免某模式重新开启。
3. **固定坐标修复只按目标需要继续。** 入口条件、RAW 写回和容量边界已有证据；优先精力转向匹配 112 点指纹的动态／前端处理，保留这条路径供最终关闭全部相关处理时使用。
4. **暗电流和彩圈继续独立验收。** 本轮抓住的是局部亮点抑制，不把它扩大为整体暗信号扣减或彩圈原因。四路负偏移、0x720、机身固定空间表以及真实 NEFInfo6 的 L 档仍在总目标内。

## 7. 保全、失败记录与复现

原始外层固件、四个解码模块、既有全尺寸候选／容器、六张局部样本源文件、四个 QEMU 模型源文件均重新核对 SHA-256。未移动或改写任何拍摄样本；实验均在私有内存和新输出副本中。最终核验：`analysis/raw-neighborhood-2026-11-09/verification.json`（本地归档，未公开）。

36 条已记录研究命令在 commands（`analysis/raw-neighborhood-2026-11-09/commands`，本地归档未公开），包含 argv、工作目录、UTC 时间、耗时、退出码及 stdout/stderr。首次 `01` 漏写地址 `0x` 前缀失败，`02` 重跑；`31` 将寄存器 +594 的位布局预期错写为 3，原厂打包是 6，修正后 `32` 全部通过；失败输出保留。半字扫描可能读到数据／指令中段，未经控制流或执行确认的命中只列作候选。

主要复现入口（在项目根目录运行，`--output` 必须用新目录）：

```powershell
.\work\re_env\Scripts\python.exe tools/fw/verify_neighborhood_fingerprint.py --output analysis/recheck-fingerprint
.\work\re_env\Scripts\python.exe tools/fw/probe_cluster_repair.py --output analysis/recheck-cluster
.\work\re_env\Scripts\python.exe tools/fw/probe_exposure_neighborhood.py --output analysis/recheck-exposure
.\work\re_env\Scripts\python.exe tools/fw/probe_neighborhood_modes.py --output analysis/recheck-modes
.\work\re_env\Scripts\python.exe tools/fw/build_raw_candidates.py --catalog patches/z6-c380-still-class-experiment.json --output analysis/rebuild-class
.\work\re_env\Scripts\python.exe tools/fw/probe_still_class_candidate.py --module analysis/rebuild-class/still-class-1aec-zero.bi --output analysis/recheck-class
.\work\re_env\Scripts\python.exe tools/fw/verify_neighborhood_study.py --output analysis/recheck-neighborhood-verification.json
```

脚本快照、命令、反汇编、样本坐标、图和模块构建清单均留在 `analysis/raw-neighborhood-2026-11-09/`；证据与文档索引见该目录的 `evidence-index.json`。

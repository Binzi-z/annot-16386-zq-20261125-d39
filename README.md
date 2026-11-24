# 跨设备停机证据的最紧因果界

离线核验多设备停机日志：设备时钟允许**回拨**，人工补登只带**局部因果**。
仅使用原生 Windows 上的 Python 3.12 标准库，输入为本地确定性合成数据。

## 1. 统一的整数差分约束模型

每条证据都归一化为同一种整数约束（`forensic/model.py`）：

```
x_v - x_u <= w            对应图上一条 u -> v、权为 w 的边
```

| 证据 | 变量/边 |
|---|---|
| 设备偏移范围 `lo..hi` | `off:dev` 与参考零点 `ref` 之间的两条边 |
| 时钟回拨 `clock_adjust` | 新增偏移分段 `off:dev#k`，用 `delta_min..delta_max` 约束分段差 |
| 事件本地时戳 `t` | 有效时 `ev = t + off`（一对等权反向边，钉死等式） |
| 入账延迟上限 `lag` | `bk - ev <= lag`，入账位 `bk` 与有效时 `ev` 是**两套变量** |
| 入账先后 | 相邻入账位之间 `bk_prev - bk <= -1`（严格递增） |
| 跨设备因果边 | `dst - src >= min_delay`、`<= max_delay` |
| 人工补登 `manual` | 与因果边同构（仅局部因果），另给宽松入账延迟 |

关键推论（`forensic/solver.py`）：

* 最紧界 = 最短路。`x_b - x_a` 的上界是 `d(a,b)`，下界是 `-d(b,a)`；
* 约束矛盾 = 负环；最短路上的边即**可复核见证链**，边权之和可手工复核；
* 整数系统中某取值可满足当且仅当落在 `[下界, 上界]` 内。据此精确判断：
  严格为负（a 晚于 b）是否**可能**、严格为正（a 早于 b）是否可能、相等是否
  可能，再区分**必然先后**（另一方向不可满足）、**仅可能先后**（两方向都可满足）、
  **必然相等（相等边界，上下界都为 0）**与**不连通**（两个方向都无路径）。
  判定 id 如 `necessary_a_before` / `possible_both_orders` / `necessary_equal` /
  `disconnected`，中文标签随报告输出。

## 2. 三个求解引擎

1. `spfa_full`：全图 SPFA（全零虚拟源、FIFO、定序），一次性求全变量最紧界；
2. `IncrementalSolver`：逐条加边做**局部传播**，只入队真正变紧的节点，
   统计节点访问数、边扫描数、松弛数；终态距离与前驱和全量逐元素一致；
3. `JohnsonOracle`：用 SPFA 解作可行势函数做 Johnson 重加权，再以
   Dijkstra 回答指定事件对，边 id 定序打破平局，见证可复现。

矛盾时按 SCC 隔离，用定界 DFS 枚举**最短负环**（长度升序、起点为环上最小
节点、规范旋转去重、稳定排序输出）；预算耗尽时回退到 SPFA 前驱链并在报告中
显式标记 `exact_shortest=false`。

## 3. 入账序 / 有效时分离与封存复现

* 有效时变量（`ev:*`/`off:*`）与入账变量（`bk:*`）只通过延迟上限耦合，
  迟到的补登不会改写既有有效时事实；
* 水位就是日志前缀长度：`replay(records, watermark=w)` 重建出逐字节相同的
  节点编号、边 id 与报告；迟到证据仅在并查集所属**连通分量**内传播，
  报告给出每个被触及分量的记录数/边数（`late_evidence`）；
* 报告以规范 JSON（键排序、无空白、UTF-8）序列化并内嵌 `sha256`，
  在旧封存水位重跑得到同一哈希。

## 4. 目录与运行

```
forensic/   model.py solver.py journal.py generator.py cli.py
tests/      test_exhaustive.py   小范围穷举（独立暴力枚举交叉验证）
            test_stress.py       60000+ 事件压力 / 水位复现
run_all.py  端到端：生成数据 -> 报告 -> 两套测试
```

```bash
python run_all.py
python tests/test_exhaustive.py
python tests/test_stress.py
python -m forensic.cli generate --kind small --outdir data
python -m forensic.cli analyze --journal data/rollback.jsonl \
    --queries data/rollback.queries.json --report artifacts/r.json
python -m forensic.cli verify --report artifacts/r.json
```

## 5. 测试如何对应题面要求

* **小范围穷举偏移**：`test_exhaustive.py` 内置与产品代码完全独立的
  暴力枚举器，逐赋值检查全部约束，对 300 个随机小图 + 手工样例核对
  最紧界、必然/可能判定、见证链数值；覆盖**时钟回拨、相等边界、不连通、
  矛盾负环**；
* **六万条事件**：`large_journal()` 默认生成 24×2500 = 60000 个事件
  （含约 10% 回拨分段），核对全量/增量距离与前驱一致、局部更新访问只落在
  相关分量、Johnson 界与见证可复核；
* **封存复现**：追加迟到证据后在旧水位重跑，报告规范字节与 sha256 不变。

# Scoping very large binaries for targeted analysis

以微信 4.1.7 macOS 版主二进制 (`Contents/MacOS/WeChat`, SHA-256
`764966cdaaf945bc8b23968bb7b3dca3cdc4067e2891a38e28c7556788e0682c`) 为例, 记录在
REA + Ghidra 上做定点分析的可复用做法与踩过的坑.

文中出现的地址都是该二进制 arm64 切片的虚地址 (镜像基址 0x100000000), 只在这一案例内有效.

## 适用场景

目标是上百 MB 的原生二进制, 函数数十万级, 全量自动分析在笔记本上跑不完, 而实际只关心
其中少数功能 (例如某一条业务链路). 做法是"先量规模, 再收缩目标, 最后定点读代码".

## 1. 先量规模, 不要先跑工具

两个数就能决定策略:

| 指标 | 取法 | 本例 |
| --- | --- | --- |
| 函数数 | `LC_FUNCTION_STARTS` 的 ULEB128 增量表 | 328,989 |
| 代码量 | `__TEXT.__text` 节区大小 | 92.29 MB |

本例分析的 arm64 切片 (文件内偏移 `0x9530000`, 大小 147,375,040 字节) 的 SHA-256 是
`f7f9b8044c911e674d5a7c8b377f410a2784c07d67d80b5bce188ed221b199be`.

经验判断: 函数数过 5 万, 或 `__text` 过 20 MB, 就不要指望全量分析在 16 GB 笔记本上跑完.
本例约 2300 万条 ARM64 指令.

同时确认符号情况: 本例非导入符号只有 2 个, 说明已剥离, 拿不到本地函数名, 只能靠元数据加反汇编.

## 2. 地址基准: 最容易错的地方

`LC_FUNCTION_STARTS` 的增量是相对**镜像基址** (`__TEXT` 段 vmaddr) 的, **不是** `__text`
节区地址. 两者通常差一个头部长度 (本例 0x15000). 混用会让函数地址整体偏移一个固定值,
表现为"函数起点看起来像函数中段": 反汇编出来的是一个 `bl` 开头的片段, 而不是正常的
函数序言.

## 3. 找入口: 字符串引用扫描

ARM64 上字符串引用多为 `adrp` + `add` 或 `adrp` + `ldr`. 三个必须注意的点:

1. **ADRP 的编码是 `1 immlo[2] 10000 immhi[19] Rd[5]`**, 高字节随 `immlo` 变化.
   判断必须用掩码 `(insn & 0x9F000000) == 0x90000000`; 只比高字节是否为 0x90 会漏掉
   四分之三的 ADRP, 表现为"命中数少得离谱". 修好之后命中从 3 处变 7 处.
2. **配对窗口不必开大**. 把 ADRP 与 ADD 的距离窗口从 12 放宽到 128, 结果完全一样,
   说明该二进制的取址是紧邻的. 窗口放大只会引入误报.
3. **得到 0 命中时先做对照实验**. 拿反汇编里亲眼见过的某个引用 (例如
   `adrp x9, 0x108c9d000` + `ldr x9, [x9, #0x9a8]`) 去扫, 能精确命中就证明工具是好的,
   0 是真实结论. 这一步能省掉大量"再换个写法试试"的瞎猜.

引用可能有三条完全不同的路径, 都要考虑:

- 代码直接 ADRP+ADD 取址
- 经数据段的指针槽 (要处理链式修复编码, 见下节)
- **运行期拼串**. 本例 `_revoke_time` 是代码逐字节写进全局缓冲区的, `revokemsg` 也是拼出来的,
  静态扫描永远看不到.

## 4. 数据段的指针是编码的

有 `LC_DYLD_CHAINED_FIXUPS` 时, 文件内的指针不是运行期虚地址. 对
`DYLD_CHAINED_PTR_64_OFFSET`, **低 36 位是相对镜像基址的偏移**:

```
运行期虚地址 = 镜像基址 + (原值 & 0xFFFFFFFFF)
```

字符串池有两种形态混在一起, 必须区分:

- NUL 结尾的正常字符串 (`__cstring` 基本是这种)
- **定长槽的名字表**. 本例 `__TEXT.__const` 里有一段 127 字节的可打印区, 按 16 字节切
  正好是 `CancelCheckRevok|AsyncCheckRevoke|HandleRevokeFail|Revoke list empt|...`,
  长名被硬截断到 16 字节, 且没有 NUL 分隔

在第二种区域里按"向前读到 NUL"取字符串, 会得到拼接的假串, 进而误判为"没有引用".
先确认字符串所在区域属于哪一种, 再决定信任哪一部分结论.

## 5. 收缩分析范围

**关键认识: Ghidra 会沿调用目标扩散, 只收缩函数表是不够的.**
本例把函数表从 328,989 项收缩到 586 项后, 日志里仍然出现距离目标五千万字节之外的地址,
说明分析已经扩散到几乎整份二进制.

要真正把工作量关进上界, 需要两个手段叠用:

1. 重写 `LC_FUNCTION_STARTS`, 只保留目标范围内的函数项
2. **把范围之外的 `__text` 字节清零**: 这一步才切断扩散

| 做法 | 本例结果 |
| --- | --- |
| 只做第 1 步 | 328,989 -> 15,016 项, 40 分钟仍未跑完 |
| 第 1 步 + 第 2 步 | 328,989 -> 1,895 项, `__text` 保留 0.47 MB, 分析 **147 秒** |

派生件保持段区表, 数据段和指针修复表不变, 因此**虚地址与原文件一致**, 结果可以直接对照.
代价是范围外被调函数的语义丢失 (调用点指向无意义字节), 所以这种派生件只适合
"读指定函数的伪代码", 不适合"顺着调用图往外走". 要顺着走就必须保留更大的连续范围,
从而接受更长的分析时间: 这是必须显式权衡的取舍.

派生件与原文件不再字节一致, 因此要走 `--integrity-policy record-and-continue`, 并如实
说明来源.

## 6. 分析器与堆

三个最耗时的分析器 (按本例观测):

- `Aggressive Instruction Finder`: 会在可执行段里搜索所有未标记字节
- `Decompiler Parameter ID`: 会对每个函数跑一遍反编译器
- `Decompiler Switch Analysis`: 遇到不返回函数会反复重启

用 `REA_GHIDRA_DISABLED_ANALYZERS` 关闭.**保真度代价要记住**: 关掉
`Decompiler Switch Analysis` 会让部分被调函数的恢复代码体显著变短 (REA 自己的实验里
一个被调函数从 604 字节降到 164 字节), 顶层计数相同不能证明调用图等价.

堆用 `GHIDRA_HEADLESS_MAXMEM` (或 `GHIDRA_MAXMEM`, 默认 2G). 它是 JVM 的 `-Xmx`,
**只是上限不会预留**, 所以设大不浪费. 本例 3 GB 不够: 日志里
`ConstantPropagationAnalyzer` 抛 `OutOfMemoryError: Java heap space`, 随后
`HeadlessAnalyzer Abort due to Headless analyzer error` 整轮中止. 改用 12 GB 后越过了
原来的崩溃点.

启动超时用 `REA_GHIDRA_STARTUP_TIMEOUT_MS` (默认 330 秒). 大目标必须提前提高, 否则
跑到一半被 REA 判超时; REA 用 `-deleteProject` 启动 Ghidra, 项目会被删掉, 前面的时间白费.

## 7. 版本落差: 文档描述的能力可能不在已发布版里

仓库 checkout 的文档可能描述**尚未发布**的能力. 本例踩到两次:

- `--target-format raw-binary` (含 `--architecture` / `--entry-point`)
- `REA_GHIDRA_DISABLED_ANALYZERS`

两次的表现都是"参数被静默忽略"或"直接报 Unknown flag", 容易误判成参数写错.
校验方式是在已安装包里直接查:

```shell
P=~/.npm/_npx/<hash>/node_modules/rea-agents
grep -rl "raw-binary\|disabledAnalyzers\|ReaGhidraAnalysisOptions" "$P"
ls "$P/bridge/ghidra/"
```

反向印证: 看实际启动的 JVM 命令行里有没有那个 `-postScript`.

确认缺能力后, 从仓库构建即可:

```shell
npm ci
npm run build:cached      # compile 任务会跑 tsc 并打包到 dist/
node scripts/rea.mjs ...  # 用本地构建的 CLI
```

## 8. 环境相关

- **JDK**: REA 找 Ghidra 时会挑 PATH 里最新的 JDK. 本例默认是 OpenJDK 26, 会被判为
  不合格; 必须显式 `export JAVA_HOME=...` 指到 21.
- **沙箱拒绝 `ps` 的副作用**: REA 在 `close_binary` 阶段要用进程表核对它启动的 Ghidra
  进程是否已清理. 沙箱拒绝 `ps` (`spawn EPERM`) 时, REA 会把整次调用报成
  `cleanup_incomplete`, **掩盖掉已经算出来的结果**. 真实结果保存在
  `details.partial_observation.raw_result.value` 里, 可以正常取出.
- **内存压力判断**: 不要用 swap 的 used. 它是累积分配量, 系统不会因为负载下降而归还,
  所以不能反映当前压力. 要看 `sysctl kern.memorystatus_vm_pressure_level`
  (1 = normal, 2 = warn, 4 = critical) 和 `memory_pressure` 的 free percentage.
  本例压力始终 1 到 2, 负载高只是 Ghidra 在并行分析.
- **清理遗留进程**: REA 被强杀时子 JVM 会留下.REA 会写 `ownership.json` (含 `pid` 与
  `process_group_id`), 用它核对后再终止进程组, 不要只凭 `pgrep` 的单个 PID 就动手.

## 9. 记录方式

原始反汇编与日志不要往对话里搬, 一律落文件, 对话里只留结论, 地址与排除项.
每轮记录这几类内容:

- 结论 (带虚地址)
- 证据来源 (哪个脚本, 哪条日志行)
- 排除项 (查过但没有的东西, 防止重复劳动)
- 方法论更新 (工具修正, 判断依据更正)
- 未解问题

另外: 用 `--snapshot` 保存分析结果, 后续查询复用.

## 10. 时间预算参考 (本例实测)

| 步骤 | 耗时 |
| --- | --- |
| 规模量测与字符串扫描 | 每次 1 到 2 分钟 |
| 有界分析 (1,895 个函数, 8 GB 堆) | 147 秒 |
| 单次反编译查询 (复用快照) | 约 2 分 20 秒 |
| 未切断扩散的中等范围分析 | 40 分钟仍未完成 |

## 附: 关键代码片段

以下几段是上面做法的核心, 用 Python 表达, 只读解析原件后写出派生件.

### 读函数起始表

`LC_FUNCTION_STARTS` 是一串 ULEB128 增量, 累加后得到相对镜像基址的函数偏移:

```python
def function_starts(blob):
    starts, addr, index = [], 0, 0
    while index < len(blob):
        value, shift = 0, 0
        while True:
            byte = blob[index]
            index += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        if value == 0:
            break
        addr += value
        starts.append(addr)
    return starts
```

### ADRP + ADD 取址扫描

```python
for index, insn in enumerate(instructions):
    va = text_addr + index * 4
    if insn & 0x9F000000 == 0x90000000:            # ADRP
        imm = ((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3)) << 12
        pages[insn & 0x1F] = ((va & ~0xFFF) + imm, index)
        continue
    if insn >> 24 == 0x91:                         # ADD (immediate, 64 位)
        delta = (insn >> 10) & 0xFFF
        if (insn >> 22) & 1:
            delta <<= 12
        register = (insn >> 5) & 0x1F
    elif insn >> 24 == 0xF9:                       # LDR (immediate, 64 位)
        delta = ((insn >> 10) & 0xFFF) * 8
        register = (insn >> 5) & 0x1F
    else:
        continue
    page, seen = pages.get(register, (None, 0))
    if page is not None and 0 < index - seen <= 12:
        resolved = page + delta                    # 与目标集合比对
```

### 解链式修复编码

```python
target_va = image_base + (raw_value & 0xFFFFFFFFF)
```

### 收缩函数表并清零范围外代码

```python
kept = [value for value in starts if inside(image_base + value)]   # 1. 过滤函数项
blob = b"".join(encode_uleb128(v - p) for v, p in pairs(kept)) + b"\x00"
patch_function_starts(image, blob)

for low, high in merged_keep_spans:                                 # 2. 清零间隔
    image[fileoff + cursor : fileoff + low] = b"\x00" * (low - cursor)
    cursor = high
```

### 从被掩盖的错误载荷里取结果

```python
payload = json.loads(stdout)
partial = payload.get("details", {}).get("partial_observation")
value = partial["raw_result"]["value"] if partial else None
```

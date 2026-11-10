# pdb-symbol-extract

[![tests](https://github.com/Calmgh/pdb-symbol-extract/actions/workflows/tests.yml/badge.svg)](https://github.com/Calmgh/pdb-symbol-extract/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

用**纯 Python** 读 Windows PDB 符号表 —— 不需要 IDA、不需要 `llvm-pdbutil`、
`cvdump`、`dumpbin`，不需要 DIA SDK，也不需要装 Visual Studio。

只要手上有 `exe` + 配套 `.pdb`，就能拿到：

* **`RVA → 函数名`** 全量公有符号（`S_PUB32`）
* **结构体成员偏移**（每个类每个字段的 `+0x??`），来自 TPI 流
* **一份「这份 PDB 到底是不是这个 exe 的」的证明**（GUID + Age）—— 这是最常被跳过、
  事后最痛的一步
* 可选的**带符号与 IAT 标注的反汇编**，不用开 IDA

实测：某大型游戏构建的 517 MB PDB，**134,571 个公有符号约 60 秒导完**；
956,127 条类型记录解出约 75,000 行成员偏移。同样一份符号，在 IDA 里光是打开
IDB 就要好几分钟，之后才谈得上查询。

```console
$ python pdb_symbols.py target.pdb target.exe out
PE sections:
   .text    VA=00001000 vsize=0A3F2000 raw=00000400
   .rdata   VA=0A3F3000 vsize=03B1A000 raw=0A3F3400
...
public symbols : 134571
filtered       : 1346  ((Server|NotifyServer|Client[A-Z]|_Server|RPC))
written        : out.tsv, out_rpc.txt
```

---

## 为什么做这个

现成的符号工具都默认你有一整套逆向环境：带授权的 IDA，或者装了 Visual Studio
因而有 `cvdump`。但很多时候两个都没有 —— 在干净的取证机上、IDA 已经被几百 MB
的数据库拖住、或者你要连续导五十个 build 而 GUI 根本不适合脚本化。

MSF 容器和 CodeView 记录本身并不复杂。这个仓库就是照格式一层层读下来的结果，
包括那些没有文档、只能靠看着偏移越错越离谱才学会的记录布局。

一路上踩过的坑都写在 **[docs/PITFALLS.md](docs/PITFALLS.md)**，共 21 条，
每条都有「症状 / 原因 / 修法」。如果你打算自己写解析器，那份文档才是有用的部分；
格式本身在 **[docs/FORMAT.md](docs/FORMAT.md)** 里做了一页纸的摘要。

## 安装

```bash
git clone https://github.com/Calmgh/pdb-symbol-extract
cd pdb-symbol-extract
pip install -r requirements.txt   # 只有 capstone，只有反汇编需要
```

Python 3.8+，无编译，无原生依赖。核心功能（容器、符号、类型）只用标准库。

## 快速开始

```bash
# 1. 这份 PDB 是不是这个 exe 的？**先跑这个**
python pdb_check.py target.pdb target.exe

# 2. 看容器结构：块、流、DBI 头
python pdb_info.py target.pdb

# 3. 导出全部公有符号 → RVA / 名字
python pdb_symbols.py target.pdb target.exe out
#    -> out.tsv       (rva / size / tag / name)
#    -> out_rpc.txt   (名字像网络入口的子集)

# 4. 结构体成员偏移
python pdb_types.py target.pdb types --find=UObject,UFunction
#    -> types_types.tsv    struct / size / member / offset / type_index
#    -> types_structs.tsv  struct / size / 成员数 / 基类数

# 5. 反汇编某个 RVA 附近（需要 capstone）
python pdb_disasm.py target.exe 0x1A2B30 30 --sym=out.tsv
python pdb_disasm.py target.exe 0x1A2B30 12 --check-start
```

## 每个工具回答什么问题

| 工具 | 问题 |
|---|---|
| `pdb_check.py` | 这份 PDB 和这个 exe 是同一次链接吗？（GUID **和** Age 都要对） |
| `pdb_info.py` | 这是不是合法的 MSF 7.0 容器，符号流在哪？ |
| `pdb_symbols.py` | 函数 X 的 RVA 是多少？RPC 攻击面大概什么规模？ |
| `pdb_types.py` | 类 X 的字段 Y 在哪个偏移？ |
| `pdb_disasm.py` | 这个 RVA 处的代码长什么样？它真的是函数开头吗？ |

### 输出格式

`out.tsv` 故意做得很朴素：

```
# rva	size	tag	name
0x1234	0	5	?SomeFunction@UObject@@QEAAXXZ
```

四列、Tab 分隔、按 RVA 排序。可以直接喂给 `awk`、`grep`、表格软件，
或者和另一个 build 的导出做 diff。

## 作为库使用

```python
from pdbsym import MSF, PE, TPI
from pdbsym.pub import extract_public_symbols

with PE("target.exe") as pe, MSF("target.pdb") as pdb:
    # 同 build 证明
    _, _, pdb_age, pdb_guid = pdb.info_stream()
    cv = pe.codeview()
    assert (cv.guid, cv.age) == (pdb_guid, pdb_age)

    # 符号
    symbols = extract_public_symbols(pdb, pe)
    print(len(symbols), "symbols")

    # 类型
    tpi = TPI(pdb.stream(2))
    members, structs = tpi.collect_structs(only=["UObject"])
```

`pdbsym.tpi.TPI.collect_structs()` 直接返回可以写成 TSV 的行，
所以「每个 build 自动导一遍」只需要十几行脚本。

## 千万别省的两项校验

一份解析完全成功、但内容错位的符号表，是能骗过你自己的。两个便宜的检查能拦住
绝大多数情况：

1. **`pdb_check.py`** —— GUID 和 Age 必须**都**匹配。增量重建会保留 GUID 只把
   Age 加一，于是符号名全部有效，而每个 RVA 的漂移量各不相同。
2. **节区间包含** —— 抽几个符号，确认 RVA 落在 `.text` 里。如果所有符号都落在
   镜像之外，说明节表映射错了。

想要更强的证据：抽 20–30 个公有函数，各反汇编不超过 40 条指令，统计直接 `call`
的目标有多少正好落在已知符号入口。同 build 接近 100%，不同 build 会断崖式下跌。

## 已知限制

* **`S_PUB32` 只覆盖公有符号。** 静态/内部函数不在里面。`0 命中` 只代表「不是
  公有的」，不代表「不存在」—— 那些要走模块流或运行期特征扫描。
* **不做反修饰。** 名字是 MSVC 修饰名。可读部分都在，关键词 `grep` 通常够用。
* **没有覆盖全部 CodeView leaf。** 未建模的成员（尤其是 `UObject` /
  `UFunction` / `UProperty` / `FArchive` 里的）靠有界重同步兜底，可能少几个成员。
  见 PITFALLS #16。
* **不读源码行号**，不解析模块流，不支持写回。
* **只支持 MSF 7.0。** 老的 MSF 2.0 PDB 会明确报错拒绝。

## 测试

测试用例按格式规范**现造**一个最小 PDB 和 PE —— 一个类、一个成员、两个公有符号
—— 然后走一遍全部解析链路。不依赖任何第三方二进制，仓库里也不存 fixture 文件。

```bash
python -m unittest discover -s tests -v
```

## 这些知识从哪来

格式本身不是新东西，散落在
[LLVM](https://github.com/llvm/llvm-project)（`llvm/lib/DebugInfo/MSF`、
`llvm/lib/DebugInfo/CodeView`）、流传在外的 `microsoft-pdb` 笔记，以及一堆各自
踩坑的小解析器里。这个仓库补的是一个最小、无依赖的实现，外加一份把
「最费时间的记录布局」写下来的记录。

## 许可

MIT，见 [LICENSE](LICENSE)。

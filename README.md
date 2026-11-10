# pdb-symbol-extract

[![tests](https://github.com/Calmgh/pdb-symbol-extract/actions/workflows/tests.yml/badge.svg)](https://github.com/Calmgh/pdb-symbol-extract/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)

Read Windows PDB symbol tables in **pure Python** — no IDA, no
`llvm-pdbutil`, no `cvdump`, no `dumpbin`, no DIA SDK, no Visual Studio.

Given an `exe` + its `.pdb`, this gets you:

* **`RVA -> function name`** for every public symbol (`S_PUB32`)
* **struct member offsets** (`+0x??` for every field of every class) from the TPI stream
* a **proof that the PDB actually belongs to that exe** (GUID + age), which is
  the check almost everyone skips and later regrets
* optional **disassembly with symbol and IAT annotation**, without opening IDA

On a 517 MB PDB that ships with a large game build: **134,571 public symbols in
about 60 seconds**, and roughly 75,000 struct member offsets from a 956,127-record
type stream. On the same machine, opening the equivalent IDB in IDA takes
minutes before you can query anything.

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

## Why

Symbol tooling usually assumes you have a full RE environment: IDA with a
license, or a Visual Studio install that provides `cvdump`. Sometimes you have
neither — you are on a clean analysis box, or IDA is already choking on a
500 MB database, or you want to script the export for fifty builds in a row and
a GUI is not an option.

The MSF container and the CodeView records are not that complicated. This
repository is the result of parsing them from the format up, including the
record layouts that are documented nowhere and can only be learned by watching
your offsets drift.

Every trap found along the way is written up in
**[docs/PITFALLS.md](docs/PITFALLS.md)** — 21 of them, each with symptom, cause
and fix. If you are writing your own parser, that document is the useful part.
The format itself is summarised in **[docs/FORMAT.md](docs/FORMAT.md)**.

## Install

```bash
git clone https://github.com/Calmgh/pdb-symbol-extract
cd pdb-symbol-extract
pip install -r requirements.txt   # only capstone, only for disassembly
```

Python 3.7+. No compilation, no native dependencies. The core (container,
symbols, types) needs nothing beyond the standard library.

## Quick start

```bash
# 1. Does this PDB belong to this exe? Run this FIRST.
python pdb_check.py target.pdb target.exe

# 2. Look at the container: blocks, streams, DBI header
python pdb_info.py target.pdb

# 3. Export every public symbol as RVA -> name
python pdb_symbols.py target.pdb target.exe out
#    -> out.tsv        (rva / size / tag / name)
#    -> out_rpc.txt    (subset whose names look like network entry points)

# 4. Struct member offsets
python pdb_types.py target.pdb types --find=UObject,UFunction
#    -> types_types.tsv    struct / size / member / offset / type_index
#    -> types_structs.tsv  struct / size / member_count / base_count

# 5. Disassemble around an RVA (needs capstone)
python pdb_disasm.py target.exe 0x1A2B30 30 --sym=out.tsv
python pdb_disasm.py target.exe 0x1A2B30 12 --check-start
```

## What each tool answers

| Tool | Question |
|---|---|
| `pdb_check.py` | Is this PDB from the same link as this exe? (GUID **and** age) |
| `pdb_info.py` | Is this a well-formed MSF 7.0 container, and where is the symbol stream? |
| `pdb_symbols.py` | What is the RVA of function X, and what does the RPC surface look like? |
| `pdb_types.py` | What offset is field `Y` at inside class `X`? |
| `pdb_disasm.py` | What does the code at this RVA look like, and is it a real function entry? |

### Output format

`out.tsv` is deliberately boring:

```
# rva	size	tag	name
0x1234	0	5	?SomeFunction@UObject@@QEAAXXZ
```

Four tab-separated columns, sorted by RVA. It drops straight into `awk`,
`grep`, a spreadsheet, or a diff against another build's export.

## Library use

```python
from pdbsym import MSF, PE, TPI
from pdbsym.pub import extract_public_symbols

with PE("target.exe") as pe, MSF("target.pdb") as pdb:
    # Same-link proof
    _, _, pdb_age, pdb_guid = pdb.info_stream()
    cv = pe.codeview()
    assert (cv.guid, cv.age) == (pdb_guid, pdb_age)

    # Symbols
    symbols = extract_public_symbols(pdb, pe)
    print(len(symbols), "symbols")

    # Types
    tpi = TPI(pdb.stream(2))
    members, structs = tpi.collect_structs(only=["UObject"])
```

`pdbsym.tpi.TPI.collect_structs()` returns rows ready to write as TSV, so
scripting a per-build export is a handful of lines.

## Verification you should not skip

A symbol table that parses cleanly can still be completely wrong. Two cheap
checks catch nearly everything:

1. **`pdb_check.py`** — GUID and age must *both* match. An incremental rebuild
   keeps the GUID and bumps the age; the names stay valid while every RVA
   shifts by a different amount.
2. **Section containment** — sample a few symbols and confirm the RVA falls
   inside `.text`. If every symbol lands outside the image, the section mapping
   is wrong.

For a stronger check, sample 20–30 public functions, disassemble up to 40
instructions each, and count how many direct `call` targets land exactly on a
known symbol entry. A correctly matched build scores near 100%; a mismatched
build collapses.

## Limitations

* **`S_PUB32` only covers public symbols.** Static and internal functions are
  absent. `0 hits` means "not public", not "does not exist" — use module streams
  or runtime signature scanning for those.
* **No demangler.** Names come out MSVC-decorated. The readable parts survive,
  so keyword `grep` usually works without undecorating.
* **Not every CodeView leaf is modelled.** Unknown members (notably in
  `UObject` / `UFunction` / `UProperty` / `FArchive`) are recovered by bounded
  resynchronisation, which can lose members. See PITFALLS #16.
* **No source line info**, no module stream parsing, no write support.
* **MSF 7.0 only.** Old MSF 2.0 PDBs are rejected with a clear error.

## Tests

The test suite builds a synthetic PDB and PE from the format spec — one class,
one member, two public symbols — and round-trips them through every parser. No
third-party binaries, no fixtures checked in.

```bash
python -m unittest discover -s tests -v
```

## Prior art

The format knowledge here is not new; it is scattered across
[LLVM](https://github.com/llvm/llvm-project) (`llvm/lib/DebugInfo/MSF`,
`llvm/lib/DebugInfo/CodeView`), the `microsoft-pdb` notes that circulated
publicly, and a long tail of small parsers. What this repository adds is a
minimal, dependency-free implementation plus a written record of the record
layouts that cost the most time.

## License

MIT. See [LICENSE](LICENSE).

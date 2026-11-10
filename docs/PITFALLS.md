# Pitfalls

Every entry below cost real debugging time. The format is the same throughout:
**symptom** (what you see), **cause** (why), **fix** (what to do).

If you are writing your own PDB parser, read this before you start. The MSF
container is easy; the record layouts are where the time goes.

---

## Container / MSF

### 1. The DBI header field order is easy to get wrong

**Symptom** — `ModInfoSize` comes out as `4177264641` or some other absurd
number, and everything after it is nonsense.

**Cause** — The DBI header is `3 x u32` then `6 x u16` then `8 x i32` then
`2 x u16`. Dropping the third `u32` (the **age** field, which is redundant with
the info stream and therefore easy to dismiss as noise) shifts every following
field by four bytes.

**Fix** — Sanity-check the numbers as you parse them. `ModInfoSize` should be a
plausible byte count, `Machine` should be one of the known constants. If a value
looks like a pointer, you are off by a field.

### 2. Stream block lists have **no length prefix**

**Symptom** — `struct.error: unpack_from requires a buffer of at least 3918216
bytes ... at offset 1964212`. The reported offset grows each time you retry,
which is the signature of this bug.

**Cause** — The directory layout is:

```
u32 stream_count
u32 stream_sizes[stream_count]
u32 block_indices[]          <-- bare array, no count, per stream
```

The number of block indices for stream *i* is `ceil(stream_sizes[i] /
block_size)`. It is **derived**, not stored. Reading a count first will consume
the first block index as if it were a length, and everything after that is
garbage.

**Fix**

```python
pos = 4 + 4 * n_streams
for i in range(n_streams):
    size = 0 if sizes[i] == 0xFFFFFFFF else sizes[i]
    nb = -(-size // block_size)          # ceil, no prefix
    blocks = struct.unpack_from("<%dI" % nb, directory, pos)
    pos += nb * 4
```

Self-check: `pos` must not exceed `dir_bytes` rounded up to a block boundary.

### 3. `0xFFFFFFFF` means "empty stream", not "4 GB"

**Symptom** — the parser tries to read a 4 GB stream and either hangs or throws.

**Cause** — Empty streams are marked with a size of `0xFFFFFFFF`.

**Fix** — Normalise to `0` before computing the block count.

### 4. The directory must be padded up to a block boundary before slicing

**Symptom** — the last stream's block list is truncated, or parsing runs past
the end.

**Cause** — `dir_bytes` tells you how many blocks to read, not how many bytes
the directory logically contains. Slicing the concatenated blocks to `dir_bytes`
clips the final block.

**Fix** — Use `dir_bytes` only to compute `ceil(dir_bytes / block_size)`. Parse
from the padded buffer.

### 5. Zero-length streams have an empty block list

**Fix** — Skip them entirely. `struct.unpack_from("<0I", ...)` on an empty
buffer is fine, but `n = 0` with a manual loop will still try to seek.

### 6. Streams 4, 8, 9 are usually empty

Do not assume a stream index implies content. Only stream 1 (info), 2 (TPI),
3 (DBI) and the streams named in the DBI header are guaranteed to be useful.

---

## Public symbols (S_PUB32)

### 7. S_PUB32 is **not** all symbols

**Symptom** — a function you know exists returns zero hits when you grep the
exported table.

**Cause** — `S_PUB32` covers **public** symbols only: function entry points and
file-scope globals. Static / internal functions are not in it. They live in the
module streams, which is a different (larger) job.

**Fix** — Treat `0 hits` as "not public", never as "does not exist". To get
internal names, read the module streams or fall back to runtime signature
scanning.

### 8. Names are MSVC-decorated, not source names

`?ProcessRemoteFunction@UObject@@UEAAXPEAVUFunction@@PEAX@Z` — that is the name
you get. The readable parts survive, so `grep -i ProcessRemote` works fine
without undecorating. Do not spend time on a demangler unless you need the
signature.

### 9. Duplicate RVAs are normal

**Symptom** — several different names share one address.

**Cause** — Identical COMDAT folding (ICF) merges identical functions, and
aliases are common.

**Fix** — Not a bug. Disassemble to decide which name is meaningful.

---

## Type records (TPI, stream 2)

Four traps, all of the same shape: a field is one width smaller than expected,
so every following field shifts.

### 10. Record `Length` **includes** the leaf field

**Symptom** — names truncated, offsets absurd, member chains empty.

**Cause** — A TPI record is `u16 Length; u16 Leaf; u8 data[]` where `Length`
counts the leaf. The payload is therefore `data[off+2 : off+2+Length]`, **not**
`Length - 2`.

### 11. `LF_CLASS` / `LF_STRUCTURE` `Size` is a plain `u16`

**Symptom** — class names lose their first two characters.

**Cause** — The layout is:

```
+0x00 u16 leaf
+0x02 u16 member_count
+0x04 u16 properties
+0x06 u32 field_list
+0x0A u32 derived_from
+0x0E u32 vshape
+0x12 u16 size            <-- plain u16
+0x14     name
```

Reading `size` as a Numeric consumes two extra bytes and shifts the name.

**Fix** — Read `u16` at `+0x12`; only treat it as a Numeric when the value is
`>= 0x8000`.

### 12. Member offsets use a "hybrid Numeric"

**Symptom** — `Next` becomes `xt`, offsets become astronomical.

**Cause** — `LF_MEMBER`, `LF_BCLASS` and `LF_ENUMERATE` store their offset as a
`u16` that is *sometimes* a Numeric leaf. The rule: if the `u16` is `>= 0x8000`
it is a Numeric leaf; otherwise it is the literal value.

```python
value = struct.unpack_from("<H", rec, off)[0]
if value >= 0x8000:
    value, off = read_numeric(rec, off)
else:
    off += 2
```

### 13. `LF_PAD0..LF_PAD3` are **single bytes**

**Symptom** — a class has a size but zero members; the member chain stops at the
first padding byte.

**Cause** — Padding leaves occupy one byte each (`0xF0`–`0xF3`). Reading them as
a `u16` turns `F2 F1` into `0xF1F2`, the leaf check fails, and the walk aborts.

**Fix** — Check the single byte first:

```python
if 0xF0 <= rec[off] <= 0xF3:
    off += 1
    continue
leaf = struct.unpack_from("<H", rec, off)[0]
```

### 14. Same-named classes appear multiple times

Forward declarations and template instantiations all carry the same name.

**Fix** — Pick the most complete record. "Largest size" is a decent heuristic
but can select a template instantiation; "most members + exact name match" is
usually better. Neither is a rule — verify against a class you can check.

### 15. Inheritance is not expanded

`LF_MEMBER` lists only members declared in that class. Base-class members come
from `LF_BCLASS`, which you must follow upward yourself.

### 16. Some leaves are not handled

`LF_ONEMETHOD`, `LF_METHOD`, `LF_VFUNCTAB`, `LF_VBCLASS`, `LF_IVBCLASS` have
lengths that depend on attribute bits. This implementation resynchronises by
scanning forward (bounded to 96 bytes) for the next plausible leaf on an even
boundary. It recovers many members, but is unreliable for `UObject`,
`UFunction`, `UProperty` and `FArchive`.

The precise fix is to implement those length derivations, or to follow the
`LF_INDEX` chain completely.

---

## Matching a PDB to its binary

### 17. "Same GUID" does **not** mean "same build"

This is the most dangerous pitfall because everything looks fine until it does
not.

**Symptom** — symbol names resolve, the parse validates, but disassembly is
garbage: function entries land in the middle of other functions' epilogues, or
inside `int3` padding.

**Cause** — An incremental rebuild keeps the CodeView GUID and increments the
**age**. Two different links can therefore report the same GUID.

**Fix** — Compare **GUID and age**, from both sides:

* exe → PE debug directory → `RSDS` record → `GUID(16) + age(u32)`
* PDB → info stream (stream 1) → `version, signature, age, guid`

`pdb_check.py` does exactly this. Do not skip it: it costs a second and saves
hours.

If the GUID matches but the age differs, symbol *names* are still meaningful but
every RVA may have shifted. If both differ, you have an unrelated PDB.

### 18. Validate RVAs inside the binary's sections

**Symptom** — no crash, just wrong results.

**Fix** — Sample a few symbols and confirm the RVA falls inside a real section
(`.text` VA .. VA + vsize). A symbol table where every RVA lands outside the
image means the section table or the section index mapping is wrong.

Cross-validation, cheap to strong:

1. **String constants** — take a `??_C@_...@<literal>@` symbol, search the exe
   for the literal, compare RVAs. Beware: with wide-character + hashed name
   encoding this can return `0/0`, which proves nothing. Do not treat `0/0` as
   a pass.
2. **Call-target hit rate** — sample 20–30 public functions in `.text`,
   disassemble ≤40 instructions each, and count how many direct `call` targets
   land exactly on a known symbol entry. A correctly matched build scores near
   100%; a mismatched build drops sharply.

### 19. Function entries need a prologue check before hooking

**Symptom** — the hook crashes immediately, or corrupts unrelated state.

**Cause** — the address is a symbol RVA, but not the start of the function (it
can point at a thunk interior or a jump table entry).

**Fix** — Look backwards: the byte before the target should terminate the
previous function (`ret`, `jmp`, `int3`, padding), and the bytes at the target
should be a standard x64 prologue (`48 8B C4`, `48 89 5C 24 xx`, `40 55`,
`48 83 EC`). `pdbsym.disasm.looks_like_function_start()` implements this.

---

## PE side

### 20. Import names live in the INT, not the IAT

**Symptom** — import resolution returns garbage for `call qword ptr [rip+x]`.

**Cause** — Two parallel arrays: `OriginalFirstThunk` (INT, holds name RVAs) and
`FirstThunk` (IAT, holds resolved addresses at runtime). Code references the
IAT, but the names must be read from the INT. If `OriginalFirstThunk` is zero,
the INT and IAT are the same array at load time. Names are prefixed with a
2-byte hint, so skip two bytes before reading the string.

### 21. Packed binaries make static RVAs meaningless

**Symptom** — the disassembly of `.text` looks like noise; section names are odd
(`.std`), entropy near 8.

**Cause** — The on-disk code is encrypted. A runtime address is still valid, but
the file you are reading has different bytes there.

**Fix** — Get an unpacked copy and verify it is the same link via
`TimeDateStamp` + section virtual-address table + CodeView GUID/age before using
its RVAs. Hook baselines (the original prologue bytes) must be read from running
memory, not from disk.

---

## Scope note

This tool reads symbols and type records. It does not read source lines, fails
to model every CodeView leaf, and makes no attempt at a full demangler. That is
deliberate: `S_PUB32` plus TPI member offsets answer most "where is this
function, what is that field" questions, and they do it in about a minute on a
500 MB PDB.

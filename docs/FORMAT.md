# PDB format, in one page

Enough of the layout to read this codebase. For the full story, see the
`llvm-pdbutil` sources under `llvm/lib/DebugInfo/MSF` and
`llvm/lib/DebugInfo/CodeView`.

## Three layers

```
1. MSF 7.0 container
   The file is a fixed-size-block filesystem. A block map points at the
   directory; the directory lists streams; each stream is a chain of blocks.

2. Streams
   stream 1  -> Info:   version, signature, age, GUID
   stream 2  -> TPI:    type records (struct members)
   stream 3  -> DBI:    debug information index; names the symbol record stream
   stream 4+ -> payloads referenced by the DBI header

3. Records
   The symbol record stream is a flat sequence of length-prefixed records.
   The type stream is the same, addressed by type index.
```

## Superblock (block 0, 56 bytes used)

| offset | type | field |
|---|---|---|
| 0x00 | u8[32] | `Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0` |
| 0x20 | u32 | block size |
| 0x24 | u32 | free block map block |
| 0x28 | u32 | number of blocks |
| 0x2C | u32 | directory size in bytes |
| 0x30 | u32 | unknown |
| 0x34 | u32 | block map address |

## Directory

```
u32 stream_count
u32 stream_size[stream_count]      # 0xFFFFFFFF == empty
u32 block_index[...]               # per stream, ceil(size/block_size) entries,
                                   # NO count prefix
```

## DBI header (stream 3)

| offset | type | field |
|---|---|---|
| 0x00 | u32 | version signature (`0xFFFFFFFF`) |
| 0x04 | u32 | version header (`19990903`) |
| 0x08 | u32 | age |
| 0x0C | u16 | global stream index |
| 0x0E | u16 | build number |
| 0x10 | u16 | public stream index |
| 0x12 | u16 | pdb dll version |
| 0x14 | u16 | **symbol record stream** |
| 0x16 | u16 | pdb dll rbld |
| 0x18 | i32[8] | mod info, section contrib, section map, source info, type server map, mfc type server, optional dbg header, ec substream sizes |
| 0x38 | u16 | flags |
| 0x3A | u16 | machine |

## Info stream (stream 1)

```
u32 version      # 20000404 for VC7+
u32 signature
u32 age
u8  guid[16]     # CodeView GUID; compare with the exe's RSDS record
```

## S_PUB32 symbol record

```
u16 length        # excludes itself, includes the type field
u16 type          # 0x110E
u32 flags
u32 section_offset
u16 section_index # 1-based
u8  name[]        # NUL-terminated, MSVC decorated
```

```
RVA       = sections[section_index - 1].VirtualAddress + section_offset
runtime   = ImageBase + RVA
```

## TPI type record

```
u16 length        # INCLUDES the leaf field
u16 leaf          # 0x1504 LF_CLASS, 0x1203 LF_FIELDLIST, 0x150D LF_MEMBER, ...
u8  payload[]
```

`LF_CLASS` payload:

```
+0x00 u16 member_count
+0x02 u16 properties
+0x04 u32 field_list
+0x08 u32 derived_from
+0x0C u32 vshape
+0x10 u16 size
+0x12     name
```

(Offsets are relative to the start of the payload, i.e. the leaf is already
consumed by the record header.)

`LF_MEMBER` entry inside `LF_FIELDLIST`:

```
u16 leaf          # 0x150D
u16 attributes
u32 type_index
u16 offset        # hybrid: >= 0x8000 means a Numeric leaf follows
u8  name[]        # padded to a 4-byte boundary
```

## PE debug directory (for the exe side)

`DataDirectory[6]` → array of 28-byte entries:

```
u32 characteristics
u32 timestamp
u16 major
u16 minor
u32 type            # 2 == CODEVIEW
u32 size_of_data
u32 address_of_raw_data   # RVA
u32 pointer_to_raw_data   # file offset
```

CODEVIEW payload: `"RSDS" | guid[16] | age(u32) | path[]`.

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build a minimal, synthetic MSF 7.0 PDB + PE pair for the test suite.

Nothing here is derived from a real binary: the PDB contains exactly one class,
one member and two public symbols, laid out by hand from the format spec. That
keeps the tests fast, self-contained and free of any third-party sample.

Run standalone to drop the fixtures next to this file::

    python tests/make_fixture.py
"""
import os
import struct

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"

BLOCK_SIZE = 512
IMAGE_BASE = 0x140000000
TEXT_VA = 0x1000
TEXT_RAW_SIZE = 0x200

#: Synthetic, obviously-fake identity shared by the fixture exe and PDB.
#: Never use a real GUID here -- a fixture that leaks a target's identity is a
#: fixture that should not be published.
GUID = bytes.fromhex("443322116655887799aabbccddeeff00")
AGE = 1

INFO_STREAM = 1
TPI_STREAM = 2
DBI_STREAM = 3
SYM_STREAM = 4
NUM_STREAMS = 5


# --------------------------------------------------------------- PDB content

def build_info_stream():
    return struct.pack("<III", 20000404, 0x12345678, AGE) + GUID


def build_dbi_stream(sym_stream=SYM_STREAM):
    out = bytearray(64)
    struct.pack_into("<III", out, 0, 0xFFFFFFFF, 19990903, AGE)
    struct.pack_into("<6H", out, 12,
                     3,            # global stream index
                     0,            # build number
                     3,            # public stream index
                     0,            # pdb dll version
                     sym_stream,   # symbol record stream
                     0)            # pdb dll rbld
    struct.pack_into("<HH", out, 56, 0, 0x8664)
    return bytes(out)


def build_tpi_stream():
    # LF_FIELDLIST with a single LF_MEMBER: "Health" at +0x10, type 0x74.
    member = struct.pack("<HHI", 0x150D, 0x0003, 0x0074)
    member += struct.pack("<H", 0x0010) + b"Health\0"
    member += b"\0" * (((len(member) + 3) & ~3) - len(member))

    fieldlist = struct.pack("<H", 0x1203) + member
    fieldlist_rec = struct.pack("<HH", len(fieldlist), 0x1203) + fieldlist[2:]

    # LF_CLASS "APawn", size 0x20, field list at type index 0x1000.
    body = struct.pack("<HHHIIIH", 0x1504, 1, 0, 0x1000, 0, 0, 0x20) + b"APawn\0"
    class_rec = struct.pack("<H", len(body)) + body
    # NOTE: `len(body)` already includes the leaf, matching CodeView's rule that
    # the Length field covers the leaf. See docs/PITFALLS.md #9.

    records = fieldlist_rec + class_rec
    header = struct.pack("<IIIII", 19950410, 20, 0x1000, 0x1001, len(records))
    return header + records


def build_symbol_stream():
    out = bytearray()
    for name, offset in (("?ServerFire@Test@@QEAAXXZ", 0x100),
                         ("?ClientMove@Test@@QEAAXXZ", 0x200)):
        encoded = name.encode("ascii")
        # length excludes its own 2 bytes, includes type+flags+offset+section+name
        length = 2 + 4 + 4 + 2 + len(encoded) + 1
        out += struct.pack("<HHIIH", length, 0x110E, 0, offset, 1)
        out += encoded + b"\0"
    return bytes(out)


# ---------------------------------------------------------------- PE content

def build_pe():
    image = bytearray(0x400)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)

    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", image, 0x84, 0x8664, 1)          # machine, sections
    struct.pack_into("<I", image, 0x88, 0x5F000000)          # timestamp
    struct.pack_into("<H", image, 0x94, 240)                 # SizeOfOptionalHeader

    opt = 0x98
    struct.pack_into("<H", image, opt, 0x20B)                # PE32+
    struct.pack_into("<Q", image, opt + 24, IMAGE_BASE)

    # Debug data directory = entry #6.
    struct.pack_into("<II", image, opt + 112 + 6 * 8, TEXT_VA, 28)

    sec = opt + 240
    image[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<4I", image, sec + 8,
                     0x1000, TEXT_VA, TEXT_RAW_SIZE, 0x200)
    struct.pack_into("<I", image, sec + 36, 0x60000020)

    # Debug directory entry -> RSDS blob.
    raw_offset = 0x200
    rsds = b"RSDS" + GUID + struct.pack("<I", AGE) + b"target.pdb\0"
    struct.pack_into("<IIHHIII", image, raw_offset,
                     0, 0, 0, 0, 2, len(rsds), TEXT_VA + 0x1C)
    struct.pack_into("<I", image, raw_offset + 24, 0x21C)
    image[0x21C:0x21C + len(rsds)] = rsds

    # A plausible function at RVA 0x1100: `mov rax, rsp` prologue preceded by a
    # `ret`, so the entry-point heuristic has something real to look at.
    image[raw_offset + 0xFF] = 0xC3              # rva 0x10FF: ret
    image[raw_offset + 0x100:raw_offset + 0x104] = b"\x48\x8B\xC4\xC3"
    return bytes(image)


# ------------------------------------------------------------ MSF container

def build_pdb():
    streams = [b"", build_info_stream(), build_tpi_stream(),
               build_dbi_stream(), build_symbol_stream()]

    def blocks_for(payload):
        n = -(-len(payload) // BLOCK_SIZE)
        return [payload[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE].ljust(BLOCK_SIZE, b"\0")
                for i in range(n)]

    payload_blocks = [blocks_for(s) for s in streams]
    n_dir_blocks = 1
    n_map_blocks = 1

    block_index = 1 + n_dir_blocks          # 0 = superblock, 1 = directory
    block_lists = []
    for blocks in payload_blocks:
        block_lists.append(list(range(block_index, block_index + len(blocks))))
        block_index += len(blocks)
    map_block = block_index

    directory = struct.pack("<I", NUM_STREAMS)
    directory += struct.pack("<%dI" % NUM_STREAMS,
                             *[len(s) for s in streams])
    for blocks in block_lists:
        directory += struct.pack("<%dI" % len(blocks), *blocks)
    directory = directory.ljust(n_dir_blocks * BLOCK_SIZE, b"\0")

    superblock = bytearray(64)
    superblock[0:32] = MAGIC
    struct.pack_into("<6I", superblock, 32,
                     BLOCK_SIZE,      # block size
                     0,               # free block map
                     map_block + 1,   # num blocks
                     len(directory),  # directory bytes (before padding)
                     0,               # unknown
                     map_block)       # block map address

    image = bytearray()
    image += superblock.ljust(BLOCK_SIZE, b"\0")
    image += directory
    for blocks in payload_blocks:
        for b in blocks:
            image += b
    image += struct.pack("<I", 1).ljust(n_map_blocks * BLOCK_SIZE, b"\0")
    return bytes(image)


def write_fixtures(directory):
    os.makedirs(directory, exist_ok=True)
    pdb_path = os.path.join(directory, "fixture.pdb")
    exe_path = os.path.join(directory, "fixture.exe")
    with open(pdb_path, "wb") as f:
        f.write(build_pdb())
    with open(exe_path, "wb") as f:
        f.write(build_pe())
    return pdb_path, exe_path


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    pdb, exe = write_fixtures(os.path.join(here, "data"))
    print("wrote %s (%d bytes)" % (pdb, os.path.getsize(pdb)))
    print("wrote %s (%d bytes)" % (exe, os.path.getsize(exe)))

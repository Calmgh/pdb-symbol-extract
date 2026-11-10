#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Print the container structure of a PDB: blocks, streams, DBI header.

Run this first on any new PDB. If the numbers printed here do not make sense,
nothing downstream will either.

Usage::

    python pdb_info.py target.pdb
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pdbsym import MSF


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    path = argv[1]

    with MSF(path) as pdb:
        print("file            : %s" % path)
        print("file size       : %d bytes" % pdb.filesize())
        print("block_size      : %d" % pdb.block_size)
        print("num_blocks      : %d" % pdb.num_blocks)
        print("dir_bytes       : %d" % pdb.dir_bytes)
        print("block_map_addr  : %d" % pdb.block_map_addr)
        print()

        problems = pdb.check()
        if problems:
            print("!! consistency problems:")
            for p in problems:
                print("   - %s" % p)
            print()
        else:
            print("consistency     : block_size * num_blocks == filesize  OK")
            print()

        print("stream count    : %d" % pdb.num_streams)
        sizes = pdb.stream_sizes
        preview = ", ".join(str(s) for s in sizes[:12])
        print("stream sizes[0:12]: %s" % preview)
        biggest = max(range(len(sizes)), key=lambda i: sizes[i])
        print("largest stream  : index %d, %d bytes" % (biggest, sizes[biggest]))
        print()

        version, signature, age, guid = pdb.info_stream()
        print("[Info stream 1]")
        print("  version   = %d" % version)
        print("  signature = %08X" % signature)
        print("  age       = %d" % age)
        print("  guid      = %s" % _format_guid(guid))
        print()

        dbi = pdb.dbi_header()
        print("[DBI stream 3]")
        print("  version_signature = %08X  (expect FFFFFFFF)" % dbi["version_signature"])
        print("  version_header    = %d  (expect 19990903)" % dbi["version_header"])
        print("  age               = %d" % dbi["age"])
        print("  machine           = %04X  (%s)" % (
            dbi["machine"], _machine_name(dbi["machine"])))
        print("  global stream     = %d" % dbi["global_stream"])
        print("  public stream     = %d" % dbi["public_stream"])
        print("  sym record stream = %d" % (
            -1 if dbi["sym_record_stream"] == 0xFFFF else dbi["sym_record_stream"]))
        print()

        print("[stream heads]")
        for i in range(min(pdb.num_streams, 12)):
            head = pdb.stream(i, limit=16)
            print("  stream[%2d] size=%-12d head=%s" % (i, sizes[i], head.hex()))
    return 0


def _format_guid(guid):
    d1 = int.from_bytes(guid[0:4], "little")
    d2 = int.from_bytes(guid[4:6], "little")
    d3 = int.from_bytes(guid[6:8], "little")
    d4 = guid[8:10].hex().upper()
    d5 = guid[10:16].hex().upper()
    return "%08X-%04X-%04X-%s-%s" % (d1, d2, d3, d4, d5)


def _machine_name(machine):
    return {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64",
            0x01C0: "ARM", 0x01C4: "ARMv7"}.get(machine, "unknown")


if __name__ == "__main__":
    sys.exit(main(sys.argv))

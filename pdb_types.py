#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Extract struct/class member offsets from a PDB's TPI stream.

Usage::

    python pdb_types.py target.pdb [prefix] [--find=UObject,UFunction]

Outputs::

    <prefix>_types.tsv     struct size member offset type_index
    <prefix>_structs.tsv   struct size members bases

Member offsets are the thing you actually want before hooking a function or
walking an object graph: they are exact, offline, and need no debugger.
"""
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pdbsym import MSF, TPI

TPI_STREAM = 2


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1

    pdb_path = argv[1]
    prefix = "types"
    outdir = "."
    find = None
    for arg in argv[2:]:
        if arg.startswith("--find="):
            find = [x.strip() for x in arg.split("=", 1)[1].split(",") if x.strip()]
        elif arg.startswith("--outdir="):
            outdir = arg.split("=", 1)[1]
        elif not arg.startswith("--"):
            prefix = arg

    os.makedirs(outdir, exist_ok=True)

    with MSF(pdb_path) as pdb:
        print("streams      : %d" % pdb.num_streams)
        print("TPI stream   : %d (%d bytes)" % (TPI_STREAM, pdb.stream_sizes[TPI_STREAM]))
        tpi = TPI(pdb.stream(TPI_STREAM))

    print("TPI version  : 0x%X" % tpi.version)
    print("type indices : %d..%d" % (tpi.ti_begin, tpi.ti_end))
    print("records      : %d" % len(tpi.records))

    members, structs = tpi.collect_structs()
    print("unique types : %d" % len(set(s[0] for s in structs)))
    print("member rows  : %d" % len(members))
    print()

    types_path = os.path.join(outdir, prefix + "_types.tsv")
    structs_path = os.path.join(outdir, prefix + "_structs.tsv")

    with open(types_path, "w", encoding="utf-8") as f:
        f.write("# struct\tsize\tmember\toffset\ttype_index\n")
        for row in members:
            f.write("%s\t%s\t%s\t%s\t%s\n" % row)

    with open(structs_path, "w", encoding="utf-8") as f:
        f.write("# struct\tsize\tmembers\tbases\n")
        for row in sorted(structs):
            f.write("%s\t%s\t%s\t%s\n" % row)

    print("written: %s" % types_path)
    print("written: %s" % structs_path)

    if find:
        _print_selected(members, structs, find)
    return 0


def _print_selected(members, structs, wanted):
    index = collections.defaultdict(list)
    for row in members:
        index[row[0]].append(row)
    sizes = dict((name, size) for name, size, _m, _b in structs)

    for want in wanted:
        hits = [k for k in index if k == want]
        if not hits:
            hits = [k for k in index if want.lower() in k.lower()]
        if not hits:
            print("### %-28s not found" % want)
            continue
        for name in hits[:3]:
            rows = sorted(index[name], key=lambda r: (r[3] is None, r[3]))
            print("### %s  (size=%s, %d members)" % (
                name, sizes.get(name, "?"), len(rows)))
            for _struct, _size, member, offset, type_index in rows:
                print("      +0x%-4X %-36s type#%d" % (offset or 0, member, type_index))
            print()


if __name__ == "__main__":
    sys.exit(main(sys.argv))

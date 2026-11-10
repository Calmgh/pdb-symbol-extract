#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Extract public symbols from a PDB into an RVA -> name table.

Usage::

    python pdb_symbols.py target.pdb target.exe [output_prefix]

Outputs::

    <prefix>.tsv        # rva<TAB>size<TAB>tag<TAB>name   (sorted by RVA)
    <prefix>_rpc.txt    subset whose names look like network entry points

The TSV header/column layout is intentionally boring so it drops straight into
``grep``, awk, or a spreadsheet.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pdbsym import MSF, PE
from pdbsym.pub import (DEFAULT_RPC_PATTERN, extract_public_symbols,
                        filter_symbols, write_tsv)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1

    pdb_path, exe_path = argv[1], argv[2]
    prefix = argv[3] if len(argv) > 3 else "symbols"
    pattern = DEFAULT_RPC_PATTERN
    for arg in argv[4:]:
        if arg.startswith("--filter="):
            pattern = re.compile(arg.split("=", 1)[1])

    with PE(exe_path) as pe, MSF(pdb_path) as pdb:
        print("PE sections:")
        for section in pe.sections:
            print("   %-8s VA=%08X vsize=%08X raw=%08X" % (
                section.name, section.va, section.vsize, section.raw_ptr))
        print()

        dbi = pdb.dbi_header()
        print("sym record stream = %s" % (
            -1 if dbi["sym_record_stream"] == 0xFFFF else dbi["sym_record_stream"]))

        last = [0]

        def progress(done, total):
            # Keep the console quiet: one line per ~64 MB of records.
            if done - last[0] > 0x4000000 or done >= total:
                last[0] = done
                sys.stderr.write("   ... %d / %d bytes\n" % (done, total))

        symbols = extract_public_symbols(pdb, pe, progress=progress)
        section_hist = _section_histogram(symbols, pe)

    if not symbols:
        print("\nNo S_PUB32 symbols found.")
        print("The PDB may be stripped, or the sym record stream index is wrong.")
        return 2

    rpc = filter_symbols(symbols, pattern)

    write_tsv(prefix + ".tsv", symbols)
    with open(prefix + "_rpc.txt", "w", encoding="utf-8") as f:
        for rva, name in sorted(rpc):
            f.write("0x%08X\t%s\n" % (rva, name))

    print("\npublic symbols : %d" % len(symbols))
    print("filtered       : %d  (%s)" % (len(rpc), pattern.pattern))
    print("sections used  : %s" % section_hist)
    print("written        : %s.tsv, %s_rpc.txt" % (prefix, prefix))
    return 0


def _section_histogram(symbols, pe):
    counts = {}
    for rva, _name in symbols:
        section = pe.section_for_rva(rva)
        key = section.name if section else "?"
        counts[key] = counts.get(key, 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:4]
    return ", ".join("%s=%d" % kv for kv in top)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

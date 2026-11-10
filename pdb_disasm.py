#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Disassemble a few instructions at an RVA, with symbol and IAT annotation.

Usage::

    python pdb_disasm.py target.exe 0x1A2B30 [count] [--sym=symbols.tsv]

Requires ``capstone`` (``pip install capstone``).

Useful patterns::

    # Is this really the start of a function? (do this before hooking)
    python pdb_disasm.py target.exe 0x1A2B30 12 --check-start

    # What does the code 0x20 bytes before my address look like?
    python pdb_disasm.py target.exe 0x1A2B10 16
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pdbsym import PE
from pdbsym.disasm import disassemble, find_section_span, looks_like_function_start
from pdbsym.errors import PdbFormatError
from pdbsym.pub import read_tsv


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1

    exe_path = argv[1]
    rva = int(argv[2], 16)
    count = 40
    symbols = {}
    check_start = False
    for arg in argv[3:]:
        if arg.startswith("--sym="):
            symbols = read_tsv(arg.split("=", 1)[1])
        elif arg == "--check-start":
            check_start = True
        elif arg.isdigit():
            count = int(arg)

    with PE(exe_path) as pe:
        try:
            rows = disassemble(pe, rva, count=count, symbols=symbols,
                               imports=pe.imports())
        except PdbFormatError as exc:
            print("error: %s" % exc)
            return 2
        section = find_section_span(pe, rva)
        is_start = looks_like_function_start(pe, rva) if check_start else None

        print("file   : %s" % exe_path)
        print("RVA    : 0x%X   VA = 0x%X + 0x%X = 0x%X" % (
            rva, pe.image_base, rva, pe.image_base + rva))
        print("section: %s" % section)

        if rva in symbols:
            print("symbol : %s" % symbols[rva])
        else:
            near = sorted(symbols, key=lambda k: abs(k - rva))[:3]
            if near:
                print("symbol : (no exact match) nearest:")
                for k in near:
                    print("         0x%X  %s  (delta %+d)" % (k, symbols[k], k - rva))
            else:
                print("symbol : (no symbol table loaded)")

        if is_start is not None:
            print("prologue: %s" % (
                "looks like a function entry" if is_start
                else "NOT a clean function entry -- hooks here will likely crash"))
        print("-" * 94)

    for ins_rva, raw, asm, note in rows:
        print("  0x%08X  %-26s %-40s %s" % (ins_rva, raw, asm, note))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

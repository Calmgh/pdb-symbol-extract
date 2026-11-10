#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""pdbsym -- read Windows PDB files in pure Python.

No IDA, no ``llvm-pdbutil``, no ``cvdump``, no ``dumpbin``, no DIA SDK.

What you get out of a PDB:

* :class:`pdbsym.msf.MSF` -- the container (streams / blocks)
* :func:`pdbsym.pub.extract_public_symbols` -- ``S_PUB32`` symbols as RVA
* :class:`pdbsym.tpi.TPI` -- type records, i.e. struct member offsets
* :class:`pdbsym.pe.PE` -- the exe side (sections / imports) needed for RVA math

Example::

    from pdbsym import MSF, PE, extract_public_symbols

    with MSF("target.pdb") as pdb, PE("target.exe") as pe:
        print(pdb.info_stream())
        for rva, name in extract_public_symbols(pdb, pe):
            print(hex(rva), name)
"""

from .errors import PdbFormatError
from .msf import MSF
from .pe import PE
from .pub import extract_public_symbols, iter_public_symbols
from .tpi import TPI

__version__ = "1.0.0"

__all__ = [
    "MSF",
    "PE",
    "TPI",
    "PdbFormatError",
    "extract_public_symbols",
    "iter_public_symbols",
    "__version__",
]

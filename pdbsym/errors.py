#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Exceptions raised by :mod:`pdbsym`."""


class PdbFormatError(ValueError):
    """The file does not follow the MSF 7.0 / CodeView layout we expect.

    Raised instead of ``struct.error`` so callers can distinguish "this is not
    a PDB we understand" from "I passed a bad argument".
    """

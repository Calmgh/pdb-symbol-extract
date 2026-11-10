#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests run against a hand-built fixture PDB/PE pair (see make_fixture.py).

Run with::

    python -m unittest discover -s tests -v

These do not prove the parser handles every quirky real-world PDB, but they do
pin down the layout assumptions the whole tool rests on: MSF block lists, the
DBI symbol-record pointer, S_PUB32 offsets, and the four TPI traps.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import make_fixture  # noqa: E402
from pdbsym import MSF, PE, TPI  # noqa: E402
from pdbsym.pub import extract_public_symbols, filter_symbols  # noqa: E402


class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pdb_path, cls.exe_path = make_fixture.write_fixtures(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()


class TestContainer(FixtureCase):
    def test_superblock(self):
        with MSF(self.pdb_path) as pdb:
            self.assertEqual(pdb.block_size, make_fixture.BLOCK_SIZE)
            self.assertEqual(pdb.num_streams, make_fixture.NUM_STREAMS)
            self.assertEqual(pdb.check(), [])

    def test_stream_sizes(self):
        with MSF(self.pdb_path) as pdb:
            self.assertEqual(pdb.stream_sizes[0], 0)
            self.assertEqual(pdb.stream_sizes[1], 28)
            self.assertGreater(pdb.stream_sizes[make_fixture.SYM_STREAM], 0)

    def test_info_stream_identity(self):
        with MSF(self.pdb_path) as pdb:
            _version, _signature, age, guid = pdb.info_stream()
            self.assertEqual(age, make_fixture.AGE)
            self.assertEqual(guid, make_fixture.GUID)

    def test_dbi_header(self):
        with MSF(self.pdb_path) as pdb:
            dbi = pdb.dbi_header()
            self.assertEqual(dbi["version_signature"], 0xFFFFFFFF)
            self.assertEqual(dbi["version_header"], 19990903)
            self.assertEqual(dbi["sym_record_stream"], make_fixture.SYM_STREAM)
            self.assertEqual(dbi["machine"], 0x8664)


class TestPublicSymbols(FixtureCase):
    def test_extracts_both_symbols(self):
        with MSF(self.pdb_path) as pdb, PE(self.exe_path) as pe:
            symbols = extract_public_symbols(pdb, pe)
        self.assertEqual(len(symbols), 2)
        self.assertEqual(symbols[0][0], make_fixture.TEXT_VA + 0x100)
        self.assertEqual(symbols[1][0], make_fixture.TEXT_VA + 0x200)
        self.assertIn("?ServerFire@Test@@", symbols[0][1])

    def test_filter_matches_network_names(self):
        with MSF(self.pdb_path) as pdb, PE(self.exe_path) as pe:
            symbols = extract_public_symbols(pdb, pe)
        filtered = filter_symbols(symbols)
        # Both fixture names look like network entry points: ServerFire and
        # ClientMove (Client[A-Z]).
        self.assertEqual(len(filtered), 2)
        self.assertTrue(any("ServerFire" in name for _rva, name in filtered))

    def test_rva_lands_in_text_section(self):
        with MSF(self.pdb_path) as pdb, PE(self.exe_path) as pe:
            for rva, _name in extract_public_symbols(pdb, pe):
                section = pe.section_for_rva(rva)
                self.assertIsNotNone(section)
                self.assertEqual(section.name, ".text")


class TestTypes(FixtureCase):
    def test_class_and_member(self):
        with MSF(self.pdb_path) as pdb:
            tpi = TPI(pdb.stream(make_fixture.TPI_STREAM))
        self.assertEqual(len(tpi.records), 2)

        members, structs = tpi.collect_structs(["APawn"])
        self.assertEqual(len(structs), 1)
        name, size, member_count, base_count = structs[0]
        self.assertEqual(name, "APawn")
        self.assertEqual(size, 0x20)
        self.assertEqual(member_count, 1)
        self.assertEqual(base_count, 0)

        struct, _size, member, offset, _type = members[0]
        self.assertEqual(struct, "APawn")
        self.assertEqual(member, "Health")
        self.assertEqual(offset, 0x10)


class TestPE(FixtureCase):
    def test_sections(self):
        with PE(self.exe_path) as pe:
            self.assertTrue(pe.is_64)
            self.assertEqual(len(pe.sections), 1)
            self.assertEqual(pe.sections[0].name, ".text")

    def test_rva_to_offset(self):
        with PE(self.exe_path) as pe:
            self.assertEqual(pe.rva_to_offset(make_fixture.TEXT_VA), 0x200)
            self.assertIsNone(pe.rva_to_offset(0x900000))

    def test_codeview_matches_pdb(self):
        with PE(self.exe_path) as pe:
            cv = pe.codeview()
        self.assertIsNotNone(cv)
        self.assertEqual(cv.guid, make_fixture.GUID)
        self.assertEqual(cv.age, make_fixture.AGE)
        self.assertEqual(cv.pdb_path, "target.pdb")

    def test_function_entry_heuristic(self):
        from pdbsym.disasm import looks_like_function_start
        with PE(self.exe_path) as pe:
            self.assertTrue(looks_like_function_start(pe, make_fixture.TEXT_VA + 0x100))
            # Interior of the function: no prologue, no preceding terminator.
            self.assertFalse(looks_like_function_start(pe, make_fixture.TEXT_VA + 0x102))


class TestCheckCommand(FixtureCase):
    def test_same_link_returns_zero(self):
        import pdb_check
        self.assertEqual(pdb_check.main(["pdb_check.py", self.pdb_path, self.exe_path]), 0)

    def test_age_mismatch_returns_one(self):
        import pdb_check
        with open(self.pdb_path, "rb") as f:
            data = bytearray(f.read())
        # Info stream lives in block 2; age sits 8 bytes into it.
        age_offset = 2 * make_fixture.BLOCK_SIZE + 8
        data[age_offset:age_offset + 4] = (make_fixture.AGE + 60).to_bytes(4, "little")
        with tempfile.NamedTemporaryFile(suffix=".pdb", delete=False) as f:
            f.write(bytes(data))
            patched = f.name
        try:
            self.assertEqual(pdb_check.main(["pdb_check.py", patched, self.exe_path]), 1)
        finally:
            os.unlink(patched)


if __name__ == "__main__":
    unittest.main()

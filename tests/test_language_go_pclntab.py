"""
Unit tests for floss.language.go.pclntab

Each version specific test builds a minimal pclntab blob and
verifies that the parser returns the expected name -> VA mapping. This lets us
validate the parser logic without needing a real Go binary

The integration test (test_parse_pclntab_real_binary) is skipped unless a
pre-built Go binary exists at the expected fixture path
"""

import types
import struct
import pathlib
import unittest.mock as mock

import pytest

from floss.language.go.pclntab import (
    MAGIC_V12,
    ALL_MAGICS,
    MAGIC_V116,
    MAGIC_V118,
    MAGIC_V120,
    _parse_v12,
    _parse_v116,
    _parse_v118,
    parse_pclntab,
    _locate_pclntab,
    find_runtime_functions,
)

### Helpers to build minimal in-memory pclntab blobs


def _build_v12(ptrsize: int, funcs: dict) -> bytes:
    """
    Build a minimal Go 1.2-style pclntab with the given {name: va} entries

    Layout:
        [magic:6][quantum:1][ptrsize:1]
        nfunctab : uint(ptrsize)
        functab  : nfunctab (va:P, data_off:P)  +  sentinel (va:P)
        Func structs  : for each func: [entry:P][nameoff:4]
        names    : null-terminated strings
    """
    p = "<I" if ptrsize == 4 else "<Q"

    hdr = MAGIC_V12 + bytes([1, ptrsize])  # magic + quantum=1 + ptrsize

    nfunctab = len(funcs)
    nfunctab_bytes = struct.pack(p, nfunctab)

    # We will compute offsets after we know the layout
    # Pass 1: figure out where everything lands
    functab_size = (nfunctab * 2 + 1) * ptrsize  # entries + sentinel_va
    # NB: sentinel only has a va, no data_off   ← but Go uses (n*2+1)*ptrsize
    # which means: n pairs of (va,off) + 1 lone va = n*2*ptrsize + ptrsize

    header_end = 8 + ptrsize + functab_size  # end of header + nfunctab + functab
    func_struct_base = header_end  # Func structs start here

    # Each Func struct: entry(P) + nameoff(4)
    func_struct_size = ptrsize + 4
    name_base = func_struct_base + nfunctab * func_struct_size

    names_list = list(funcs.keys())
    name_offsets = {}
    cur = name_base
    for name in names_list:
        name_offsets[name] = cur
        cur += len(name) + 1  # +1 for null terminator

    # Pass 2: build the bytes
    buf = bytearray()
    buf += hdr
    buf += nfunctab_bytes

    # functab: pairs + sentinel
    for i, name in enumerate(names_list):
        va = funcs[name]
        data_off = func_struct_base + i * func_struct_size
        buf += struct.pack(p, va)
        buf += struct.pack(p, data_off)
    # sentinel
    buf += struct.pack(p, max(funcs.values()) + 0x100)

    assert len(buf) == 8 + ptrsize + (nfunctab * 2 + 1) * ptrsize

    # Func structs
    for name in names_list:
        va = funcs[name]
        buf += struct.pack(p, va)  # entry
        buf += struct.pack("<I", name_offsets[name])  # nameoff (into whole pclntab)

    # Names
    for name in names_list:
        buf += name.encode() + b"\x00"

    return bytes(buf)


def _build_v116(ptrsize: int, funcs: dict) -> bytes:
    """
    Build a minimal Go 1.16-style pclntab

    pcHeader after 8-byte magic/quantum/ptrsize:
        [nfunctab:P][nfiletab:P][funcnameOff:P][cuOff:P][filetabOff:P][pctabOff:P][pclnOff:P]

    pclntab[pclnOff] = functab + Func structs (funcdata region)
    pclntab[funcnameOff] = funcnametab
    """
    p = "<I" if ptrsize == 4 else "<Q"

    nfunctab = len(funcs)
    names_list = list(funcs.keys())

    # Build funcnametab: concatenated null-terminated names
    funcnametab = bytearray()
    name_offsets = {}
    for name in names_list:
        name_offsets[name] = len(funcnametab)
        funcnametab += name.encode() + b"\x00"
    funcnametab_bytes = bytes(funcnametab)

    # Header size: 8 (magic/q/p) + 7 * ptrsize (nfunc, nfile, 5 offsets)
    header_size = 8 + 7 * ptrsize

    # funcnametab immediately follows header
    funcname_off = header_size

    # pcln (functab/funcdata) follows funcnametab
    pcln_off = funcname_off + len(funcnametab_bytes)

    # functab: (nfunctab*2+1) * ptrsize
    ffs = ptrsize
    functab_size = (nfunctab * 2 + 1) * ffs

    # Func structs follow functab, within funcdata region
    func_struct_base_in_funcdata = functab_size  # offset within funcdata
    func_struct_size = ptrsize + 4  # entry(P) + nameoff(4)

    # Build header
    buf = bytearray()
    buf += MAGIC_V116 + bytes([1, ptrsize])  # 8 bytes
    buf += struct.pack(p, nfunctab)  # nfunctab
    buf += struct.pack(p, 0)  # nfiletab
    buf += struct.pack(p, funcname_off)  # funcnameOffset
    buf += struct.pack(p, 0)  # cuOffset (unused in our test)
    buf += struct.pack(p, 0)  # filetabOffset
    buf += struct.pack(p, 0)  # pctabOffset
    buf += struct.pack(p, pcln_off)  # pclnOffset

    assert len(buf) == header_size

    # funcnametab
    buf += funcnametab_bytes

    # funcdata region starts here (pcln_off)
    funcdata_start = len(buf)
    assert funcdata_start == pcln_off

    # functab entries
    for i, name in enumerate(names_list):
        va = funcs[name]
        funcdata_rel = func_struct_base_in_funcdata + i * func_struct_size
        buf += struct.pack(p, va)  # va
        buf += struct.pack(p, funcdata_rel)  # funcdata offset within funcdata region
    # sentinel
    buf += struct.pack(p, max(funcs.values()) + 0x100)

    # Func structs
    for name in names_list:
        va = funcs[name]
        buf += struct.pack(p, va)  # entry
        buf += struct.pack("<I", name_offsets[name])  # nameoff into funcnametab

    return bytes(buf)


def _build_v118(ptrsize: int, funcs: dict, magic: bytes = MAGIC_V118) -> bytes:
    """
    Build a minimal Go 1.18-style pclntab

    pcHeader after 8-byte magic/quantum/ptrsize:
        [nfunctab:P][nfiletab:P][textStart:P][funcnameOff:P][cuOff:P]
        [filetabOff:P][pctabOff:P][pclnOff:P]

    All functab entries are uint32 (NOT pointer-sized).
    func_va = textStart + pc_off_uint32.
    """
    p = "<I" if ptrsize == 4 else "<Q"

    TEXT_START = 0x401000
    nfunctab = len(funcs)
    names_list = list(funcs.keys())

    # funcnametab
    funcnametab = bytearray()
    name_offsets = {}
    for name in names_list:
        name_offsets[name] = len(funcnametab)
        funcnametab += name.encode() + b"\x00"
    funcnametab_bytes = bytes(funcnametab)

    # Header: 8 + 8*ptrsize
    header_size = 8 + 8 * ptrsize
    funcname_off = header_size
    pcln_off = funcname_off + len(funcnametab_bytes)

    ffs = 4  # uint32 for 1.18
    functab_size = (nfunctab * 2 + 1) * ffs
    func_struct_base_in_funcdata = functab_size
    func_struct_size = 4 + 4  # entry(uint32) + nameoff(uint32)

    buf = bytearray()
    buf += magic + bytes([1, ptrsize])  # 8 bytes
    buf += struct.pack(p, nfunctab)  # nfunctab
    buf += struct.pack(p, 0)  # nfiletab
    buf += struct.pack(p, TEXT_START)  # textStart
    buf += struct.pack(p, funcname_off)  # funcnameOffset
    buf += struct.pack(p, 0)  # cuOffset
    buf += struct.pack(p, 0)  # filetabOffset
    buf += struct.pack(p, 0)  # pctabOffset
    buf += struct.pack(p, pcln_off)  # pclnOffset

    assert len(buf) == header_size

    buf += funcnametab_bytes

    # functab
    for i, name in enumerate(names_list):
        va = funcs[name]
        pc_off = va - TEXT_START
        funcdata_rel = func_struct_base_in_funcdata + i * func_struct_size
        buf += struct.pack("<I", pc_off)  # pc_off from textStart
        buf += struct.pack("<I", funcdata_rel)  # funcdata offset

    # sentinel
    sentinel_pc_off = max(v - TEXT_START for v in funcs.values()) + 0x100
    buf += struct.pack("<I", sentinel_pc_off)

    # Func structs
    for name in names_list:
        va = funcs[name]
        pc_off = va - TEXT_START
        buf += struct.pack("<I", pc_off)  # entry
        buf += struct.pack("<I", name_offsets[name])  # nameoff

    return bytes(buf)


### Unit tests: parser internals


class TestParseV12:
    def test_single_function_ptrsize8(self):
        data = _build_v12(8, {"runtime.slicebytetostring": 0x401000})
        result = _parse_v12(data, 8)
        assert result == {"runtime.slicebytetostring": 0x401000}

    def test_single_function_ptrsize4(self):
        data = _build_v12(4, {"runtime.slicebytetostring": 0x401000})
        result = _parse_v12(data, 4)
        assert result == {"runtime.slicebytetostring": 0x401000}

    def test_multiple_functions(self):
        funcs = {
            "runtime.slicebytetostring": 0x401000,
            "runtime.memmove": 0x402000,
            "main.main": 0x403000,
        }
        data = _build_v12(8, funcs)
        result = _parse_v12(data, 8)
        assert result == funcs

    def test_empty_data_returns_empty(self):
        assert _parse_v12(b"", 8) == {}

    def test_truncated_data_returns_partial(self):
        data = _build_v12(8, {"runtime.slicebytetostring": 0x401000})
        # Truncate the name bytes — should return empty (name not readable)
        result = _parse_v12(data[:40], 8)
        assert isinstance(result, dict)  # no crash


class TestParseV116:
    def test_single_function_ptrsize8(self):
        data = _build_v116(8, {"runtime.slicebytetostring": 0x401000})
        result = _parse_v116(data, 8)
        assert result == {"runtime.slicebytetostring": 0x401000}

    def test_single_function_ptrsize4(self):
        data = _build_v116(4, {"runtime.slicebytetostring": 0x401000})
        result = _parse_v116(data, 4)
        assert result == {"runtime.slicebytetostring": 0x401000}

    def test_multiple_functions(self):
        funcs = {
            "runtime.slicebytetostring": 0x401000,
            "runtime.memmove": 0x402000,
            "main.main": 0x403000,
        }
        data = _build_v116(8, funcs)
        result = _parse_v116(data, 8)
        assert result == funcs

    def test_empty_data_returns_empty(self):
        assert _parse_v116(b"", 8) == {}


class TestParseV118:
    def test_single_function_v118_ptrsize8(self):
        data = _build_v118(8, {"runtime.slicebytetostring": 0x401500})
        result = _parse_v118(data, 8)
        assert result == {"runtime.slicebytetostring": 0x401500}

    def test_single_function_ptrsize4(self):
        data = _build_v118(4, {"runtime.slicebytetostring": 0x401500})
        result = _parse_v118(data, 4)
        assert result == {"runtime.slicebytetostring": 0x401500}

    def test_v120_magic(self):
        # 1.20 uses same layout as 1.18, only magic differs
        data = _build_v118(8, {"runtime.slicebytetostring": 0x401500}, magic=MAGIC_V120)
        result = _parse_v118(data, 8)
        assert result == {"runtime.slicebytetostring": 0x401500}

    def test_multiple_functions(self):
        TEXT_START = 0x401000
        funcs = {
            "runtime.slicebytetostring": TEXT_START + 0x500,
            "runtime.memmove": TEXT_START + 0x1000,
            "main.main": TEXT_START + 0x2000,
        }
        data = _build_v118(8, funcs)
        result = _parse_v118(data, 8)
        assert result == funcs

    def test_empty_data_returns_empty(self):
        assert _parse_v118(b"", 8) == {}


### Unit tests: locate_pclntab via fake PE


def _fake_pe(sections: list) -> mock.MagicMock:
    """
    Build a minimal mock pefile.PE with the given sections
    Each section is a dict with keys: Name (bytes), VirtualAddress (int), data (bytes).
    """
    pe = mock.MagicMock()
    pe.OPTIONAL_HEADER.ImageBase = 0x400000

    fake_sections = []
    for s in sections:
        sec = mock.MagicMock()
        sec.Name = s["Name"]
        sec.VirtualAddress = s["VirtualAddress"]
        sec.get_data.return_value = s["data"]
        fake_sections.append(sec)

    pe.sections = fake_sections
    return pe


class TestLocatePclntab:
    def test_named_section_gopclntab(self):
        pclntab_data = _build_v118(8, {"runtime.foo": 0x401500})
        pe = _fake_pe(
            [
                {"Name": b".gopclntab\x00\x00\x00\x00\x00\x00", "VirtualAddress": 0x5000, "data": pclntab_data},
            ]
        )
        va, data = _locate_pclntab(pe)
        assert data[:6] == MAGIC_V118
        assert va == 0x400000 + 0x5000

    def test_magic_scan_fallback(self):
        pclntab_data = _build_v118(8, {"runtime.foo": 0x401500})
        # Section name does NOT match — simulates stripped/obfuscated binary
        pe = _fake_pe(
            [
                {"Name": b".data\x00\x00\x00\x00\x00\x00\x00\x00\x00", "VirtualAddress": 0x5000, "data": pclntab_data},
            ]
        )
        va, data = _locate_pclntab(pe)
        assert data[:6] == MAGIC_V118

    def test_not_found_raises(self):
        pe = _fake_pe(
            [
                {"Name": b".text\x00\x00\x00\x00\x00\x00\x00\x00\x00", "VirtualAddress": 0x1000, "data": b"\x00" * 64},
            ]
        )
        with pytest.raises(ValueError, match="pclntab not found"):
            _locate_pclntab(pe)


class TestParsePclntab:
    """End-to-end tests through the public parse_pclntab() API using mock PEs"""

    def _make_pe(self, pclntab_data: bytes):
        return _fake_pe(
            [
                {"Name": b".gopclntab\x00\x00\x00\x00\x00\x00", "VirtualAddress": 0x5000, "data": pclntab_data},
            ]
        )

    def test_v12(self):
        data = _build_v12(8, {"runtime.slicebytetostring": 0x401000})
        pe = self._make_pe(data)
        result = parse_pclntab(pe)
        assert "runtime.slicebytetostring" in result
        assert result["runtime.slicebytetostring"] == 0x401000

    def test_v116(self):
        data = _build_v116(8, {"runtime.slicebytetostring": 0x401000})
        pe = self._make_pe(data)
        result = parse_pclntab(pe)
        assert result.get("runtime.slicebytetostring") == 0x401000

    def test_v118(self):
        data = _build_v118(8, {"runtime.slicebytetostring": 0x401500})
        pe = self._make_pe(data)
        result = parse_pclntab(pe)
        assert result.get("runtime.slicebytetostring") == 0x401500

    def test_v120(self):
        data = _build_v118(8, {"runtime.slicebytetostring": 0x401500}, magic=MAGIC_V120)
        pe = self._make_pe(data)
        result = parse_pclntab(pe)
        assert result.get("runtime.slicebytetostring") == 0x401500

    def test_missing_pclntab_returns_empty(self):
        pe = _fake_pe(
            [
                {"Name": b".text\x00\x00\x00\x00\x00\x00\x00\x00\x00", "VirtualAddress": 0x1000, "data": b"\x00" * 64},
            ]
        )
        result = parse_pclntab(pe)
        assert result == {}


class TestFindRuntimeFunctions:
    def test_find_slicebytetostring(self):
        funcs = {
            "runtime.slicebytetostring": 0x401000,
            "runtime.memmove": 0x402000,
            "main.main": 0x403000,
        }
        data = _build_v118(8, funcs)
        pe = _fake_pe(
            [
                {"Name": b".gopclntab\x00\x00\x00\x00\x00\x00", "VirtualAddress": 0x5000, "data": data},
            ]
        )
        result = find_runtime_functions(pe, ("slicebytetostring",))
        assert "runtime.slicebytetostring" in result
        assert result["runtime.slicebytetostring"] == 0x401000
        assert "runtime.memmove" not in result

    def test_case_insensitive(self):
        data = _build_v118(8, {"runtime.SliceByteToString": 0x401000})
        pe = _fake_pe(
            [
                {"Name": b".gopclntab\x00\x00\x00\x00\x00\x00", "VirtualAddress": 0x5000, "data": data},
            ]
        )
        result = find_runtime_functions(pe, ("slicebytetostring",))
        assert "runtime.SliceByteToString" in result

    def test_no_match_returns_empty(self):
        data = _build_v118(8, {"runtime.memmove": 0x401000})
        pe = _fake_pe(
            [
                {"Name": b".gopclntab\x00\x00\x00\x00\x00\x00", "VirtualAddress": 0x5000, "data": data},
            ]
        )
        result = find_runtime_functions(pe, ("slicebytetostring",))
        assert result == {}


# Integration test: real Go binary fixture

_FIXTURE_DIR = pathlib.Path(__file__).parent / "data" / "language" / "go"


def _collect_go_fixtures():
    if not _FIXTURE_DIR.exists():
        return []
    exts = (".exe", ".exe_", "")
    return [p for p in _FIXTURE_DIR.rglob("*") if p.is_file() and (p.suffix in exts or p.name.endswith(".exe_"))]


@pytest.mark.parametrize("fixture_path", _collect_go_fixtures())
def test_parse_pclntab_real_binary(fixture_path: pathlib.Path):
    """
    parse_pclntab on every Go binary fixture in the test data
    We only require that the call does not raise and returns a dict
    """
    import pefile

    try:
        pe = pefile.PE(str(fixture_path), fast_load=True)
    except Exception:
        pytest.skip(f"pefile could not open {fixture_path}")

    result = parse_pclntab(pe)
    assert isinstance(result, dict)
    # For real Go binaries we expect at least some functions
    if result:
        assert any(
            "runtime" in name or "main" in name for name in result.keys()
        ), f"No runtime/main functions found in {fixture_path}: got {list(result.keys())[:5]}"

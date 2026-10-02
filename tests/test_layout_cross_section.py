from pathlib import Path

import pytest

from floss.layout import xor_static, compute_layout
from floss.ranges import Slice
from floss.layout.base import PELayout, SegmentLayout
from floss.layout.extract import collect_strings, extract_strings

CD = Path(__file__).resolve().parent
DOTNET_HELLO = CD / "data" / "language" / "dotnet" / "dotnet-hello" / "bin" / "dotnet-hello.exe"


def _node(layout, name):
    if layout.name == name:
        return layout
    for child in layout.children:
        found = _node(child, name)
        if found is not None:
            return found
    return None


def _strings(layout):
    return [(s.slice.range.offset, s.string, s.encoding) for s in collect_strings(layout)]  # type: ignore


def test_string_across_section_boundary_is_whole():
    # dotnet-hello.exe: .text is [0x200, 0x600), .rsrc is [0x600, 0xc00), .reloc starts at 0xc00
    buf = bytearray(DOTNET_HELLO.read_bytes())
    buf[0x5F0 : 0x5F0 + 33] = b"FLOSS_CROSS_SECTION_BUG_1_STRING!"
    buf[0xBFD : 0xBFD + 5] = b"EDGES"

    layout = compute_layout(Slice.from_bytes(bytes(buf)))
    layout.extract_strings(5)

    assert _strings(_node(layout, ".text")).count((0x5F0, "FLOSS_CROSS_SECTION_BUG_1_STRING!", "ascii")) == 1
    assert _strings(_node(layout, ".rsrc")).count((0xBFD, "EDGES", "ascii")) == 1
    assert "ION_BUG_1_STRING!" not in [s for _, s, _ in _strings(layout)]


@pytest.mark.parametrize(
    "path",
    [
        CD / "data" / "pma" / "Practical Malware Analysis Lab 01-01.exe_",
        CD / "data" / "elf" / "ls",
        CD / "data" / "macho" / "true",
    ],
)
def test_layout_strings_equal_whole_file_extraction(path):
    buf = bytearray(path.read_bytes())
    boundary = compute_layout(Slice.from_bytes(bytes(buf))).children[-1].offset
    buf[boundary - 10 : boundary - 10 + 33] = b"FLOSS_CROSS_SECTION_BUG_1_STRING!"

    layout = compute_layout(Slice.from_bytes(bytes(buf)))
    layout.extract_strings(6)

    expected = [(s.slice.range.offset, s.string, s.encoding) for s in extract_strings(Slice.from_bytes(bytes(buf)), 6)]
    assert sorted(_strings(layout)) == sorted(expected)


def test_xor_encoded_nested_layout_extracts_decoded_strings():
    encoded = xor_static(DOTNET_HELLO.read_bytes(), 0x41)
    outer = b"\x00" * 0x100 + encoded + b"\x00" * 0x100

    root = SegmentLayout(name="root", slice=Slice.from_bytes(outer))
    nested = compute_layout(root.slice.slice(0x100, len(encoded)))
    assert isinstance(nested, PELayout) and nested.xor_key == 0x41
    root.add_child(nested)
    root.extract_strings(4)

    nested_strings = [s for _, s, _ in _strings(nested)]
    assert "!This program cannot be run in DOS mode." in nested_strings
    assert "v4.0.30319" in nested_strings
    assert root.strings == []

from pathlib import Path

import pytest

from floss.layout import xor_static, compute_layout
from floss.ranges import Slice
from floss.layout.base import PELayout, SegmentLayout
from floss.layout.extract import collect_strings, extract_strings

CD = Path(__file__).resolve().parent
DOTNET_HELLO = CD / "data" / "language" / "dotnet" / "dotnet-hello" / "bin" / "dotnet-hello.exe"


def _offset(s) -> int:
    return s.slice.range.offset


def _key(s) -> tuple:
    return (s.slice.range.offset, s.string, s.encoding)


def test_string_across_section_boundary_is_whole():
    buf = bytearray(0x300)
    buf[0xF8:0x104] = b"CROSSING_STR"
    buf[0x1FD:0x202] = b"SPLIT"

    root = SegmentLayout(name="root", slice=Slice.from_bytes(bytes(buf)))
    child1 = SegmentLayout(name="child1", slice=root.slice.slice(0x000, 0x100))
    child2 = SegmentLayout(name="child2", slice=root.slice.slice(0x100, 0x100))
    root.add_child(child1)
    root.add_child(child2)

    root.extract_strings(4)

    assert any(s.string == "CROSSING_STR" and _offset(s) == 0xF8 for s in child1.strings)
    assert any(s.string == "SPLIT" and _offset(s) == 0x1FD for s in child2.strings)
    assert not any(s.string in ("CROSSING", "_STR", "SPL", "IT") for s in collect_strings(root))
    assert root.strings == []


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

    expected = sorted(_key(s) for s in extract_strings(Slice.from_bytes(bytes(buf)), 6))
    assert sorted(_key(s) for s in collect_strings(layout)) == expected


def test_xor_encoded_nested_layout_extracts_decoded_strings():
    encoded = xor_static(DOTNET_HELLO.read_bytes(), 0x41)
    outer = b"\x00" * 0x100 + encoded + b"\x00" * 0x100

    root = SegmentLayout(name="root", slice=Slice.from_bytes(outer))
    nested = compute_layout(root.slice.slice(0x100, len(encoded)))
    assert isinstance(nested, PELayout) and nested.xor_key == 0x41
    root.add_child(nested)
    root.extract_strings(4)

    assert any(s.string == "!This program cannot be run in DOS mode." for s in collect_strings(nested))
    assert any(s.string == "v4.0.30319" for s in collect_strings(nested))
    assert root.strings == []

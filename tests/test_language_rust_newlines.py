import pathlib

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.rust.extract import split_strings, strip_newlines, extract_rust_strings


def test_split_after_newline_keeps_byte_offsets():
    # "Hello, world!\n" is followed directly by another literal; a cross-reference points at
    # the second one. Splitting must happen on the text as it is in the file, newline included.
    strings = [StaticString(string="Hello, world!\nalready destroyed", offset=0x1000, encoding=StringEncoding.UTF8)]
    split_strings(strings, 0x1000 + len("Hello, world!\n"), 6)
    assert sorted(strip_newlines(strings, 6), key=lambda s: s.offset) == [
        StaticString(string="Hello, world!", offset=0x1000, encoding=StringEncoding.UTF8),
        StaticString(string="already destroyed", offset=0x100E, encoding=StringEncoding.UTF8),
    ]


def test_strip_newlines_applies_min_length():
    strings = [StaticString(string="\n\nabcde", offset=0, encoding=StringEncoding.UTF8)]
    assert strip_newlines(strings, 6) == []
    assert strip_newlines(strings, 5) == [StaticString(string="abcde", offset=0, encoding=StringEncoding.UTF8)]


@pytest.fixture(scope="module")
def rust_strings64():
    path = pathlib.Path(__file__).parent / "data" / "language" / "rust" / "rust-hello" / "bin" / "rust-hello64.exe"
    return extract_rust_strings(path, 6)


@pytest.mark.parametrize(
    "string,offset",
    [
        # gimli's DwarfFileType / Format names follow a "...\n" literal in the same run; with the
        # newline removed before splitting, these came out as "rf32Dwa", "rf64Enc", "odingadd"
        pytest.param("Dwarf32", 0xC9E6F),
        pytest.param("Dwarf64", 0xC9E76),
        pytest.param("Encoding", 0xC9E7D),
        # "thread '" ... "' has overflowed its stack\n": the quote ended up on the wrong side
        pytest.param("' has overflowed its stack", 0xC1519),
    ],
)
def test_split_offsets_after_newlines(rust_strings64, string, offset):
    assert StaticString(string=string, offset=offset, encoding=StringEncoding.UTF8) in rust_strings64

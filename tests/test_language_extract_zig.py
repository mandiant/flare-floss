import pathlib
from unittest.mock import Mock

import pefile
import pytest

from floss.results import Analysis, StaticString, StringEncoding
from floss.pipeline import Options, analyze
from floss.language.utils import StructString
from floss.language.zig.extract import extract_zig_strings, get_string_blob_strings


@pytest.fixture(scope="module")
def zig_strings32():
    n = 6
    path = (
        pathlib.Path(__file__).parent
        / "data"
        / "language"
        / "zig"
        / "zig-hello"
        / "bin"
        / "zig-hello.exe"
    )
    return extract_zig_strings(path, n)


@pytest.fixture(scope="module")
def zig_strings64():
    n = 6
    path = (
        pathlib.Path(__file__).parent
        / "data"
        / "language"
        / "zig"
        / "zig-hello"
        / "bin"
        / "zig-hello64.exe"
    )
    return extract_zig_strings(path, n)


@pytest.fixture(scope="module")
def zig_slice_strings32():
    n = 6
    path = (
        pathlib.Path(__file__).parent
        / "data"
        / "language"
        / "zig"
        / "zig-slices"
        / "bin"
        / "zig-slices.exe"
    )
    return extract_zig_strings(path, n)


@pytest.fixture(scope="module")
def zig_slice_strings64():
    n = 6
    path = (
        pathlib.Path(__file__).parent
        / "data"
        / "language"
        / "zig"
        / "zig-slices"
        / "bin"
        / "zig-slices64.exe"
    )
    return extract_zig_strings(path, n)


def test_zig_extraction_runs_in_pipeline():
    path = pathlib.Path(__file__).parent / "data/language/zig/zig-hello/bin/zig-hello64.exe"
    results = analyze(
        Options(
            sample=path,
            min_length=4,
            analysis=Analysis(
                enable_stack_strings=False,
                enable_tight_strings=False,
                enable_decoded_strings=False,
                enable_layout=False,
                enable_tags=False,
            ),
        )
    )

    assert results is not None
    assert results.metadata.language == "zig"
    assert any(string.string == "Hello, world!" for string in results.strings.language_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,zig_strings",
    [
        pytest.param("Hello, world!", 0x19CA5C, StringEncoding.UTF8, "zig_strings32"),
        # .rdata:0000000000183918 48 65 6C 6C 6F 2C aHelloWorldNoAd db 'Hello, world!',0Ah
        pytest.param("Hello, world!", 0x182D18, StringEncoding.UTF8, "zig_strings64"),
        # .rdata:0000000000183926 20 28 6E 6F 20 61…                db ' (no address available)',0Ah
        pytest.param(
            " (no address available)", 0x182D26, StringEncoding.UTF8, "zig_strings64"
        ),
    ],
)
def test_data_string_offset(request, string, offset, encoding, zig_strings):
    assert StaticString(
        string=string, offset=offset, encoding=encoding
    ) in request.getfixturevalue(zig_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,zig_strings",
    [
        # .rdata:0000000140183918 48 65 6C 6C 6F 2C aHelloWorldNoAd db 'Hello, world!',0Ah
        pytest.param("Hello, world!", 0x182D18, StringEncoding.UTF8, "zig_strings64"),
        # .text:0000000000005E71 4C 8D 05 33 C5 12                 lea     r8, aStartIndexIsLa ; "start index  is larger than end index d"...
        # .text:0000000000005E78 41 B9 0C 00 00 00                 mov     r9d, 12
        pytest.param("start index ", 0x1317AB, StringEncoding.UTF8, "zig_strings64"),
        pytest.param(
            " is larger than end index ", 0x1317B7, StringEncoding.UTF8, "zig_strings64"
        ),
        pytest.param(
            "invalid enum value", 0x131928, StringEncoding.UTF8, "zig_strings64"
        ),
        pytest.param("slice length '", 0x1323A0, StringEncoding.UTF8, "zig_strings64"),
        pytest.param(
            "' does not divide exactly into destination elements",
            0x1323AE,
            StringEncoding.UTF8,
            "zig_strings64",
        ),
    ],
)
def test_lea_mov(request, string, offset, encoding, zig_strings):
    assert StaticString(
        string=string, offset=offset, encoding=encoding
    ) in request.getfixturevalue(zig_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,zig_strings",
    [
        pytest.param("start index ", 0x151013, StringEncoding.UTF8, "zig_strings32"),
        pytest.param(
            " is larger than end index ", 0x15101F, StringEncoding.UTF8, "zig_strings32"
        ),
        pytest.param("slice length '", 0x151858, StringEncoding.UTF8, "zig_strings32"),
        pytest.param(
            "' does not divide exactly into destination elements",
            0x151866,
            StringEncoding.UTF8,
            "zig_strings32",
        ),
    ],
)
def test_mov_mov(request, string, offset, encoding, zig_strings):
    assert StaticString(
        string=string, offset=offset, encoding=encoding
    ) in request.getfixturevalue(zig_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,zig_strings",
    [
        pytest.param(
            "ZIG_SLICE_ALPHA", 0x19CE14, StringEncoding.UTF8, "zig_slice_strings32"
        ),
        pytest.param(
            "ZIG_SLICE_BRAVO", 0x19CE24, StringEncoding.UTF8, "zig_slice_strings32"
        ),
        pytest.param(
            "ZIG_SLICE_CHARLIE", 0x19CE34, StringEncoding.UTF8, "zig_slice_strings32"
        ),
        pytest.param(
            "ZIG_SLICE_ALPHA", 0x1832D8, StringEncoding.UTF8, "zig_slice_strings64"
        ),
        pytest.param(
            "ZIG_SLICE_BRAVO", 0x1832E8, StringEncoding.UTF8, "zig_slice_strings64"
        ),
        pytest.param(
            "ZIG_SLICE_CHARLIE", 0x1832F8, StringEncoding.UTF8, "zig_slice_strings64"
        ),
    ],
)
def test_slice_boundaries(request, string, offset, encoding, zig_strings):
    assert StaticString(
        string=string, offset=offset, encoding=encoding
    ) in request.getfixturevalue(zig_strings)


@pytest.mark.parametrize("zig_strings", ["zig_slice_strings32", "zig_slice_strings64"])
def test_slice_backing_blob_is_split(request, zig_strings):
    strings = request.getfixturevalue(zig_strings)
    assert all(
        string.string != "ZIG_SLICE_ALPHA|ZIG_SLICE_BRAVO|ZIG_SLICE_CHARLIE"
        for string in strings
    )


@pytest.mark.parametrize(
    "binary_name", ["zig-hello.exe", "zig-hello64.exe"], ids=["i386", "amd64"]
)
def test_extract_zig_strings_respects_minimum_length(binary_name):
    path = (
        pathlib.Path(__file__).parent
        / "data"
        / "language"
        / "zig"
        / "zig-hello"
        / "bin"
        / binary_name
    )
    assert all(len(string.string) >= 20 for string in extract_zig_strings(path, 20))


@pytest.mark.parametrize(
    "min_length,expected",
    [
        (4, [(0x200, "SHORT"), (0x205, "LONGSTRING")]),
        (6, [(0x205, "LONGSTRING")]),
    ],
)
def test_short_slice_preserves_boundary(monkeypatch, min_length, expected):
    data = b"SHORTLONGSTRING"
    section = Mock(
        PointerToRawData=0x200, VirtualAddress=0x1000, SizeOfRawData=len(data)
    )
    section.get_data.return_value = data
    pe = Mock(spec=pefile.PE)
    pe.OPTIONAL_HEADER = Mock(ImageBase=0x400000)
    pe.FILE_HEADER = Mock(Machine=pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"])
    pe.get_data.side_effect = lambda rva, length: data[
        rva - 0x1000 : rva - 0x1000 + length
    ]

    monkeypatch.setattr(
        "floss.language.zig.extract.get_rdata_section", lambda pe: section
    )
    # Only the short slice supplies the boundary; no instruction references help split the blob.
    monkeypatch.setattr(
        "floss.language.zig.extract.get_struct_string_candidates",
        lambda pe: [StructString(address=0x401000, length=5)],
    )
    monkeypatch.setattr("floss.language.zig.extract.find_lea_xrefs", lambda pe: [])

    strings = list(get_string_blob_strings(pe, min_length))

    assert strings == [
        StaticString(string=value, offset=offset, encoding=StringEncoding.UTF8)
        for offset, value in expected
    ]


@pytest.mark.parametrize(
    "data,slices,min_length,expected",
    [
        (b"HELLOWORLD", [(0, 10), (5, 5)], 4, [(0, "HELLOWORLD"), (5, "WORLD")]),
        (b"HELLOWORLD", [(0, 10), (0, 5)], 4, [(0, "HELLOWORLD"), (0, "HELLO")]),
        (b"ABCDEFGHIJKL", [(0, 8), (4, 8)], 4, [(0, "ABCDEFGH"), (4, "EFGHIJKL")]),
        (b"HELLOWORLD", [(0, 10), (5, 5)], 6, [(0, "HELLOWORLD")]),
        (
            "caf\u00e9WORLD".encode("utf-8"),
            [(0, 10), (5, 5)],
            4,
            [(0, "caf\u00e9WORLD"), (5, "WORLD")],
        ),
        (b"HELLO\nWORLD", [(0, 11), (6, 5)], 4, [(0, "HELLOWORLD"), (6, "WORLD")]),
    ],
    ids=[
        "suffix",
        "same-start",
        "partial-overlap",
        "minimum-length",
        "utf8-byte-offset",
        "newline",
    ],
)
def test_overlapping_slices(monkeypatch, data, slices, min_length, expected):
    section = Mock(
        PointerToRawData=0x200, VirtualAddress=0x1000, SizeOfRawData=len(data)
    )
    section.get_data.return_value = data
    pe = Mock(spec=pefile.PE)
    pe.OPTIONAL_HEADER = Mock(ImageBase=0x400000)
    pe.FILE_HEADER = Mock(Machine=pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"])
    pe.get_data.side_effect = lambda rva, length: data[
        rva - 0x1000 : rva - 0x1000 + length
    ]

    monkeypatch.setattr(
        "floss.language.zig.extract.get_rdata_section", lambda pe: section
    )
    monkeypatch.setattr(
        "floss.language.zig.extract.get_struct_string_candidates",
        lambda pe: [
            StructString(address=0x401000 + start, length=length)
            for start, length in slices
        ],
    )
    monkeypatch.setattr("floss.language.zig.extract.find_lea_xrefs", lambda pe: [])

    strings = list(get_string_blob_strings(pe, min_length))

    for offset, value in expected:
        assert (
            StaticString(
                string=value, offset=0x200 + offset, encoding=StringEncoding.UTF8
            )
            in strings
        )
    assert all(len(string.string) >= min_length for string in strings)
    assert len(strings) == len({(s.string, s.offset, s.encoding) for s in strings})

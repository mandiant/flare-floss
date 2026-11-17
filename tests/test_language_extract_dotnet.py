import json
import pathlib

import pytest

import floss.main
from floss.results import StaticString, StringEncoding
from floss.language.dotnet.extract import extract_dotnet_strings, get_static_strings_from_us_heap

CD = pathlib.Path(__file__).resolve().parent
# built from tests/data/language/dotnet/dotnet-hello/hello-world.cs: Console.WriteLine("Hello World!")
DOTNET_HELLO = CD / "data" / "language" / "dotnet" / "dotnet-hello" / "bin" / "dotnet-hello.exe"
RUST_HELLO = CD / "data" / "language" / "rust" / "rust-hello" / "bin" / "rust-hello64.exe"

# the #US heap spans file offsets 0x4dc..0x4f8; heap index 0 is the empty string,
# so the first entry's length byte is at 0x4dd and its characters start at 0x4de
HELLO = StaticString(string="Hello World!", offset=0x4DE, encoding=StringEncoding.UTF16LE)


def test_user_string_literal():
    assert extract_dotnet_strings(DOTNET_HELLO, 4) == [HELLO]


def test_offset_points_at_the_string_bytes():
    buf = DOTNET_HELLO.read_bytes()
    for s in extract_dotnet_strings(DOTNET_HELLO, 1):
        assert buf[s.offset : s.offset + 2 * len(s.string)].decode("utf-16-le") == s.string


def test_min_length():
    assert extract_dotnet_strings(DOTNET_HELLO, len(HELLO.string)) == [HELLO]
    assert extract_dotnet_strings(DOTNET_HELLO, len(HELLO.string) + 1) == []


def test_native_pe_has_no_user_strings():
    assert extract_dotnet_strings(RUST_HELLO, 4) == []
    assert get_static_strings_from_us_heap(RUST_HELLO, [HELLO]) == []


def test_entry_running_past_heap_end(tmp_path):
    # malformed heap found by mutation: the last byte (0x2b) declares a 43-byte entry that is not there
    buf = bytearray(DOTNET_HELLO.read_bytes())
    buf[0x4DC:0x4F8] = bytes.fromhex("0019480065c16c006c006f00200057006f00723f6c0064002100002b")
    sample = tmp_path / "malformed-us-heap.exe"
    sample.write_bytes(bytes(buf))

    strings = extract_dotnet_strings(sample, 1)
    for s in strings:
        assert 0x4DC <= s.offset and s.offset + 2 * len(s.string) <= 0x4F8


@pytest.mark.parametrize(
    "offset,inside",
    [
        pytest.param(0x4DC, True, id="heap-start"),
        pytest.param(0x4F7, True, id="heap-last-byte"),
        pytest.param(0x4DB, False, id="before-heap"),
        pytest.param(0x4F8, False, id="heap-end-exclusive"),
    ],
)
def test_static_strings_from_us_heap(offset, inside):
    s = StaticString(string="x" * 8, offset=offset, encoding=StringEncoding.UTF16LE)
    assert get_static_strings_from_us_heap(DOTNET_HELLO, [s]) == ([s] if inside else [])


def test_main_reports_dotnet_strings(capsys, monkeypatch):
    monkeypatch.setenv("FLOSS_CACHE_ENABLE", "0")
    assert floss.main.main([str(DOTNET_HELLO), "-j"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["metadata"]["language"] == "dotnet"
    assert "Hello World!" in [s["string"] for s in doc["strings"]["language_strings"]]

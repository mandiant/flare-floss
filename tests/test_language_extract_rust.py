import pathlib

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.rust.extract import split_strings, extract_rust_strings


@pytest.fixture(scope="module")
def rust_strings32():
    n = 6
    path = pathlib.Path(__file__).parent / "data" / "language" / "rust" / "rust-hello" / "bin" / "rust-hello.exe"
    return extract_rust_strings(path, n)


@pytest.fixture(scope="module")
def rust_strings64():
    n = 6
    path = pathlib.Path(__file__).parent / "data" / "language" / "rust" / "rust-hello" / "bin" / "rust-hello64.exe"
    return extract_rust_strings(path, n)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        pytest.param("Hello, world!", 0xAD044, StringEncoding.UTF8, "rust_strings32"),
        # .rdata:00000001400BD030 48 65 6C 6C 6F 2C aHelloWorld     db 'Hello, world!',0Ah,0
        # .rdata:00000001400BD03F 00                                align 20h
        # .rdata:00000001400BD040                   ; const ___str_ pieces
        # .rdata:00000001400BD040 30 D0 0B 40 01 00 pieces          ___str_ <offset aHelloWorld, 0Eh>
        # .rdata:00000001400BD040 00 00 00 00                                               ; "Hello, world!\n"
        pytest.param("Hello, world!", 0xBB030, StringEncoding.UTF8, "rust_strings64"),
        # .rdata:00000001400BD050 69 6E 76 61 6C 69 aInvalidArgs    db 'invalid args',0
        # .rdata:00000001400BD05D 00 00 00                          align 20h
        # .rdata:00000001400BD060 50 D0 0B 40 01 00 stru_1400BD060  ___str_ <offset aInvalidArgs, 0Ch>
        # .rdata:00000001400BD060 00 00 00 00                                               ; "invalid args"
        pytest.param("invalid args", 0xBB050, StringEncoding.UTF8, "rust_strings64"),
    ],
)
def test_data_string_offset(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        # .text:0000000140021155 4C 8D 05 2C DA 09 lea     r8, aAccesserror ; "AccessError"
        # .text:000000014002115C 48 8D 74 24 20    lea     rsi, [rsp+38h+var_18]
        # .text:0000000140021161 41 B9 0B 00 00 00 mov     r9d, 11
        pytest.param("AccessError", 0xBCB88, StringEncoding.UTF8, "rust_strings64"),
        pytest.param("already destroyed", 0xBCB93, StringEncoding.UTF8, "rust_strings64"),
    ],
)
def test_lea_mov(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        # .text:0041EF8C 68 50 08 4B 00            push    offset unk_4B0850 ; "AccessError"
        # .text:0041EFB8 68 5B 08 4B 00            push    offset unk_4B085B "already destroyed"
        pytest.param("AccessError", 0xAE850, StringEncoding.UTF8, "rust_strings32"),
        pytest.param("already destroyed", 0xAE85B, StringEncoding.UTF8, "rust_strings32"),
    ],
)
def test_push(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        # .text:0046B04A BA 1A 00 00 00                                mov     edx, 1Ah        ; jumptable 0046A19C case 8752
        # .text:0046B04F B9 A0 C2 4B 00                                mov     ecx, offset unk_4BC2A0
        # .text:0046B054 E9 93 F8 FF FF                                jmp     loc_46A8EC      ; jumptable 0046A1CA case 0
        pytest.param("DW_AT_SUN_return_value_ptr", 0xBA2A0, StringEncoding.UTF8, "rust_strings32"),
        pytest.param("DW_AT_SUN_c_vla", 0xBA2BA, StringEncoding.UTF8, "rust_strings32"),
    ],
)
def test_mov_jmp(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)


def _split_once(s: str, offset: int, split_substr: str, min_length: int = 4):
    """Build a single StaticString, split it at the file offset of ``split_substr``, and
    return the resulting (offset, string) pairs sorted by offset."""
    address = offset + s.encode("utf-8").index(split_substr.encode("utf-8"))
    static_strings = [StaticString(string=s, offset=offset, encoding=StringEncoding.UTF8)]
    split_strings(static_strings, address, min_length)
    return [(ss.offset, ss.string) for ss in sorted(static_strings, key=lambda x: x.offset)]


@pytest.mark.parametrize(
    "s,offset,split_substr,expected",
    [
        # ASCII: byte offset == character index, so this is the pre-existing behavior
        pytest.param("hello_world_foo", 0x1000, "_world_foo", [(0x1000, "hello"), (0x1005, "_world_foo")], id="ascii"),
        # a multi-byte character (é = 2 UTF-8 bytes) before the split point: splitting on the
        # character index would cut one byte late ("café_" / "endpoint" at a drifted offset)
        pytest.param("café_endpoint", 0x1000, "_endpoint", [(0x1000, "café"), (0x1005, "_endpoint")], id="utf8-before"),
        # the split falls past the character count (8) but within the byte length (16): the
        # character-index containment test ended the string early and skipped the split entirely
        pytest.param("€€€€xyzw", 0x2000, "xyzw", [(0x2000, "€€€€"), (0x200C, "xyzw")], id="utf8-past-charcount"),
    ],
)
def test_split_strings_utf8_offsets(s, offset, split_substr, expected):
    # split points are byte offsets into the file while the string is decoded text, so the
    # split must be computed on the UTF-8 bytes (regression test for the char-index bug)
    assert _split_once(s, offset, split_substr) == expected


def test_split_strings_respects_min_length():
    # the leading piece "ab" (2 chars) is shorter than min_length and must be dropped, while
    # the remainder is kept; offsets stay byte-accurate across the multi-byte "é"
    s = "abé_long_enough_tail"
    address = 0x1000 + s.encode("utf-8").index(b"_long_enough_tail")
    static_strings = [StaticString(string=s, offset=0x1000, encoding=StringEncoding.UTF8)]
    split_strings(static_strings, address, min_length=4)
    results = [(ss.offset, ss.string) for ss in static_strings]
    assert (address, "_long_enough_tail") in results
    assert all(len(ss) >= 4 for _, ss in results)

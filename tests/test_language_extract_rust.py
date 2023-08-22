import pathlib

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.rust.extract import extract_rust_strings


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
    ],
)
def test_data_string_offset(request, string, offset, encoding, rust_strings):
    for s in request.getfixturevalue(rust_strings):
        if s.string == "Hello, world!":
            print(s)

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

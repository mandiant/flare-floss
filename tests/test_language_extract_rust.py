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
        # TODO
        #  pytest.param("hello world", 0xA03E1, StringEncoding.UTF8, "rust_strings32"),
        # .text:0000000140021155 4C 8D 05 2C DA 09 lea     r8, aAccesserror ; "AccessError"
        # .text:000000014002115C 48 8D 74 24 20    lea     rsi, [rsp+38h+var_18]
        # .text:0000000140021161 41 B9 0B 00 00 00 mov     r9d, 11
        pytest.param("AccessError", 0xBCB88, StringEncoding.UTF8, "rust_strings64"),
        pytest.param("already destroyed", 0xBCB93, StringEncoding.UTF8, "rust_strings64"),
    ],
)
def test_lea_mov(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)

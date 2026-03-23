import pathlib

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.rust.extract import extract_rust_strings


@pytest.fixture(scope="module")
def rust_strings64():
    n = 1
    path = pathlib.Path(__file__).parent / "data" / "language" / "rust" / "rust-hello" / "bin" / "rust-hello64.exe"
    return extract_rust_strings(path, n)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        # For 1 character strings
        pytest.param("Hello, world!", 0xBB030, StringEncoding.UTF8, "rust_strings64"),
        # For 2 character strings
        pytest.param("۶ж̶ƶ", 0xC73E3, StringEncoding.UTF8, "rust_strings64"),
        # For 3 character strings
        pytest.param("jd8n8n헧??", 0xD3CE2, StringEncoding.UTF8, "rust_strings64"),
        # For 4 character strings
        pytest.param("&ޓޓttt", 0xD41F8, StringEncoding.UTF8, "rust_strings64"),
    ],
)
def test_utf8_decoder(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)

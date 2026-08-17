from pathlib import Path

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.go.extract_elf import extract_go_strings_elf


@pytest.fixture(scope="module")
def go_strings_elf():
    n = 6
    sample = Path(__file__).parent / "data" / "language" / "go" / "go-hello" / "bin" / "go-hello"
    return extract_go_strings_elf(sample, n)


@pytest.mark.parametrize(
    "string,offset,encoding",
    [
        pytest.param('5:<=CLMPSZ[]`hms{} + @ P [(") )()\n, ->', 0x9951D, StringEncoding.UTF8),
        pytest.param("boolcallcas1cas2cas3cas4cas5cas6", 0x996AA, StringEncoding.UTF8),
        pytest.param("arrayclose", 0x997AB, StringEncoding.UTF8),
    ],
)
def test_elf_go_string_offset(string, offset, encoding, go_strings_elf):
    assert StaticString(string=string, offset=offset, encoding=encoding) in go_strings_elf


def test_extract_go_strings_elf_go_hello_not_empty(go_strings_elf):
    assert go_strings_elf

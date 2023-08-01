import os
from pathlib import Path

import pytest

from floss.utils import get_static_strings
from floss.language.identify import Language, identify_language


@pytest.mark.parametrize(
    "binary_file, expected_result",
    [
        ("data/language/go/go-hello/bin/go-hello.exe", Language.GO),
        ("data/language/rust/rust-hello/bin/rust-hello.exe", Language.RUST),
        ("data/test-decode-to-stack.exe", Language.UNKNOWN),
        ("data/language/dotnet/dotnet-hello/bin/dotnet-hello.exe", Language.DOTNET),
        ("data/src/shellcode-stackstrings/bin/shellcode-stackstrings.bin", Language.UNKNOWN),
    ],
)
def test_language_detection(binary_file, expected_result):
    CD = Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()
    # check if the file exists
    assert abs_path.exists(), f"File {binary_file} does not exist"

    static_strings = get_static_strings(abs_path, 4)

    language = identify_language(abs_path, static_strings)
    # Check the expected result
    assert language == expected_result, f"Expected: {expected_result.value}, Actual: {language.value}"

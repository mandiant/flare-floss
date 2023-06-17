import os

import pytest

from floss.main import get_static_strings
from floss.language.identify import Language, identify_language


@pytest.mark.parametrize(
    "binary_file, expected_result",
    [
        ("data/src/go-hello/bin/go-hello.exe", Language.GO),
        ("data/src/rust-hello/bin/rust-hello.exe", Language.RUST),
        ("data/test-decode-to-stack.exe", Language.UNKNOWN),
        ("data/src/dotnet-hello/bin/dotnet-hello.exe", Language.DOTNET),
        ("data/src/shellcode-stackstrings/bin/shellcode-stackstrings.bin", Language.UNKNOWN),
    ],
)
def test_language_detection(binary_file, expected_result):
    CD = os.path.dirname(__file__)
    abs_path = os.path.normpath(os.path.join(CD, binary_file))
    # check if the file exists
    assert os.path.exists(abs_path), f"File {binary_file} does not exist"

    static_strings = get_static_strings(abs_path, 4)

    language = identify_language(abs_path, static_strings)
    # Check the expected result
    assert language == expected_result, f"Expected: {expected_result.value}, Actual: {language.value}"

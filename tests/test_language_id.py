import os

import pytest

from floss.language_identifier import is_go_bin


@pytest.mark.parametrize(
    "binary_file, expected_result",
    [
        ("data/src/go-hello/bin/go-hello.exe", True),
        # ("data/src/go-hello/bin/go-hello", True), should be true, but it fails as elf file format is not supported
        ("data/test-decode-to-stack.exe", False),
        ("data/src/shellcode-stackstrings/bin/shellcode-stackstrings.bin", False),
    ],
)
def test_go_binary_detection(binary_file, expected_result):
    CD = os.path.dirname(__file__)
    abs_path = os.path.normpath(os.path.join(CD, binary_file))
    # check if the file exists
    assert os.path.exists(abs_path) == True, f"File {binary_file} does not exist"

    is_go_binary = is_go_bin(abs_path)
    # Check the expected result
    assert is_go_binary == expected_result, f"Expected: {expected_result}, Actual: {is_go_binary}"

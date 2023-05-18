import pytest

from floss.language_identifier import is_go_bin


@pytest.mark.parametrize("binary_file, expected_result", [
    ("./tests/data/src/go-hello/bin/go-hello.exe", True),
    ("./tests/data/src/go-hello/bin/go-hello", False),
    ("test-decode-to-stack.exe", False),
    ("./src/shellcode-stackstrings/bin/shellcode-stackstrings.bin", False),
])
def test_go_binary_detection(binary_file, expected_result):

    is_go_binary = is_go_bin(binary_file)
    
    # Check the expected result
    assert is_go_binary == expected_result, f"Expected: {expected_result}, Actual: {is_go_binary}"

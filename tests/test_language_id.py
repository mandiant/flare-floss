from pathlib import Path

import pytest

from floss.utils import get_static_strings
from floss.language.identify import VERSION_UNKNOWN_OR_NA, Language, identify_language_and_version


@pytest.mark.parametrize(
    "binary_file, expected_result, expected_version",
    [
        ("data/language/go/go-hello/bin/go-hello.exe", Language.GO, "1.20"),
        # Go sample with stomped PCNLTAB magic bytes, see https://github.com/mandiant/flare-floss/issues/840
        (
            "data/language/go/go-unknown-binaries/bin/8f62cfdb7b29fdc39131d8b43a32ae705854db96e340b78991bc9b43b32b4eb8.exe_",
            Language.GO,
            VERSION_UNKNOWN_OR_NA,
        ),
        ("data/language/rust/rust-hello/bin/rust-hello.exe", Language.RUST, "1.69.0"),
        ("data/test-decode-to-stack.exe", Language.UNKNOWN, VERSION_UNKNOWN_OR_NA),
        ("data/language/dotnet/dotnet-hello/bin/dotnet-hello.exe", Language.DOTNET, VERSION_UNKNOWN_OR_NA),
        ("data/src/shellcode-stackstrings/bin/shellcode-stackstrings.bin", Language.UNKNOWN, VERSION_UNKNOWN_OR_NA),
    ],
)
def test_language_detection(binary_file, expected_result, expected_version):
    CD = Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()

    assert abs_path.exists(), f"File {binary_file} does not exist"

    static_strings = get_static_strings(abs_path, 4)

    language, version = identify_language_and_version(abs_path, static_strings)

    assert language == expected_result, f"Expected: {expected_result.value}, Actual: {language.value}"
    assert version == expected_version, f"Expected: {expected_version}, Actual: {version}"

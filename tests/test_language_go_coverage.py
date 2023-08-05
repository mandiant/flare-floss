import pathlib
import contextlib

import pefile
import pytest

from floss.utils import get_static_strings
from floss.language.go.extract import extract_go_strings
from floss.language.go.coverage import get_extract_stats


@pytest.mark.parametrize(
    "binary_file",
    [
        ("data/language/go/go-unknown-binaries/bin/386_go1.12"),
        ("data/language/go/go-unknown-binaries/bin/386_go1.16"),
        ("data/language/go/go-unknown-binaries/bin/386_go1.18"),
        ("data/language/go/go-unknown-binaries/bin/386_go1.20"),
        ("data/language/go/go-unknown-binaries/bin/amd64_go1.12"),
        ("data/language/go/go-unknown-binaries/bin/amd64_go1.16"),
        ("data/language/go/go-unknown-binaries/bin/amd64_go1.18"),
        ("data/language/go/go-unknown-binaries/bin/amd64_go1.20"),
    ],
)
def test_language_detection_64(binary_file):
    CD = pathlib.Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()

    assert abs_path.exists(), f"File {binary_file} does not exist"

    n = 4

    all_ss_strings = get_static_strings(abs_path, n)
    go_strings = extract_go_strings(abs_path, n)

    pe = pefile.PE(abs_path)

    # do not print the output of the function
    with contextlib.redirect_stdout(None):
        out = get_extract_stats(pe, all_ss_strings, go_strings, n)

    # check that the output percentage is greater than 98%
    assert out > 98

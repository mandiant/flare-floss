import pathlib
import contextlib

import pytest
import pefile

from floss.strings import extract_ascii_unicode_strings
from floss.language.rust.extract import extract_utf8_strings
from floss.language.rust.coverage import get_extract_stats


@pytest.mark.parametrize(
    "binary_file",
    [
        ("data/language/rust/rust-unknown-binaries/bin/1.59.0_i386"),
        ("data/language/rust/rust-unknown-binaries/bin/1.64.0_amd64"),
        ("data/language/rust/rust-unknown-binaries/bin/1.65.0_amd64"),
        ("data/language/rust/rust-unknown-binaries/bin/1.68.1_amd64"),
        ("data/language/rust/rust-unknown-binaries/bin/1.69.0_amd64"),
        ("data/language/rust/rust-unknown-binaries/bin/1.69.0_i386"),
    ],
)
def test_language_detection_64(binary_file):
    CD = pathlib.Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()

    assert abs_path.exists(), f"File {binary_file} does not exist"

    n = 4

    path = pathlib.Path(abs_path)
    buf = path.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            pointer_to_raw_data = section.PointerToRawData
            section_size = section.SizeOfRawData
            break

    start_rdata = pointer_to_raw_data
    end_rdata = pointer_to_raw_data + section_size

    all_ss_strings = extract_ascii_unicode_strings(buf[start_rdata:end_rdata], n)
    # all_ss_strings = get_static_strings(abs_path, n)
    rust_strings = extract_utf8_strings(abs_path, n)

    # do not print the output of the function
    with contextlib.redirect_stdout(None):
        out = get_extract_stats(all_ss_strings, rust_strings)

    # check that the output percentage is greater than 97%
    assert float(out) > 97

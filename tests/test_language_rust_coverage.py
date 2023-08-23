import pathlib
import contextlib

import pefile
import pytest

from floss.strings import extract_ascii_unicode_strings
from floss.language.utils import get_extract_stats
from floss.language.rust.extract import extract_rust_strings


@pytest.mark.parametrize(
    "binary_file",
    [
        (
            "data/language/rust/rust-unknown-binaries/bin/1.59.0/i386/bf7362a9a5e94d93d5f495ac2535779708f2f09bf0729382aba0f7f64f42f36a"
        ),
        (
            "data/language/rust/rust-unknown-binaries/bin/1.64.0/amd64/e37b08d35b237961c2d5a94a5ced3919616037b3e2a73efa77bf992c5335fbf6"
        ),
        (
            "data/language/rust/rust-unknown-binaries/bin/1.65.0/amd64/635d89076c3c68520ae7927196c5b9448cb783f4ac0ee0a552d3bb60e899caba"
        ),
        (
            "data/language/rust/rust-unknown-binaries/bin/1.68.1/amd64/07e00bbedff9a4aee59056c629a6ac67a34d6f8b8f0082f98d14f0f80ee037a4"
        ),
        (
            "data/language/rust/rust-unknown-binaries/bin/1.69.0/amd64/b76d3f6327b9e680c491289ecd38f0a8b2fc7a7ba458e5532d80a78d89af0184"
        ),
        (
            "data/language/rust/rust-unknown-binaries/bin/1.69.0/i386/200c308a793630e4f3686dd846f0d55b6368834a859875970b4135f3ca487f46"
        ),
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

    all_ss_strings = list(extract_ascii_unicode_strings(buf, 4))

    rust_strings = extract_rust_strings(path, n)

    # do not print the output of the function
    with contextlib.redirect_stdout(None):
        out = get_extract_stats(pe, all_ss_strings, rust_strings, n)

    # check that the output percentage is greater than 88%
    assert float(out) > 88

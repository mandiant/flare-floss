# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Tests for the .NET user-string extractor.

The test binary is AddInProcess.exe from .NET Framework 4 (a small, pure
managed assembly shipped with Windows).  Ground-truth offsets were obtained by
parsing the binary with our extractor and cross-checking with a hex editor
against the #US heap location.

String objects are compared by value *and* file offset, matching the convention
used in test_language_extract_go.py and test_language_extract_rust.py.
"""

import pathlib

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.dotnet.extract import extract_dotnet_strings, _find_metadata_root, _get_us_heap

# Path to the test binary inside the repository's test data tree.
# AddInProcess.exe is a small (~20 KB), pure managed .NET 4 assembly
# that ships as part of the .NET Framework on every Windows system.
_BIN_DIR = pathlib.Path(__file__).parent / "data" / "language" / "dotnet" / "dotnet-hello" / "bin"
_DOTNET_BINARY = _BIN_DIR / "AddInProcess.exe"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dotnet_strings():
    """Extract strings from the test .NET binary (min length = 4)."""
    return extract_dotnet_strings(_DOTNET_BINARY, min_length=4)


# ---------------------------------------------------------------------------
# Helper so parametrize can reference the fixture by name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "string,offset,encoding",
    [
        # These offsets are file offsets into the #US heap entries.
        # Verified by running: python -m floss.language.dotnet.extract <binary>
        #
        # 0x00002349: /guid:
        pytest.param("/guid:", 0x2349, StringEncoding.UTF16LE),
        # 0x00002357: /pid:
        pytest.param("/pid:", 0x2357, StringEncoding.UTF16LE),
        # 0x00002363: System.AddIn.Hosting.AddInServer
        pytest.param("System.AddIn.Hosting.AddInServer", 0x2363, StringEncoding.UTF16LE),
        # 0x000023AF: ServerChannel
        pytest.param("ServerChannel", 0x23AF, StringEncoding.UTF16LE),
        # 0x000023DD: typeFilterLevel
        pytest.param("typeFilterLevel", 0x23DD, StringEncoding.UTF16LE),
        # 0x000023FD: Full
        pytest.param("Full", 0x23FD, StringEncoding.UTF16LE),
        # 0x00002407: AddInServer
        pytest.param("AddInServer", 0x2407, StringEncoding.UTF16LE),
        # 0x0000241F: AddInProcess:
        pytest.param("AddInProcess:", 0x241F, StringEncoding.UTF16LE),
    ],
)
def test_known_strings_extracted(dotnet_strings, string, offset, encoding):
    """Verify that each known string is present at its expected file offset."""
    assert StaticString(string=string, offset=offset, encoding=encoding) in dotnet_strings


# ---------------------------------------------------------------------------
# Structural tests
# ---------------------------------------------------------------------------


def test_metadata_root_found():
    """The BSJB metadata root must be locatable in the test binary."""
    import pefile

    buf = _DOTNET_BINARY.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)
    result = _find_metadata_root(pe)
    assert result is not None, "BSJB metadata root not found"
    file_offset, _ = result
    assert buf[file_offset : file_offset + 4] == b"BSJB"


def test_us_heap_found():
    """The #US heap must be locatable and have a non-zero size."""
    import pefile

    buf = _DOTNET_BINARY.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)
    result = _find_metadata_root(pe)
    assert result is not None
    metadata_file_offset, _ = result

    us_heap = _get_us_heap(buf, metadata_file_offset)
    assert us_heap is not None, "#US heap not found"
    _, us_size = us_heap
    assert us_size > 0, "#US heap has zero size"


def test_all_strings_are_utf16le(dotnet_strings):
    """All extracted strings must be tagged as UTF-16LE."""
    assert len(dotnet_strings) > 0
    for s in dotnet_strings:
        assert s.encoding == StringEncoding.UTF16LE, f"unexpected encoding for '{s.string}': {s.encoding}"


def test_min_length_filter():
    """Strings shorter than min_length must be filtered out."""
    all_strings = extract_dotnet_strings(_DOTNET_BINARY, min_length=4)
    filtered = extract_dotnet_strings(_DOTNET_BINARY, min_length=10)
    # Increasing min_length must never increase the result count
    assert len(filtered) <= len(all_strings)
    for s in filtered:
        assert len(s.string) >= 10


def test_no_empty_strings(dotnet_strings):
    """No empty strings should be present in the output."""
    for s in dotnet_strings:
        assert len(s.string) > 0, "empty string in results"


def test_string_count(dotnet_strings):
    """Sanity check: AddInProcess.exe has exactly 10 user strings (min_length=4)."""
    assert len(dotnet_strings) == 10

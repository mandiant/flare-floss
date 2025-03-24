# Copyright 2025 Google LLC
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

import mmap
import tempfile

from floss.results import StaticString, StringEncoding
from floss.strings import buf_filled_with, extract_ascii_strings, extract_unicode_strings


def test_buf_filled_with():
    # Single repeating byte
    assert buf_filled_with(b"\x00" * 8, 0x00) is True
    assert buf_filled_with(b"\xff" * 8, 0xFF) is True

    # Mixed bytes
    assert buf_filled_with(b"\x00\x01" * 8, 0x00) is False
    assert buf_filled_with(b"ABCD" * 8, ord("A")) is False

    # Edge cases
    assert buf_filled_with(b"", 0x00) is False  # Empty buffer
    assert buf_filled_with(b"\x00", 0x00) is True  # Single byte

    # Large buffers and patterns
    assert buf_filled_with(b"A" * 10000, ord("A")) is True
    assert buf_filled_with(b"A" * 10000 + b"B", ord("A")) is False
    assert buf_filled_with(b"B" + b"A" * 5000, ord("A")) is False
    assert buf_filled_with(b"A" * 5000 + b"B" + b"A" * 2000, ord("A")) is False
    assert buf_filled_with(b"A" * 5000 + b"B" * 5000, ord("A")) is False

    # Test with mmap
    mmap_tests = [
        (b"A" * 10000, ord("A"), True),
        (b"A" * 10000 + b"B", ord("A"), False),
        (b"B" + b"A" * 5000, ord("A"), False),
        (b"A" * 5000 + b"B" + b"A" * 2000, ord("A"), False),
        (b"A" * 5000 + b"B" * 5000, ord("A"), False),
    ]

    for buf, char, expectation in mmap_tests:
        with tempfile.NamedTemporaryFile() as f:
            f.write(buf)
            f.flush()
            test_mmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            mmap_bytes = bytes(test_mmap)
            assert buf_filled_with(mmap_bytes, char) == expectation


def test_extract_ascii_strings():
    # Test 1: Empty buffer
    assert list(extract_ascii_strings(b"")) == []

    # Test 2: Basic ASCII extraction
    buf = b"Hello World\x00This is a test\x00"
    strings = list(extract_ascii_strings(buf))
    assert len(strings) == 2
    assert strings[0] == StaticString("Hello World", 0, StringEncoding.ASCII)
    assert strings[1] == StaticString("This is a test", 12, StringEncoding.ASCII)

    # Test 3: Minimum length constraint
    buf = b"Hi\x00Test\x00"
    strings = list(extract_ascii_strings(buf, n=4))
    assert len(strings) == 1
    assert strings[0] == StaticString("Test", 3, StringEncoding.ASCII)

    # Test 4: Non-ASCII characters (should ignore them)
    buf = b"Hello\xffWorld\x00"
    strings = list(extract_ascii_strings(buf))
    assert len(strings) == 2
    assert strings[0] == StaticString("Hello", 0, StringEncoding.ASCII)
    assert strings[1] == StaticString("World", 6, StringEncoding.ASCII)

    # Test 5: Buffer with only non-ASCII (no matches)
    assert list(extract_ascii_strings(b"\xff\xff\xff")) == []

    # Test 6: Skip repeated bytes
    buf = b"\x00" * 8 + b"ValidString\x00"
    strings = list(extract_ascii_strings(buf))
    assert len(strings) == 1
    assert strings[0] == StaticString("ValidString", 8, StringEncoding.ASCII)


def test_extract_unicode_strings():
    # Test 1: Basic UTF-16LE extraction
    buf = b"H\x00e\x00l\x00l\x00o\x00\x00\x00"
    strings = list(extract_unicode_strings(buf))
    assert len(strings) == 1
    assert strings[0] == StaticString("Hello", 0, StringEncoding.UTF16LE)

    # Test 2: Minimum length constraint
    buf = b"H\x00i\x00\x00\x00T\x00e\x00s\x00t\x00\x00\x00"
    strings = list(extract_unicode_strings(buf, n=4))
    assert len(strings) == 1
    assert strings[0] == StaticString("Test", 6, StringEncoding.UTF16LE)

    # Test 3: Invalid UTF-16LE sequences (should be skipped)
    buf = b"H\x00\xff\x00l\x00l\x00o\x00\x00\x00"
    strings = list(extract_unicode_strings(buf))
    assert len(strings) == 0

    # Test 4: Skip repeated bytes
    buf = b"\x00" * 8 + b"V\x00a\x00l\x00i\x00d\x00\x00\x00"
    strings = list(extract_unicode_strings(buf))
    assert len(strings) == 1
    assert strings[0] == StaticString("Valid", 8, StringEncoding.UTF16LE)

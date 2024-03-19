# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import pytest
import envi.memory

from floss.string_decoder import memdiff

basic_tests = [
    # Empty strings
    ("", ""),
    # Single byte matching
    ("a", "a"),
    # Single byte diffing
    ("a", "b"),
    # Multi-byte first character diff
    ("aaa", "baa"),
    # Multi-byte mid character diff
    ("aaa", "aba"),
    # multi-byte last character diff
    ("aaa", "aab"),
    # Multi-byte multi-diff
    ("aaaa", "abab"),
]


def test_basics():
    for a, b in basic_tests:
        assert envi.memory.memdiff(a, b) == memdiff(a, b)

    # Make sure we're throwing an exception on different length strings
    with pytest.raises(Exception):
        memdiff("a", "aa")


complex_tests = [
    # 32 byte diff in the second half of the input string
    ("A" * 800, ("A" * 512) + ("B" * 32) + ("A" * 256)),
    # 32 byte diff in the first half of the input string
    ("A" * 800, ("A" * 256) + ("B" * 32) + ("A" * 512)),
    # early 512 byte  diff
    ("A" * 800, ("A" * 32) + ("B" * 512) + ("A" * 256)),
    # End of line diff
    ("A" * 800, ("A" * 799) + "B"),
    # Beginning of line diff
    ("A" * 800, "B" + ("A" * 799)),
    # Midpoint diff
    ("A" * 800, ("A" * 400) + "B" + ("A" * 399)),
    # Midpoint diff
    ("A" * 800, ("A" * 399) + "B" + ("A" * 400)),
    # Midpoint diff
    ("A" * 800, ("A" * 399) + "BB" + ("A" * 399)),
    # 7 diffs, each 100 characters apart
    ("A" * 800, ((("A" * 100) + "B") * 7) + ("A" * 93)),
]


def test_complex():
    for a, b in complex_tests:
        assert envi.memory.memdiff(a, b) == memdiff(a, b)

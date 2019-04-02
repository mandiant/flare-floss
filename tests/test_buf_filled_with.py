# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import pytest

import mmap
import tempfile

from floss.strings import buf_filled_with


# (test case, expected result)
tests = [
    ("A", True),
    ("AB", False),
    ("A" * 10000, True),
    (("A" * 10000) + "B", False),
    ("B" + ("A" * 5000), False),
    (("A" * 5000) + "B" + ("A" * 2000), False),
    (("A" * 5000) + ("B" * 5000), False),
]


def test_str():
    for test, expectation in tests:
        assert buf_filled_with(test, test[0]) == expectation


def test_mmap():
    for test, expectation in tests:
        f = tempfile.NamedTemporaryFile()
        f.write(test)
        f.flush()
        test_mmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        assert buf_filled_with(test_mmap, test_mmap[0]) == expectation

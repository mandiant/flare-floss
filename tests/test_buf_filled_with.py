# Copyright 2017 Google LLC
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

import pytest

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
        f.write(test.encode("utf-8"))
        f.flush()
        test_mmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        assert buf_filled_with(test_mmap, test[0].encode("utf-8")) == expectation

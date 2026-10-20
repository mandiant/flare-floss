# Copyright 2026 Google LLC
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

import gzip
import json
from types import SimpleNamespace

import pytest

from floss.tags.oss import DEFAULT_PATHS
from floss.tags.filter import LIBRARY_TAGS, remove_false_positive_lib_strings


def make_layout(*tag_sets, children=()):
    return SimpleNamespace(strings=[SimpleNamespace(tags=set(tags)) for tags in tag_sets], children=list(children))


def tags_of(layout):
    ret = [s.tags for s in layout.strings]
    for child in layout.children:
        ret.extend(tags_of(child))
    return ret


@pytest.mark.parametrize("tag", ["#zlib", "#msvc"])
def test_rare_library_tag_is_removed(tag):
    layout = make_layout({tag, "#common"}, children=[make_layout({tag}, {tag})])
    remove_false_positive_lib_strings(layout)
    assert tags_of(layout) == [{"#common"}, set(), set()]


@pytest.mark.parametrize("tag", ["#zlib", "#msvc"])
def test_frequent_library_tag_is_kept(tag):
    layout = make_layout({tag}, {tag}, children=[make_layout({tag}, {tag}, {tag})])
    remove_false_positive_lib_strings(layout)
    assert all(tag in tags for tags in tags_of(layout))


def test_threshold_counts_each_library_separately():
    layout = make_layout(*[{"#openssl", "#msvc"} for _ in range(4)], {"#openssl"})
    remove_false_positive_lib_strings(layout)
    assert tags_of(layout) == [{"#openssl"}] * 5


def test_library_tags_match_database_library_names():
    names = set()
    for path in DEFAULT_PATHS:
        with gzip.open(path, "rt") as f:
            names.add(json.loads(f.readline())["library_name"])
    assert set(LIBRARY_TAGS) == {f"#{name}" for name in names}

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
from floss.layout.base import PELayout, ELFLayout, MachOLayout, SegmentLayout, MachOFatLayout
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


def make_typed_layout(cls, *tag_sets, children=()):
    # model_construct skips validation, so only the fields the filter walks are needed
    return cls.model_construct(
        strings=[SimpleNamespace(tags=set(tags)) for tags in tag_sets],
        children=list(children),
    )


@pytest.mark.parametrize("cls", [ELFLayout, MachOLayout, MachOFatLayout])
def test_msvc_tag_is_removed_outside_pe(cls):
    # ELF and Mach-O files are never linked against the MSVC CRT; enough generic words match its database
    # ("name", "error", "data", ...) to pass the threshold, so drop the tag regardless of the hit count
    msvc = [{"#msvc", "#common"} for _ in range(10)]
    layout = make_typed_layout(cls, *msvc, children=[make_typed_layout(SegmentLayout, *msvc)])
    remove_false_positive_lib_strings(layout)
    assert tags_of(layout) == [{"#common"}] * 20


def test_other_library_tags_are_kept_outside_pe():
    layout = make_typed_layout(ELFLayout, *[{"#zlib"} for _ in range(5)])
    remove_false_positive_lib_strings(layout)
    assert tags_of(layout) == [{"#zlib"}] * 5


def test_msvc_tag_is_kept_in_pe():
    layout = make_typed_layout(PELayout, *[{"#msvc"} for _ in range(5)])
    remove_false_positive_lib_strings(layout)
    assert tags_of(layout) == [{"#msvc"}] * 5


def test_msvc_tag_is_kept_in_pe_embedded_in_elf():
    # the nearest enclosing file format decides
    pe = make_typed_layout(PELayout, *[{"#msvc"} for _ in range(5)])
    layout = make_typed_layout(ELFLayout, {"#msvc"}, children=[pe])
    remove_false_positive_lib_strings(layout)
    assert tags_of(layout) == [set()] + [{"#msvc"}] * 5

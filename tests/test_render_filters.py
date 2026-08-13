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

"""Render-time filters, columns, and summary output for the layout view."""

import io
import sys
import json

from fixtures import exefile

import floss.main
import floss.render.filter
import floss.render.summary
from floss.results import (
    Strings,
    Analysis,
    Metadata,
    ResultLayout,
    ResultString,
    StaticString,
    ResultDocument,
    StringEncoding,
)
from floss.tags.filter import TagRules
from floss.render.default import render


def make_layout() -> ResultLayout:
    """a small PE-like tree with tagged strings in .rdata."""
    return ResultLayout(
        name="pe",
        offset=0,
        length=0x1000,
        children=[
            ResultLayout(
                name=".text",
                offset=0x400,
                length=0x400,
                strings=[
                    ResultString(string="junk code", offset=0x410, size=9, encoding="ascii", tags=["#code"]),
                ],
            ),
            ResultLayout(
                name=".rdata",
                offset=0x800,
                length=0x800,
                strings=[
                    ResultString(
                        string="CreateFileA",
                        offset=0x810,
                        size=11,
                        encoding="ascii",
                        tags=["#winapi"],
                        structure="import table",
                    ),
                    ResultString(
                        string="hello world",
                        offset=0x820,
                        size=11,
                        encoding="ascii",
                        tags=["#common"],
                    ),
                    ResultString(
                        string="kcp://url",
                        offset=0x830,
                        size=9,
                        encoding="ascii",
                        tags=["#kcp"],
                    ),
                ],
            ),
        ],
    )


def make_results() -> ResultDocument:
    return ResultDocument(
        metadata=Metadata(file_path="test.exe", min_length=4),
        analysis=Analysis(
            enable_static_strings=True,
            enable_stack_strings=False,
            enable_tight_strings=False,
            enable_decoded_strings=False,
        ),
        strings=Strings(
            static_strings=[
                StaticString(string="CreateFileA", offset=0x810, encoding=StringEncoding.ASCII),
                StaticString(string="hello world", offset=0x820, encoding=StringEncoding.ASCII),
                StaticString(string="kcp://url", offset=0x830, encoding=StringEncoding.ASCII),
            ]
        ),
        layout=make_layout(),
    )


def collect_layout_strings(layout):
    out = [s.string for s in layout.strings]
    for child in layout.children:
        out.extend(collect_layout_strings(child))
    return out


def test_filter_by_section():
    f = floss.render.filter.LayoutFilter(include_sections=[".rdata"])
    filtered = f.apply(make_layout())
    assert filtered is not None
    strings = collect_layout_strings(filtered)
    assert "CreateFileA" in strings
    assert "hello world" in strings
    assert "junk code" not in strings
    # empty branches are pruned
    assert ".text" not in [c.name for c in filtered.children]


def test_filter_exclude_section():
    f = floss.render.filter.LayoutFilter(exclude_sections=[".text"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert "junk code" not in strings
    assert "CreateFileA" in strings


def test_filter_by_structure_slug():
    f = floss.render.filter.LayoutFilter(include_structures=["import-table"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert strings == ["CreateFileA"]


def test_filter_by_tag():
    f = floss.render.filter.LayoutFilter(include_tags=["winapi"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert strings == ["CreateFileA"]


def test_filter_exclude_tag():
    f = floss.render.filter.LayoutFilter(exclude_tags=["common"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert "CreateFileA" in strings
    assert "hello world" not in strings


def test_filter_interesting():
    f = floss.render.filter.LayoutFilter(interesting=True)
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    # #code, #common are noisy; #winapi and #kcp are not
    assert "CreateFileA" in strings
    assert "hello world" not in strings
    assert "junk code" not in strings
    assert "kcp://url" in strings


def test_filter_query():
    f = floss.render.filter.LayoutFilter(queries=["CreateFile"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert strings == ["CreateFileA"]


def test_filter_query_ored():
    f = floss.render.filter.LayoutFilter(queries=["CreateFile", "kcp"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert "CreateFileA" in strings
    assert "kcp://url" in strings


def test_filter_max_strings_relevance():
    # highlighted tags (#capa) sort first, then untagged, then non-noisy tags,
    # then only-noisy tags; within a group, ascending offset.
    layout = ResultLayout(
        name=".rdata",
        offset=0x800,
        length=0x400,
        strings=[
            ResultString(string="z-only-noisy", offset=0x810, size=1, encoding="ascii", tags=["#common"]),
            ResultString(string="a-untagged", offset=0x801, size=1, encoding="ascii", tags=[]),
            ResultString(string="m-tagged", offset=0x805, size=1, encoding="ascii", tags=["#winapi"]),
            ResultString(string="b-untagged", offset=0x802, size=1, encoding="ascii", tags=[]),
            ResultString(string="c-highlighted", offset=0x800, size=1, encoding="ascii", tags=["#capa"]),
        ],
    )
    tag_rules: TagRules = {"#capa": "highlight", "#common": "mute", "#winapi": "default"}
    f = floss.render.filter.LayoutFilter(max_strings=3, tag_rules=tag_rules)
    filtered = f.apply(layout)
    assert filtered is not None
    assert [s.string for s in filtered.strings] == ["c-highlighted", "a-untagged", "b-untagged"]


def test_columns_hide_tags(exefile):
    out = render(make_results(), True, False, "auto", columns=["offset"])
    assert "CreateFileA" in out
    assert "#winapi" not in out


def test_columns_show_structure(exefile):
    out = render(make_results(), True, False, "auto", columns=["offset", "structure"])
    assert "import table" in out


def test_filter_all_removed_renders_empty(exefile):
    """a filter that matches nothing must not fall back to the unfiltered layout."""
    f = floss.render.filter.LayoutFilter(include_tags=["#nonexistent"])
    out = render(make_results(), True, False, "auto", layout_filter=f)
    assert "#winapi" not in out
    assert "CreateFileA" not in out
    assert "kcp://url" not in out


def test_summary_output(exefile):
    out = floss.render.summary.render(make_results())
    assert "FLOSS SUMMARY" in out
    assert "CreateFileA" in out
    assert "#winapi" in out


def test_main_summary_flag(exefile):
    assert floss.main.main([exefile, "--summary", "--no-string-type", "stack", "tight", "decoded"]) == 0


def test_main_json_error(capsys, exefile):
    assert floss.main.main([exefile, "-j", "--section", ".text", "--no-section", ".data"]) == -1
    err = capsys.readouterr().err
    last_line = [line for line in err.splitlines() if line.strip()][-1]
    obj = json.loads(last_line)
    assert "error" in obj
    assert obj["code"] == 1


def test_main_columns_flag(exefile):
    assert (
        floss.main.main([exefile, "--columns", "offset", "structure", "--no-string-type", "stack", "tight", "decoded"])
        == 0
    )

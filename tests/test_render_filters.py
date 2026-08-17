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
from floss.render.layout import render_strings
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


def test_filter_by_section_matches_nested_nodes():
    """--section must match strings living in nested nodes under the section."""
    layout = ResultLayout(
        name="pe",
        offset=0,
        length=0x1000,
        children=[
            ResultLayout(
                name=".rdata",
                offset=0x800,
                length=0x800,
                children=[
                    ResultLayout(
                        name="import table",
                        offset=0x810,
                        length=0x10,
                        strings=[
                            ResultString(
                                string="CloseHandle",
                                offset=0x812,
                                size=11,
                                encoding="ascii",
                                tags=["#winapi"],
                                structure="import table",
                            )
                        ],
                    )
                ],
            )
        ],
    )
    f = floss.render.filter.LayoutFilter(include_sections=[".rdata"])
    filtered = f.apply(layout)
    strings = collect_layout_strings(filtered)
    assert strings == ["CloseHandle"]


def test_filter_by_section_fat_macho_descends_arch_wrappers():
    """--section must descend through Mach-O fat-arch wrapper layers."""
    layout = ResultLayout(
        name="macho (fat)",
        offset=0,
        length=0x2000,
        children=[
            ResultLayout(
                name="macho: x86_64",
                offset=0,
                length=0x1000,
                children=[
                    ResultLayout(
                        name="__TEXT",
                        offset=0,
                        length=0x800,
                        strings=[
                            ResultString(string="in text", offset=1, size=7, encoding="ascii"),
                        ],
                    ),
                    ResultLayout(
                        name="__DATA",
                        offset=0x800,
                        length=0x800,
                        strings=[
                            ResultString(string="in data", offset=2, size=7, encoding="ascii"),
                        ],
                    ),
                ],
            ),
        ],
    )
    f = floss.render.filter.LayoutFilter(include_sections=["__TEXT"])
    filtered = f.apply(layout)
    strings = collect_layout_strings(filtered)
    assert strings == ["in text"]


def test_filter_max_strings_fat_macho_caps_per_section():
    """--max-strings caps each fat Mach-O segment, not the whole architecture."""
    layout = ResultLayout(
        name="macho (fat)",
        offset=0,
        length=0x300,
        children=[
            ResultLayout(
                name="macho: x86_64",
                offset=0,
                length=0x200,
                children=[
                    ResultLayout(
                        name="__TEXT",
                        offset=0,
                        length=0x100,
                        strings=[
                            ResultString(string="a", offset=1, size=1, encoding="ascii", tags=["#winapi"]),
                            ResultString(string="b", offset=2, size=1, encoding="ascii", tags=["#winapi"]),
                        ],
                    ),
                    ResultLayout(
                        name="__DATA",
                        offset=0x100,
                        length=0x100,
                        strings=[
                            ResultString(string="c", offset=3, size=1, encoding="ascii", tags=["#winapi"]),
                        ],
                    ),
                ],
            ),
        ],
    )
    f = floss.render.filter.LayoutFilter(max_strings=1, tag_rules={"#winapi": "default"})
    filtered = f.apply(layout)
    strings = collect_layout_strings(filtered)
    # one string per segment: a from __TEXT and c from __DATA
    assert strings == ["a", "c"]


def test_filter_by_structure_slug():
    f = floss.render.filter.LayoutFilter(include_structures=["import-table"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert strings == ["CreateFileA"]


def test_filter_by_structure_slug_variants():
    """import-table, import_table, and import table all match the same structure."""
    for slug in ("import-table", "import_table", "import table"):
        f = floss.render.filter.LayoutFilter(include_structures=[slug])
        filtered = f.apply(make_layout())
        strings = collect_layout_strings(filtered)
        assert strings == ["CreateFileA"], slug


def test_filter_no_structure():
    """--no-structure drops strings in the given structure and keeps the rest."""
    f = floss.render.filter.LayoutFilter(exclude_structures=["import-table"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert "CreateFileA" not in strings
    assert "hello world" in strings


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


def test_filter_repeated_tags_accumulate():
    """repeated --tag values are ORed."""
    f = floss.render.filter.LayoutFilter(include_tags=["winapi", "kcp"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert "CreateFileA" in strings
    assert "kcp://url" in strings


def test_filter_oss_meta_tag():
    """the oss meta tag matches any OSS library tag."""
    f = floss.render.filter.LayoutFilter(include_tags=["oss"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert strings == ["kcp://url"]


def test_filter_tag_family_gp():
    """the gp tag family matches global-prevalence tags like #common."""
    f = floss.render.filter.LayoutFilter(include_tags=["gp"])
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    assert strings == ["hello world"]


def test_filter_tag_normalization():
    """--tag input is case- and #-insensitive (#WinAPI and WinAPI match #winapi)."""
    for tag in ("#WINAPI", "WinAPI", "#winapi", "winapi"):
        f = floss.render.filter.LayoutFilter(include_tags=[tag])
        filtered = f.apply(make_layout())
        strings = collect_layout_strings(filtered)
        assert strings == ["CreateFileA"], tag


def test_filter_interesting():
    f = floss.render.filter.LayoutFilter(interesting=True)
    filtered = f.apply(make_layout())
    strings = collect_layout_strings(filtered)
    # #code, #common are noisy; #winapi and #kcp are not
    assert "CreateFileA" in strings
    assert "hello world" not in strings
    assert "junk code" not in strings
    assert "kcp://url" in strings


def test_filter_interesting_drops_strings_with_any_noisy_tag():
    """--interesting drops a string if it carries any noisy tag, even alongside
    a non-noisy tag (e.g. #winapi #common is dropped)."""
    layout = ResultLayout(
        name=".rdata",
        offset=0,
        length=0x10,
        strings=[
            ResultString(string="CreateFileA", offset=1, size=11, encoding="ascii", tags=["#winapi", "#common"]),
            ResultString(string="only winapi", offset=2, size=11, encoding="ascii", tags=["#winapi"]),
        ],
    )
    f = floss.render.filter.LayoutFilter(interesting=True)
    filtered = f.apply(layout)
    assert filtered is not None
    assert [s.string for s in filtered.strings] == ["only winapi"]


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


def test_filter_max_strings_caps_per_section():
    """--max-strings caps each top-level section, not each nested node."""
    s1 = ResultString(string="one", offset=1, size=3, encoding="ascii", tags=["#winapi"])
    s2 = ResultString(string="two", offset=2, size=3, encoding="ascii", tags=["#winapi"])
    s3 = ResultString(string="three", offset=3, size=5, encoding="ascii", tags=["#winapi"])
    s4 = ResultString(string="four", offset=4, size=4, encoding="ascii", tags=["#winapi"])
    layout = ResultLayout(
        name="pe",
        offset=0,
        length=0x100,
        children=[
            ResultLayout(
                name=".rdata",
                offset=0,
                length=0x80,
                children=[
                    ResultLayout(name="import table", offset=0, length=0x40, strings=[s1, s2]),
                    ResultLayout(name="export table", offset=0x40, length=0x40, strings=[s3, s4]),
                ],
            ),
            ResultLayout(
                name=".text",
                offset=0x80,
                length=0x80,
                strings=[ResultString(string="five", offset=0x90, size=4, encoding="ascii", tags=["#winapi"])],
            ),
        ],
    )
    f = floss.render.filter.LayoutFilter(max_strings=1, tag_rules={"#winapi": "default"})
    filtered = f.apply(layout)
    assert filtered is not None
    strings = collect_layout_strings(filtered)
    # one per top-level section (.rdata and .text)
    assert len(strings) == 2


def test_columns_hide_tags():
    out = render(make_results(), True, False, "auto", columns=["offset"])
    assert "CreateFileA" in out
    assert "#winapi" not in out


def test_columns_show_structure():
    out = render(make_results(), True, False, "auto", columns=["offset", "structure"])
    assert "import table" in out


def test_columns_encoding():
    """--columns encoding renders U for unicode strings and nothing for ascii."""
    unicode_s = ResultString(string="héllo", offset=1, size=6, encoding="unicode")
    ascii_s = ResultString(string="ascii", offset=2, size=5, encoding="ascii")
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(enable_stack_strings=False, enable_tight_strings=False, enable_decoded_strings=False),
        strings=Strings(),
        layout=ResultLayout(name="pe", offset=0, length=10, strings=[unicode_s, ascii_s]),
    )
    out = render(doc, True, False, "auto", columns=["encoding"])
    # unicode marker rendered, ascii marker absent (rich trims the trailing space)
    assert "U" in out


def test_filter_all_removed_renders_empty():
    """a filter that matches nothing must not fall back to the unfiltered layout."""
    f = floss.render.filter.LayoutFilter(include_tags=["#nonexistent"])
    out = render(make_results(), True, False, "auto", layout_filter=f)
    assert "#winapi" not in out
    assert "CreateFileA" not in out
    assert "kcp://url" not in out


def test_tag_filter_overrides_default_hide_rules():
    """--tag code / --tag winapi must show strings that carry a hide-rule tag
    (#code/#reloc) which the default render would suppress."""
    layout = ResultLayout(
        name=".rdata",
        offset=0,
        length=0x10,
        strings=[
            ResultString(string="junk code", offset=1, size=9, encoding="ascii", tags=["#code", "#winapi"]),
        ],
    )
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(enable_stack_strings=False, enable_tight_strings=False, enable_decoded_strings=False),
        strings=Strings(),
        layout=layout,
    )

    for include in ("code", "winapi"):
        out = render(
            doc,
            True,
            False,
            "auto",
            layout_filter=floss.render.filter.LayoutFilter(include_tags=[include]),
        )
        assert "junk code" in out, include

    # --interesting drops any string carrying a noisy tag, including #code
    out = render(doc, True, False, "auto", layout_filter=floss.render.filter.LayoutFilter(interesting=True))
    assert "junk code" not in out

    # without a tag filter, the default hide rules still suppress #code strings
    out = render(doc, True, False, "auto")
    assert "junk code" not in out


def test_summary_output():
    out = floss.render.summary.render_summary(make_results())
    assert "FLOSS SUMMARY" in out
    assert "CreateFileA" in out
    assert "#winapi" in out


def test_summary_section_counts_thread_top_level():
    """nested structure nodes count under their containing top-level section."""
    root_s = ResultString(string="root", offset=1, size=4, encoding="ascii")
    sec_s = ResultString(string="sec", offset=2, size=3, encoding="ascii")
    nested_s = ResultString(string="nested", offset=3, size=6, encoding="ascii")
    layout = ResultLayout(
        name="pe",
        offset=0,
        length=20,
        strings=[root_s],
        children=[
            ResultLayout(
                name=".rdata",
                offset=0,
                length=10,
                strings=[sec_s],
                children=[
                    ResultLayout(name="import table", offset=0, length=10, strings=[nested_s]),
                ],
            )
        ],
    )
    counts, _, _ = floss.render.summary.analyze_layout(layout)
    assert counts == {"pe": 1, ".rdata": 2}
    assert sum(counts.values()) == 3


def test_summary_section_counts_thread_fat_macho():
    """on a fat Mach-O, strings under an arch wrapper's segments count under
    their segment (__TEXT), while the wrapper's own strings count under the
    root."""
    root_s = ResultString(string="root", offset=1, size=4, encoding="ascii")
    wrapper_s = ResultString(string="wrapper", offset=2, size=7, encoding="ascii")
    text_s = ResultString(string="text", offset=3, size=4, encoding="ascii")
    layout = ResultLayout(
        name="macho (fat)",
        offset=0,
        length=20,
        strings=[root_s],
        children=[
            ResultLayout(
                name="macho: x86_64",
                offset=0,
                length=10,
                strings=[wrapper_s],
                children=[
                    ResultLayout(name="__TEXT", offset=0, length=10, strings=[text_s]),
                ],
            )
        ],
    )
    counts, _, _ = floss.render.summary.analyze_layout(layout)
    assert counts == {"macho (fat)": 2, "__TEXT": 1}
    assert sum(counts.values()) == 3


def test_main_summary_flag(exefile, capsys):
    assert floss.main.main([exefile, "--summary"]) == 0
    out = capsys.readouterr().out
    assert "FLOSS SUMMARY" in out
    assert "string counts" in out


def test_main_summary_is_static_only_by_default(exefile, capsys):
    """--summary alone skips stack/tight/decoded extraction."""
    assert floss.main.main([exefile, "--summary"]) == 0
    out = capsys.readouterr().out
    assert "FLOSS SUMMARY" in out
    # counts show recovered strings as 0 because they were not extracted
    assert "| stack strings | 0 |" in out


def test_main_summary_rejects_non_static_string_type(exefile, capsys):
    """--summary only covers static strings, so non-static types are rejected."""
    assert floss.main.main([exefile, "--summary", "--string-type", "stack", "tight", "decoded"]) == -1
    err = capsys.readouterr().err
    assert "--summary" in err


def test_main_summary_accepts_explicit_static(exefile, capsys):
    """--summary with an explicit static selection is fine."""
    assert floss.main.main([exefile, "--summary", "--string-type", "static"]) == 0
    out = capsys.readouterr().out
    assert "FLOSS SUMMARY" in out


def test_summary_no_layout_ok():
    """--summary must not crash when there is no layout tree."""
    results = make_results()
    results.layout = None
    out = floss.render.summary.render_summary(results, "auto")
    assert "FLOSS SUMMARY" in out
    assert "string counts" in out


def test_main_json_error(capsys, exefile):
    assert floss.main.main([exefile, "-j", "--section", ".text", "--no-section", ".data"]) == -1
    err = capsys.readouterr().err
    # in JSON mode the whole STDERR output is a single JSON object, no usage text
    obj = json.loads(err)
    assert "error" in obj
    assert obj["code"] == 1


def test_main_invalid_query_regex_json_error(capsys, exefile):
    assert floss.main.main([exefile, "-j", "--query", "["]) == -1
    err = capsys.readouterr().err
    obj = json.loads(err)
    assert "query" in obj["error"]
    assert obj["code"] == 1


def test_main_invalid_query_regex_text_error(capsys, exefile):
    assert floss.main.main([exefile, "--query", "["]) == -1
    captured = capsys.readouterr()
    # the error message and usage both go to stderr in text mode
    assert "invalid --query regular expression" in captured.err
    assert "usage:" in captured.err


def test_main_columns_flag(exefile, capsys):
    assert (
        floss.main.main([exefile, "--columns", "offset", "structure", "--no-string-type", "stack", "tight", "decoded"])
        == 0
    )
    out = capsys.readouterr().out
    assert "KERNEL32.dll" in out
    assert "import table" in out


def test_main_columns_invalid_value(exefile):
    assert floss.main.main([exefile, "--columns", "bogus"]) == -1


def test_main_columns_with_plain(exefile):
    """--columns is irrelevant with --plain (no layout), but must not crash."""
    assert floss.main.main([exefile, "--plain", "--columns", "offset", "structure"]) == 0


def test_plain_render_does_not_mutate_results():
    """--plain selects the classic view without mutating the result document."""
    layout = ResultLayout(
        name="pe",
        offset=0,
        length=0x10,
        strings=[ResultString(string="x", offset=1, size=1, encoding="ascii")],
    )
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(enable_stack_strings=False, enable_tight_strings=False, enable_decoded_strings=False),
        strings=Strings(),
        layout=layout,
    )
    out = render(doc, True, False, "auto", plain=True)
    assert "FLARE FLOSS RESULTS" in out
    assert doc.layout is not None


def test_plain_render_applies_filters():
    """--plain is filter-aware: --query/--tag narrow the flat listing."""
    s = ResultString(string="http://evil", offset=1, size=11, encoding="ascii", tags=["#winapi"])
    s2 = ResultString(string="junk", offset=2, size=4, encoding="ascii", tags=["#common"])
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(enable_stack_strings=False, enable_tight_strings=False, enable_decoded_strings=False),
        strings=Strings(
            static_strings=[
                StaticString(string="http://evil", offset=1, encoding=StringEncoding.ASCII, tags=["#winapi"]),
                StaticString(string="junk", offset=2, encoding=StringEncoding.ASCII, tags=["#common"]),
            ]
        ),
        layout=ResultLayout(name="pe", offset=0, length=10, strings=[s, s2]),
    )
    out = render(doc, True, False, "auto", plain=True, layout_filter=floss.render.filter.LayoutFilter(queries=["http"]))
    assert "http://evil" in out
    assert "junk" not in out


def test_classic_meta_fallback_when_layout_present_but_static_disabled():
    """with a layout present but static strings disabled, the classic metadata
    table renders as a fallback (file path, language, etc.) instead of dropping
    all sample context."""
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(
            enable_static_strings=False,
            enable_stack_strings=False,
            enable_tight_strings=False,
            enable_decoded_strings=False,
        ),
        strings=Strings(),
        layout=ResultLayout(name="pe", offset=0, length=10),
    )
    out = render(doc, True, False, "auto")
    assert "FLARE FLOSS RESULTS" in out
    assert "file path" in out
    # the layout tree itself is not shown when static strings are disabled
    assert "pe" not in out


def test_layout_none_warns_filters_ignored(caplog):
    """an active layout filter with no layout tree must warn, not silently no-op."""
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(enable_stack_strings=False, enable_tight_strings=False, enable_decoded_strings=False),
        strings=Strings(),
        layout=None,
    )
    with caplog.at_level("WARNING", logger="floss.render.default"):
        render(doc, True, False, "auto", layout_filter=floss.render.filter.LayoutFilter(include_tags=["winapi"]))
    assert "no layout tree" in caplog.text
    assert "ignored" in caplog.text


def test_summary_escapes_rich_markup():
    """summary must render strings containing Rich markup literally, not crash."""
    s = ResultString(string="[bold red]X[/bold]", offset=1, size=12, encoding="ascii", tags=["#winapi"])
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(enable_stack_strings=False, enable_tight_strings=False, enable_decoded_strings=False),
        strings=Strings(),
        layout=ResultLayout(name="pe", offset=0, length=10, strings=[s]),
    )
    out = floss.render.summary.render_summary(doc)
    assert "[bold red]X[/bold]" in out


def test_summary_ignores_plain(exefile, capsys):
    """--summary with --plain still renders the layout-backed summary."""
    assert floss.main.main([exefile, "--summary", "--plain"]) == 0
    out = capsys.readouterr().out
    assert "FLOSS SUMMARY" in out
    assert "section counts" in out


def test_main_summary_with_json(exefile, capsys):
    """--json takes precedence over --summary."""
    assert floss.main.main([exefile, "-j", "--summary"]) == 0
    out = capsys.readouterr().out
    assert "FLOSS SUMMARY" not in out
    json.loads(out)


def test_main_filter_mutual_exclusion(capsys, exefile):
    for args in (
        ["--structure", "import-table", "--no-structure", "export-table"],
        ["--tag", "winapi", "--no-tag", "crypto"],
    ):
        assert floss.main.main([exefile] + args) == -1
        captured = capsys.readouterr()
        assert "not allowed together" in captured.out + captured.err


def test_main_repeated_tags_accumulate(exefile, capsys):
    """repeated --tag flags accumulate (OR semantics)."""
    assert (
        floss.main.main([exefile, "--tag", "winapi", "--tag", "msvc", "--no-string-type", "stack", "tight", "decoded"])
        == 0
    )
    out = capsys.readouterr().out
    assert "KERNEL32.dll" in out


def test_main_max_strings_invalid(exefile, capsys):
    for value in ("0", "-1"):
        assert floss.main.main([exefile, "--max-strings", value]) == -1
        captured = capsys.readouterr()
        assert "positive integer" in captured.out + captured.err


def test_main_max_strings_larger_than_section(exefile, capsys):
    """a max larger than the section size is fine and returns everything."""
    assert floss.main.main([exefile, "--max-strings", "100000", "--no-string-type", "stack", "tight", "decoded"]) == 0
    out = capsys.readouterr().out
    assert "KERNEL32.dll" in out


def _render_layout(layout):
    import io

    from rich.console import Console

    console = Console(file=io.StringIO(), width=80)
    render_strings(console, layout, {})
    return console.file.getvalue()  # type: ignore [attr-defined]


def test_render_offset_not_truncated_by_depth():
    """rendering at depth must not chop characters off the offset column."""
    s = ResultString(string="hello", offset=0x810, size=5, encoding="ascii", tags=["#winapi"])
    layout = ResultLayout(name=".rdata", offset=0, length=0x900, strings=[s])
    out = _render_layout(layout)
    assert "00000810" in out


def test_render_boundary_string_not_omitted():
    """a string starting exactly at a child boundary must be rendered."""
    s = ResultString(string="boundary", offset=0xA0, size=8, encoding="ascii")
    child = ResultLayout(name=".child", offset=0x50, length=0x50)
    layout = ResultLayout(name="pe", offset=0, length=0x150, strings=[s], children=[child])
    out = _render_layout(layout)
    assert "boundary" in out


def test_render_single_child_collapse_keeps_own_strings():
    """collapsing a node into its sole dominating child must not drop the
    parent's own strings."""
    own = ResultString(string="ownstring", offset=0x250, size=9, encoding="ascii")
    child_s = ResultString(string="childstr", offset=0x100, size=8, encoding="ascii")
    child = ResultLayout(name="inner", offset=0, length=0x200, strings=[child_s])
    # child spans [0, 0x200); parent's own string sits in the gap after it
    layout = ResultLayout(name="outer", offset=0, length=0x300, strings=[own], children=[child])
    out = _render_layout(layout)
    assert "ownstring" in out
    assert "childstr" in out

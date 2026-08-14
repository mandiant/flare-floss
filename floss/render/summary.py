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

"""Concise, token-efficient summary of a FLOSS result document.

The summary is built from the same ``ResultDocument`` as the ``--json`` output,
so it is programmatic and consistent. It reports sample metadata, per-type
string counts, section counts, tag histograms, and the strings that carry
high-value (non-noisy) tags. Intended for human consumers: agents should use
``-j/--json`` for machine-readable output instead of parsing the formatted
tables.
"""

from __future__ import annotations

import io
import sys
from typing import Dict, List, Tuple, Sequence
from collections import Counter

from rich.markup import escape
from rich.console import Console

from floss.results import ResultLayout, ResultString, ResultDocument
from floss.render.filter import NOISY_TAGS, relevance_key, is_macho_arch_wrapper
from floss.render.layout import get_visible_tags
from floss.render.default import (
    DEFAULT_TAG_RULES,
    MIN_WIDTH_LEFT_COL,
    MIN_WIDTH_RIGHT_COL,
    width,
    strtime,
    get_color,
    heading_style,
    language_value,
)
from floss.render.sanitize import sanitize

HIGH_VALUE_MAX_STRINGS = 25


def analyze_layout(layout: ResultLayout):
    """walk the layout tree once, returning the derived summary values.

    returns a 3-tuple of (section_counts, tag_histogram, high_value_strings).
    The section of a string is its containing top-level section: children of
    the root (or of a Mach-O fat-arch wrapper) are the sections, and deeper
    nodes inherit their section (so strings under a nested ``import table``
    node are counted under ``.rdata``).
    """
    section_counts: Dict[str, int] = Counter()
    tag_histogram: Counter = Counter()
    high_value: List[ResultString] = []

    def walk(node: ResultLayout, section: str, depth: int) -> None:
        section_counts[section] += len(node.strings)
        for s in node.strings:
            tag_histogram.update(s.tags)
            if any(tag not in NOISY_TAGS for tag in s.tags):
                high_value.append(s)
        for child in node.children:
            # a child becomes a section when it's not a format wrapper and its
            # parent is the root or an arch wrapper; otherwise it inherits
            if not is_macho_arch_wrapper(child) and (depth == 0 or is_macho_arch_wrapper(node)):
                child_section = child.name
            else:
                child_section = section
            walk(child, child_section, depth + 1)

    # walk the whole tree from the root: root-attached strings count under the
    # root name, children of the root (or of an arch wrapper) are sections
    walk(layout, layout.name, 0)

    hist = sorted(tag_histogram.items(), key=lambda kv: (-kv[1], kv[0]))
    high_value.sort(key=lambda s: relevance_key(s, DEFAULT_TAG_RULES))
    return dict(section_counts), hist, high_value


def metadata_rows(results: ResultDocument) -> List[Tuple[str, str]]:
    meta = results.metadata
    rows: List[Tuple[str, str]] = [
        (width("file path", MIN_WIDTH_LEFT_COL), width(meta.file_path, MIN_WIDTH_RIGHT_COL)),
    ]
    if meta.md5:
        rows.append(("md5", meta.md5))
    if meta.sha1:
        rows.append(("sha1", meta.sha1))
    if meta.sha256:
        rows.append(("sha256", meta.sha256))
    if meta.language:
        rows.append(("identified language", language_value(results)))
    rows.extend(
        [
            ("runtime", strtime(meta.runtime.total)),
            ("version", meta.version),
            ("imagebase", f"0x{meta.imagebase:x}"),
            ("min string length", f"{meta.min_length}"),
        ]
    )
    return rows


def counts_rows(results: ResultDocument) -> List[Tuple[str, int]]:
    strings = results.strings
    a = results.analysis
    return [
        ("static strings", len(strings.static_strings) if a.enable_static_strings else 0),
        ("language strings", len(strings.language_strings) if a.enable_language_strings else 0),
        ("stack strings", len(strings.stack_strings) if a.enable_stack_strings else 0),
        ("tight strings", len(strings.tight_strings) if a.enable_tight_strings else 0),
        ("decoded strings", len(strings.decoded_strings) if a.enable_decoded_strings else 0),
    ]


def render_pipe_table(rows: Sequence[Tuple[str, object]]) -> str:
    """render a two-column table with markdown-style pipe separators.

    agents can parse the output without rich box-drawing characters.
    """
    return "\n".join("| %s | %s |" % (left, right) for left, right in rows)


def render_summary(results: ResultDocument, color: str = "auto") -> str:
    """render a concise summary of ``results`` as text.

    The summary is a human- and agent-consumable view over the same
    ``ResultDocument`` that ``--json`` emits.
    """
    sys.__stdout__.reconfigure(encoding="utf-8")  # type: ignore [union-attr]
    console = Console(file=io.StringIO(), color_system=get_color(color), highlight=False, soft_wrap=True)

    console.print(f"FLOSS SUMMARY (version {results.metadata.version})\n")

    console.print(heading_style("sample"))
    console.print(render_pipe_table(metadata_rows(results)))
    console.print()

    console.print(heading_style("string counts"))
    console.print(render_pipe_table(counts_rows(results)))
    console.print()

    # the layout tree is the static-string view; only shown when statics are on
    if results.layout is not None and results.analysis.enable_static_strings:
        section_counts, tag_hist, high_value = analyze_layout(results.layout)

        console.print(heading_style("section counts"))
        console.print(render_pipe_table(list(section_counts.items())))
        console.print()

        if tag_hist:
            console.print(heading_style("tag histogram"))
            console.print(render_pipe_table(tag_hist))
            console.print()

        if high_value:
            console.print(heading_style("high-value strings"))
            console.print("| tag | offset | string |")
            console.print("|---|---|---|")
            for s in high_value[:HIGH_VALUE_MAX_STRINGS]:
                # escape Rich markup and control chars so binary strings render
                # as literal text instead of crashing or breaking the table
                tags = ", ".join(get_visible_tags(s))
                console.print("| %s | 0x%x | %s |" % (tags, s.offset, escape(sanitize(s.string))))
            if len(high_value) > HIGH_VALUE_MAX_STRINGS:
                console.print(f"... and {len(high_value) - HIGH_VALUE_MAX_STRINGS} more high-value strings")

    console.file.seek(0)
    return console.file.read()

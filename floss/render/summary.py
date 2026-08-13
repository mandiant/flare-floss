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
high-value (non-noisy) tags. Meant for human consumers and agents, so it is
pretty printed with tables.
"""

from __future__ import annotations

import io
import sys
from typing import Dict, List, Tuple
from collections import Counter

from rich import box
from rich.table import Table
from rich.console import Console

from floss.results import ResultLayout, ResultString, ResultDocument
from floss.render.filter import NOISY_TAGS
from floss.render.default import (
    MIN_WIDTH_LEFT_COL,
    MIN_WIDTH_RIGHT_COL,
    width,
    strtime,
    get_color,
    language_value,
)

HIGH_VALUE_MAX_STRINGS = 25


def analyze_layout(layout: ResultLayout):
    """walk the layout tree once, returning the derived summary values.

    returns a 3-tuple of (section_counts, tag_histogram, high_value_strings).
    """
    section_counts: Dict[str, int] = Counter()
    tag_histogram: Counter = Counter()
    high_value: List[ResultString] = []

    def walk(node: ResultLayout, section: str) -> None:
        section_counts[section] += len(node.strings)
        for s in node.strings:
            tag_histogram.update(s.tags)
            if any(tag not in NOISY_TAGS for tag in s.tags):
                high_value.append(s)
        for child in node.children:
            walk(child, child.name)

    for child in layout.children:
        walk(child, child.name)

    hist = sorted(tag_histogram.items(), key=lambda kv: (-kv[1], kv[0]))
    high_value.sort(key=lambda s: (-len(s.tags), s.offset))
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
    return [
        ("static strings", len(strings.static_strings)),
        ("language strings", len(strings.language_strings)),
        ("stack strings", len(strings.stack_strings)),
        ("tight strings", len(strings.tight_strings)),
        ("decoded strings", len(strings.decoded_strings)),
    ]


def render_summary(results: ResultDocument, color: str = "auto") -> str:
    """render a concise summary of ``results`` as text.

    The summary is a human- and agent-consumable view over the same
    ``ResultDocument`` that ``--json`` emits.
    """
    sys.__stdout__.reconfigure(encoding="utf-8")  # type: ignore [union-attr]
    console = Console(file=io.StringIO(), color_system=get_color(color), highlight=False, soft_wrap=True)

    console.print(f"FLOSS SUMMARY (version {results.metadata.version})\n")

    console.print("[cyan]sample[/cyan]")
    meta_table = Table(box=box.ASCII2, show_header=False)
    for left, right in metadata_rows(results):
        meta_table.add_row(left, right)
    console.print(meta_table)
    console.print()

    console.print("[cyan]string counts[/cyan]")
    counts_table = Table(box=box.ASCII2, show_header=False)
    for label, count in counts_rows(results):
        counts_table.add_row(width(label, MIN_WIDTH_LEFT_COL), str(count))
    console.print(counts_table)
    console.print()

    if results.layout is not None:
        section_counts, tag_hist, high_value = analyze_layout(results.layout)

        console.print("[cyan]section counts[/cyan]")
        section_table = Table(box=box.ASCII2, show_header=False)
        for section, count in section_counts.items():
            section_table.add_row(width(section, MIN_WIDTH_LEFT_COL), str(count))
        console.print(section_table)
        console.print()

        if tag_hist:
            console.print("[cyan]tag histogram[/cyan]")
            tag_table = Table(box=box.ASCII2, show_header=False)
            for tag, count in tag_hist:
                tag_table.add_row(width(tag, MIN_WIDTH_LEFT_COL), str(count))
            console.print(tag_table)
            console.print()

        if high_value:
            console.print("[cyan]high-value strings[/cyan]")
            high_table = Table("tag", "offset", "string", show_header=True, box=box.ASCII2, show_edge=False)
            for s in high_value[:HIGH_VALUE_MAX_STRINGS]:
                high_table.add_row(", ".join(sorted(s.tags)), f"0x{s.offset:x}", s.string)
            console.print(high_table)
            if len(high_value) > HIGH_VALUE_MAX_STRINGS:
                console.print(f"... and {len(high_value) - HIGH_VALUE_MAX_STRINGS} more high-value strings")

    console.file.seek(0)
    return console.file.read()

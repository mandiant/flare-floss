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
interesting (non-noisy) tags. Intended for human consumers: agents should use
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
from floss.render.filter import (
    NOISY_TAGS,
    relevance_key,
    is_interesting,
    is_section_child,
    is_macho_arch_wrapper,
)
from floss.render.layout import get_visible_tags
from floss.render.default import (
    DEFAULT_TAG_RULES,
    get_color,
    heading_style,
    language_value,
)
from floss.render.sanitize import sanitize

INTERESTING_MAX_STRINGS = 25
INTERESTING_MAX_STRINGS_PER_SECTION = 5


def analyze_layout(layout: ResultLayout):
    """walk the layout tree once, returning the derived summary values.

    returns a 3-tuple of (section_counts, tag_histogram, interesting_strings).
    The section of a string is its containing top-level section: children of
    the root (or of a Mach-O fat-arch wrapper) are the sections, and deeper
    nodes inherit their section (so strings under a nested ``import table``
    node are counted under ``.rdata``).
    """
    section_counts: Dict[str, int] = {}
    tag_histogram: Counter = Counter()
    interesting_map: Dict[Tuple[str, str], Tuple[ResultString, int, set]] = {}

    def walk(node: ResultLayout, section: str, depth: int) -> None:
        if section not in section_counts:
            section_counts[section] = 0
        section_counts[section] += len(node.strings)
        for s in node.strings:
            tag_histogram.update(s.tags)
            if is_interesting(s.tags, DEFAULT_TAG_RULES):
                key = (s.string, section)
                if key not in interesting_map:
                    interesting_map[key] = (s, 1, set(s.tags))
                else:
                    existing_s, count, tags = interesting_map[key]
                    tags.update(s.tags)
                    best_s = s if s.offset < existing_s.offset else existing_s
                    interesting_map[key] = (best_s, count + 1, tags)
        for child in node.children:
            if is_section_child(node, child, depth):
                child_section = child.name
            elif is_macho_arch_wrapper(child):
                child_section = child.name
            else:
                child_section = section
            walk(child, child_section, depth + 1)

    # walk the whole tree from the root: root-attached strings count under the
    # root name, children of the root (or of an arch wrapper) are sections
    walk(layout, layout.name, 0)

    hist = sorted(tag_histogram.items(), key=lambda kv: (-kv[1], kv[0]))

    interesting = []
    for (string_val, section), (best_s, count, tags) in interesting_map.items():
        s_copy = ResultString(
            string=best_s.string,
            offset=best_s.offset,
            size=best_s.size,
            encoding=best_s.encoding,
            tags=list(tags),
            structure=best_s.structure,
        )
        interesting.append((s_copy, count, section))

    interesting.sort(key=lambda item: relevance_key(item[0], DEFAULT_TAG_RULES))
    return dict(section_counts), hist, interesting


def render_summary(results: ResultDocument, color: str = "auto") -> str:
    """render a token-efficient summary of ``results`` as text.

    The summary is a human- and agent-consumable view over the same
    ``ResultDocument`` that ``--json`` emits.
    """
    sys.__stdout__.reconfigure(encoding="utf-8")  # type: ignore [union-attr]
    console = Console(
        file=io.StringIO(),
        color_system=get_color(color),
        highlight=False,
        soft_wrap=True,
    )

    console.print(f"FLOSS SUMMARY (version {results.metadata.version})")

    # 1a. Metadata
    meta = results.metadata
    meta_pairs = [("file_path", meta.file_path)]
    if meta.md5:
        meta_pairs.append(("md5", meta.md5))
    if meta.sha256:
        meta_pairs.append(("sha256", meta.sha256))
    if meta.language:
        meta_pairs.append(("language", language_value(results)))

    meta_pairs.extend(
        [
            ("imagebase", f"0x{meta.imagebase:x}"),
            ("min_length", f"{meta.min_length}"),
        ]
    )
    console.print(heading_style("file details"))
    for km, vm in meta_pairs:
        console.print(f"{km:<15} {vm}")
    console.print()

    # 1b. Counts
    strings = results.strings
    a = results.analysis
    count_pairs = [
        ("static", len(strings.static_strings) if a.enable_static_strings else 0),
        ("language", len(strings.language_strings) if a.enable_language_strings else 0),
        ("stack", len(strings.stack_strings) if a.enable_stack_strings else 0),
        ("tight", len(strings.tight_strings) if a.enable_tight_strings else 0),
        ("decoded", len(strings.decoded_strings) if a.enable_decoded_strings else 0),
    ]
    console.print(heading_style("extracted strings"))
    for kc, vc in count_pairs:
        console.print(f"{kc:<15} {vc}")
    console.print()

    if results.layout is not None and results.analysis.enable_static_strings:
        section_counts, tag_hist, interesting = analyze_layout(results.layout)

        if tag_hist:
            console.print(heading_style("strings by tag"))
            for kt, vt in tag_hist:
                console.print(f"{kt:<15} {vt}")
            console.print()

        # 1c. High Value Strings (Integrated Physical Map)
        if interesting or section_counts:
            console.print(heading_style("preview"))

            # Map interesting strings by section
            sec_to_interesting: Dict[str, List[Tuple[ResultString, int]]] = {}
            for s, c_val, sec in interesting:
                if sec not in sec_to_interesting:
                    sec_to_interesting[sec] = []
                sec_to_interesting[sec].append((s, c_val))

            # Pick strings reflecting per-section cap and global cap
            picked_strings_by_sec: Dict[str, List[Tuple[ResultString, int]]] = {}
            total_picked = 0
            for s, c_val, sec in interesting:
                if sec not in picked_strings_by_sec:
                    picked_strings_by_sec[sec] = []
                if len(picked_strings_by_sec[sec]) < INTERESTING_MAX_STRINGS_PER_SECTION:
                    if total_picked < INTERESTING_MAX_STRINGS:
                        picked_strings_by_sec[sec].append((s, c_val))
                        total_picked += 1
                        if total_picked >= INTERESTING_MAX_STRINGS:
                            break

            # Sort within sections by physical offset
            for sec in picked_strings_by_sec:
                picked_strings_by_sec[sec].sort(key=lambda item: item[0].offset)

            is_first_section = True
            for section, total_count in section_counts.items():
                if section == results.layout.name and total_count == 0:
                    continue

                if not is_first_section:
                    console.print()
                is_first_section = False

                all_interesting_in_sec = sec_to_interesting.get(section, [])
                num_interesting = len(all_interesting_in_sec)

                # Format section header without dashes
                picked_count = len(picked_strings_by_sec.get(section, []))

                if num_interesting > 0:
                    if picked_count < num_interesting:
                        stats = f"showing {picked_count} of {num_interesting} interesting strings | {total_count} total"
                    else:
                        stats = f"{num_interesting} interesting strings | {total_count} total"
                else:
                    stats = f"{total_count} total strings"

                if section == "macho (fat)":
                    hdr = rf"[cyan bold]fat wrapper[/cyan bold] [dim]({stats})[/dim]"
                else:
                    hdr = rf"[cyan bold]\[{escape(section)}][/cyan bold] [dim]({stats})[/dim]"

                # Render header
                console.print(hdr)

                # Render picked interesting strings
                picked = picked_strings_by_sec.get(section, [])
                for s, count in picked:
                    from rich.text import Text

                    raw_string = sanitize(s.string)
                    count_str = f" (count: {count})" if count > 1 else ""

                    string_text = Text(raw_string)
                    if count > 1:
                        string_text.append(count_str, style="dim")
                    string_text.truncate(80, overflow="ellipsis", pad=True)

                    visible_tags = get_visible_tags(s)
                    tags = f"[{', '.join(visible_tags)}]" if visible_tags else ""

                    tags_text = Text(tags)
                    tags_text.truncate(25, overflow="ellipsis", pad=True)

                    offset_text = Text(f"0x{s.offset:x}", style="dim")

                    line = Text()
                    line.append_text(string_text)
                    line.append(" ")
                    line.append_text(tags_text)
                    line.append(" ")
                    line.append_text(offset_text)

                    console.print(line)

        console.print()

    console.file.seek(0)
    return console.file.read()

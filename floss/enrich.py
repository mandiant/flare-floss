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

"""Project layout analysis onto FLOSS static/language string results."""

from __future__ import annotations

from typing import Dict, List, Tuple, Optional

from floss.results import ResultLayout, ResultString, StaticString, StringEncoding


def layout_encoding_to_string_encoding(encoding: str) -> StringEncoding:
    if encoding == "unicode":
        return StringEncoding.UTF16LE
    if encoding == "utf-8":
        return StringEncoding.UTF8
    return StringEncoding.ASCII


def is_structured_layout(layout_name: str) -> bool:
    """True when compute_layout produced PE/ELF/Mach-O (not the binary fallback)."""
    name = layout_name.lower()
    return name in ("pe", "elf") or name.startswith("macho")


def _walk_offset_index(
    layout: ResultLayout,
    index: Dict[int, Tuple[ResultString, str]],
) -> None:
    for s in layout.strings:
        index[s.offset] = (s, layout.name)
    for child in layout.children:
        _walk_offset_index(child, index)


def build_offset_index(layout: ResultLayout) -> Dict[int, Tuple[ResultString, str]]:
    """Map file offset → (ResultString, containing layout node name)."""
    index: Dict[int, Tuple[ResultString, str]] = {}
    _walk_offset_index(layout, index)
    return index


def static_strings_from_layout(layout: ResultLayout) -> List[StaticString]:
    """Flatten a serializable layout tree into enriched StaticString values."""
    index = build_offset_index(layout)
    # stable order by offset
    items = sorted(index.items(), key=lambda kv: kv[0])
    out: List[StaticString] = []
    for offset, (rs, section) in items:
        out.append(
            StaticString(
                string=rs.string,
                offset=offset,
                encoding=layout_encoding_to_string_encoding(rs.encoding),
                tags=list(rs.tags),
                section=section,
                structure=rs.structure or "",
            )
        )
    return out


def enrich_static_string(
    s: StaticString,
    offset_index: Dict[int, Tuple[ResultString, str]],
) -> StaticString:
    """Copy tags/section/structure from layout for a string with a file offset."""
    hit = offset_index.get(s.offset)
    if not hit:
        return s
    rs, section = hit
    return StaticString(
        string=s.string,
        offset=s.offset,
        encoding=s.encoding,
        tags=list(rs.tags),
        section=section,
        structure=rs.structure or "",
    )


def enrich_static_strings(
    strings: List[StaticString],
    layout: Optional[ResultLayout],
) -> List[StaticString]:
    if layout is None:
        return strings
    index = build_offset_index(layout)
    return [enrich_static_string(s, index) for s in strings]

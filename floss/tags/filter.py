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

"""Visibility filters and false-positive library tag cleanup."""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Literal

from floss.results import ResultLayout, ResultString
from floss.tags.oss import DEFAULT_FILENAMES

if TYPE_CHECKING:
    from floss.layout.base import Layout

Tag = str
TagRules = Dict[Tag, Literal["mute"] | Literal["highlight"] | Literal["default"] | Literal["hide"]]

# hack: assume the libname is embedded in the filename.
# otherwise, we don't have an easy way to recover the library tag names.
# the CRT database file (crt/msvc_v143.jsonl.gz) tags its strings as #msvc.
MSVC_TAG = "#msvc"
LIBRARY_TAGS = tuple(f"#{filename.partition('.')[0]}" for filename in DEFAULT_FILENAMES) + (MSVC_TAG,)


def remove_msvc_tags_outside_pe(layout: "Layout", in_non_pe: bool = False):
    """Drop #msvc from strings of ELF and Mach-O files, which are never linked against the MSVC CRT.

    The CRT database holds common words, like "name" or "error", that otherwise match in any binary.
    A PE embedded in such a file keeps its tags: the nearest enclosing file format decides.
    """
    from floss.layout.base import PELayout, ELFLayout, MachOLayout, MachOFatLayout

    if isinstance(layout, PELayout):
        in_non_pe = False
    elif isinstance(layout, (ELFLayout, MachOLayout, MachOFatLayout)):
        in_non_pe = True

    if in_non_pe:
        for string in layout.strings:
            string.tags.discard(MSVC_TAG)

    for child in layout.children:
        remove_msvc_tags_outside_pe(child, in_non_pe)


def remove_false_positive_lib_strings(layout: "Layout"):
    from floss.layout.extract import collect_strings

    remove_msvc_tags_outside_pe(layout)

    # list of references to all the tagged strings across the layout.
    # we can (carefully) manipulate the tags here.
    tagged_strings = collect_strings(layout)

    # libraries (open source and the MSVC CRT) should have at least 5 strings,
    # or don't show their tag, since the couple hits are probably false positives.
    for tagname in LIBRARY_TAGS:
        count = 0
        for string in tagged_strings:
            if tagname in string.tags:
                count += 1

        if 0 < count < 5:
            # I picked 5 as a reasonable threshold.
            # we could research what a better value is.
            #
            # also note that large binaries with many strings have
            # a higher chance of false positives, even with this threshold.
            # this is still a useful filter, though.
            for string in tagged_strings:
                if tagname in string.tags:
                    string.tags.remove(tagname)


def should_hide_string(s: ResultString, tag_rules: TagRules) -> bool:
    return any(tag_rules.get(tag) == "hide" for tag in s.tags)


def hide_strings_by_rules(layout: ResultLayout, tag_rules: TagRules) -> ResultLayout:
    """Return a new layout tree with hide-rule strings removed.

    Does not mutate ``layout`` or its children, so callers can render a
    filtered view without deep-copying the original result document.
    """
    return ResultLayout(
        name=layout.name,
        offset=layout.offset,
        length=layout.length,
        strings=[s for s in layout.strings if not should_hide_string(s, tag_rules)],
        children=[hide_strings_by_rules(child, tag_rules) for child in layout.children],
    )

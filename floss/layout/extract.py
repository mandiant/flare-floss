# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Extract and collect strings within a layout tree."""

from __future__ import annotations

from typing import List

from floss.ranges import Range, Slice
from floss.layout.base import Layout
from floss.layout.types import extract_strings, TaggedString


def extract_layout_strings(layout: Layout, min_len: int):
    if not layout.children:
        # all the strings are found in this slice directly.

        # at this moment, layout.strings contains only ExtractedStrings
        # after layout.tag_strings, it will contain TaggedStrings.
        layout.strings = extract_strings(layout.slice, min_len)  # type: ignore
        return

    else:
        # we have children, so we need to recurse to find their strings,
        # and also find strings in the gaps between children.
        # lets find the gap strings first:
        for i, child in enumerate(layout.children):
            if i == 0:
                # find the strings before the first child
                offset = 0
                size = layout.children[0].offset - layout.offset

            else:
                # find strings between children
                prior = layout.children[i - 1]
                offset = prior.end - layout.offset
                size = child.offset - prior.end

            if size == 0:
                # there is no gap here.
                continue

            gap = layout.slice.slice(offset, size)

            # at this moment, layout.strings contains only ExtractedStrings
            # after layout.tag_strings, it will contain TaggedStrings.
            layout.strings.extend(extract_strings(gap, min_len))  # type: ignore

        # finally, find strings after the last child
        last_child = layout.children[-1]
        offset = last_child.end - layout.offset
        size = layout.end - last_child.end

        if size > 0:
            gap = layout.slice.slice(offset, size)
            # at this moment, layout.strings contains only ExtractedStrings
            # after layout.tag_strings, it will contain TaggedStrings.
            layout.strings.extend(extract_strings(gap, min_len))  # type: ignore

        # now recurse to find the strings in the children.
        for child in layout.children:
            extract_layout_strings(child, min_len)

        if layout.strings:
            child_ranges = [(child.offset, child.end) for child in layout.children]
            filtered = []
            for string in layout.strings:
                if isinstance(string, TaggedString):
                    offset = string.offset
                else:
                    offset = string.slice.range.offset
                if any(start <= offset < end for start, end in child_ranges):
                    continue
                filtered.append(string)
            layout.strings = filtered


def collect_strings(layout: Layout) -> List[TaggedString]:
    ret = []

    ret.extend(layout.strings)

    for child in layout.children:
        ret.extend(collect_strings(child))

    return ret


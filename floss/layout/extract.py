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

"""Extract and collect strings within a layout tree."""

from __future__ import annotations

import re
import itertools
from typing import List, Iterable

from floss.ranges import Slice
from floss.layout.base import Layout
from floss.layout.types import TaggedString, ExtractedString

MIN_STR_LEN = 4
# we don't include \r and \n to make output easier to understand by humans and to simplify rendering
ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
ASCII_RE_MIN = re.compile(b"([%s]{%d,})" % (ASCII_BYTE, MIN_STR_LEN))
UNICODE_RE_MIN = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, MIN_STR_LEN))


def extract_ascii_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate ASCII strings in the given binary data"

    if not slice.range.length:
        return

    r: re.Pattern
    if n == MIN_STR_LEN:
        r = ASCII_RE_MIN
    else:
        reg = b"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)

    for match in r.finditer(slice.data):
        offset = match.start()
        length = match.end() - match.start()
        string = match.group().decode("ascii")
        yield ExtractedString(string=string, slice=slice.slice(offset, length), encoding="ascii")


def extract_unicode_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate naive UTF-16 strings in the given binary data"

    if not slice.range.length:
        return

    r: re.Pattern
    if n == MIN_STR_LEN:
        r = UNICODE_RE_MIN
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)

    for match in r.finditer(slice.data):
        offset = match.start()
        length = match.end() - match.start()

        try:
            string = match.group().decode("utf-16")
        except UnicodeDecodeError:
            continue

        yield ExtractedString(string=string, slice=slice.slice(offset, length), encoding="unicode")


def extract_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate ASCII and naive UTF-16 strings in the given binary data"
    return list(
        sorted(
            itertools.chain(extract_ascii_strings(slice, n), extract_unicode_strings(slice, n)),
            key=lambda s: s.slice.range.offset,
        )
    )


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

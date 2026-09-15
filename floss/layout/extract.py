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

import itertools
from typing import List, Literal, Iterable

from floss import strings as floss_strings
from floss.ranges import Slice
from floss.results import StaticString, StringEncoding
from floss.layout.base import Layout
from floss.layout.types import TaggedString, ExtractedString

MIN_STR_LEN = floss_strings.MIN_LENGTH


def _to_extracted(s: StaticString, slice: Slice) -> ExtractedString:
    encoding: Literal["ascii", "unicode"]
    if s.encoding == StringEncoding.UTF16LE:
        encoding = "unicode"
        byte_len = len(s.string) * 2
    else:
        encoding = "ascii"
        byte_len = len(s.string)

    return ExtractedString(string=s.string, slice=slice.slice(s.offset, byte_len), encoding=encoding)


def extract_ascii_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate ASCII strings in the given binary data"
    if not slice.range.length:
        return

    for s in floss_strings.extract_ascii_strings(slice.data, n):
        yield _to_extracted(s, slice)


def extract_unicode_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate naive UTF-16 strings in the given binary data"
    if not slice.range.length:
        return

    for s in floss_strings.extract_unicode_strings(slice.data, n):
        yield _to_extracted(s, slice)


def extract_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate ASCII and naive UTF-16 strings in the given binary data"
    return list(
        sorted(
            itertools.chain(extract_ascii_strings(slice, n), extract_unicode_strings(slice, n)),
            key=lambda s: s.slice.range.offset,
        )
    )


def collect_strings(layout: Layout) -> List[TaggedString]:
    ret = []

    ret.extend(layout.strings)

    for child in layout.children:
        ret.extend(collect_strings(child))

    return ret

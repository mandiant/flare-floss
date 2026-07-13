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

"""Layout-derived tags (#code, #reloc, #decoded)."""

from __future__ import annotations

from typing import Sequence

from floss.ranges import OffsetRanges
from floss.layout.types import Tag, ExtractedString


def check_is_xor(xor_key: int | None) -> Sequence[Tag]:
    if isinstance(xor_key, int):
        return ("#decoded",)
    return ()


def check_is_reloc(reloc_offsets: OffsetRanges, string: ExtractedString) -> Sequence[Tag]:
    if reloc_offsets.overlaps(string.slice.range.offset, string.slice.range.end - 1):
        return ("#reloc",)
    return ()


def check_is_code(code_offsets: OffsetRanges, string: ExtractedString) -> Sequence[Tag]:
    if code_offsets.overlaps(string.slice.range.offset, string.slice.range.end - 1):
        return ("#code",)
    return ()

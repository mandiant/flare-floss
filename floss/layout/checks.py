# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Layout-derived tags (#code, #reloc, #decoded)."""

from __future__ import annotations

from typing import Optional, Sequence

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

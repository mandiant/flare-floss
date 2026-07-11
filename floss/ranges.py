# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Contiguous offset ranges and byte slices used by layout analysis."""

from __future__ import annotations

import time
import bisect
import logging
import contextlib
from typing import Set, List, Tuple, Iterable, Optional

from pydantic import Field, BaseModel

logger = logging.getLogger("floss.ranges")


@contextlib.contextmanager
def timing(msg: str):
    t0 = time.time()
    yield
    t1 = time.time()
    logger.debug("perf: %s: %0.2fs", msg, t1 - t0)


class Range(BaseModel):
    "a range of contiguous integer values, such as offsets within a byte sequence"

    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length

    def slice(self, offset, size) -> "Range":
        "create a new range thats a sub-range of this one, using relative offsets"
        assert 0 <= offset <= self.length
        assert 0 <= size
        assert offset + size <= self.length
        return Range(offset=self.offset + offset, length=size)

    def __iter__(self):
        "iterate over the values in this range"
        yield from range(self.offset, self.end)

    def __repr__(self):
        return f"Range(start: 0x{self.offset:x}, size: 0x{self.length:x}, end: 0x{self.end:x})"

    def __str__(self):
        return repr(self)


class Slice(BaseModel):
    """
    a contiguous range within a sequence of bytes.
    notably, it can be further sliced without copying the underlying bytes.
    a bit like a memoryview.
    """

    buf: bytes
    range: Range
    base_offset: int = 0

    @property
    def offset(self) -> int:
        return self.range.offset

    @property
    def data(self) -> bytes:
        "get the bytes in this slice, copying the data out"
        return self.buf[self.range.offset - self.base_offset : self.range.end - self.base_offset]

    def slice(self, offset, size) -> "Slice":
        "create a new slice thats a sub-slice of this one, using relative offsets"
        return Slice(buf=self.buf, range=self.range.slice(offset, size), base_offset=self.base_offset)

    def contains_range(self, offset: int, size: int) -> bool:
        """
        checks if this slice contains the given range,
        where offset is relative to the start of this slice.
        """
        if not (0 <= offset <= self.range.length):
            return False

        if size < 0:
            return False

        if (offset + size) > self.range.length:
            return False

        return True

    @classmethod
    def from_bytes(cls, buf: bytes) -> "Slice":
        return cls(buf=buf, range=Range(offset=0, length=len(buf)))

    def __repr__(self):
        buf_len = len(self.buf) if self.buf is not None else 0
        return f"Slice({repr(self.range)} of bytes of size 0x{buf_len:x})"

    def __str__(self):
        return repr(self)


class OffsetRanges(BaseModel):
    ranges: list[tuple[int, int]] = Field(default_factory=list)

    @classmethod
    def from_offsets(cls, offsets: Set[int]) -> "OffsetRanges":
        """given a bunch of number, return the contiguous spans (start, end).

        example:

            {1, 2, 3, 5, 6, 9} -> [(1, 3), (5, 6), (9, 9)]
        """
        if not offsets:
            return cls(ranges=[])

        if len(offsets) == 1:
            v = next(iter(offsets))
            return cls(ranges=[(v, v)])

        sorted_offsets = list(sorted(offsets))
        ranges: List[Tuple[int, int]] = []
        start = sorted_offsets[0]
        end = start
        for offset in sorted_offsets[1:]:
            if offset == end + 1:
                end = offset
            else:
                ranges.append((start, end))
                start = offset
                end = offset
        ranges.append((start, end))

        return cls(ranges=ranges)

    @classmethod
    def from_merged_ranges(cls, merged_ranges: List[Tuple[int, int]]) -> "OffsetRanges":
        return cls(ranges=merged_ranges)

    def __contains__(self, offset: int) -> bool:
        if not self.ranges:
            return False

        # Find the index where the offset would be inserted to maintain order.
        index = bisect.bisect_left(self.ranges, (offset, 0))

        # Check the range at the insertion index.
        # This handles cases where the offset is the start of a range.
        if index < len(self.ranges):
            start, end = self.ranges[index]
            if start == offset:
                return True

        # Check the range just before the insertion index.
        # This handles cases where the offset is within or at the end of a range.
        if index > 0:
            start, end = self.ranges[index - 1]
            if start <= offset <= end:
                return True

        return False

    def overlaps(self, start: int, end: int) -> bool:
        if not self.ranges:
            return False

        # Find the index where the start of the given range would be inserted
        index = bisect.bisect_right(self.ranges, (start, 0))

        # Check the range at index-1 for overlap
        if index > 0:
            prev_start, prev_end = self.ranges[index - 1]
            if max(start, prev_start) <= min(end, prev_end):
                return True

        # Check the range at index for overlap
        if index < len(self.ranges):
            next_start, next_end = self.ranges[index]
            if max(start, next_start) <= min(end, next_end):
                return True

        return False

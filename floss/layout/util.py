# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for layout construction."""

from __future__ import annotations

from typing import List, Tuple


def _merge_overlapping_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """
    Merge a list of (start, end) tuples into a list of contiguous ranges.
    """
    if not ranges:
        return []

    sorted_ranges = sorted(ranges)
    merged_ranges: List[Tuple[int, int]] = []
    for higher in sorted_ranges:
        if not merged_ranges:
            merged_ranges.append(higher)
        else:
            lower = merged_ranges[-1]
            lower_start, lower_end = lower
            higher_start, higher_end = higher

            # test for intersection between lower and higher:
            # we know via sorting that lower_start <= higher_start
            if higher_start <= lower_end + 1:
                upper_bound = max(lower_end, higher_end)
                merged_ranges[-1] = (lower_start, upper_bound)
            else:
                merged_ranges.append(higher)
    return merged_ranges

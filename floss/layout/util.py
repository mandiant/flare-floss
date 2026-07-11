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

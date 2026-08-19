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

from unittest.mock import Mock, MagicMock

import pefile
import pytest

from floss.ranges import Range, Slice, merge_overlapping_ranges
from floss.layout.pe import _get_code_ranges


# Tests for merge_overlapping_ranges
def test_merge_empty_list():
    """Test merging an empty list of ranges."""
    assert merge_overlapping_ranges([]) == []


def test_merge_no_overlap():
    """Test merging ranges that do not overlap."""
    ranges = [(10, 20), (30, 40), (50, 60)]
    assert merge_overlapping_ranges(ranges) == [(10, 20), (30, 40), (50, 60)]


def test_merge_with_overlap():
    """Test merging ranges that partially overlap."""
    ranges = [(10, 20), (15, 25), (30, 40)]
    assert merge_overlapping_ranges(ranges) == [(10, 25), (30, 40)]


def test_merge_adjacent():
    """Test merging ranges that are right next to each other."""
    ranges = [(10, 20), (21, 30), (31, 40)]
    assert merge_overlapping_ranges(ranges) == [(10, 40)]


def test_merge_fully_contained():
    """Test merging ranges where some are fully contained within others."""
    ranges = [(10, 40), (15, 25), (20, 30)]
    assert merge_overlapping_ranges(ranges) == [(10, 40)]


def test_merge_complex_mix():
    """Test a complex mixture of overlapping, adjacent, and contained ranges."""
    ranges = [(50, 60), (10, 20), (18, 30), (35, 40), (39, 55)]
    # After sorting: [(10, 20), (18, 30), (35, 40), (39, 55), (50, 60)]
    # (10, 20) and (18, 30) -> (10, 30)
    # (35, 40) and (39, 55) -> (35, 55)
    # (35, 55) and (50, 60) -> (35, 60)
    assert merge_overlapping_ranges(ranges) == [(10, 30), (35, 60)]


# Tests for _get_code_ranges
@pytest.fixture
def mock_pe():
    """Fixture for a mocked pefile.PE object."""
    pe = MagicMock(spec=pefile.PE)

    def get_offset_from_rva(rva):
        # Simple mapping for testing: offset is just rva + 0x1000
        return rva + 0x1000

    pe.get_offset_from_rva.side_effect = get_offset_from_rva
    return pe


def _make_instr(size: int) -> Mock:
    instr = Mock()
    instr.raw_bytes = b"\x90" * size
    return instr


def _make_be2_mocks(bb_instructions: list):
    """
    Build mock be2 and idx objects.

    bb_instructions: list of lists of (va, size) tuples, one sub-list per basic block.
    """
    be2 = MagicMock()
    idx = MagicMock()

    basic_blocks = {}
    instr_map = {}
    for bb_i, instrs in enumerate(bb_instructions):
        bb = Mock()
        basic_blocks[bb_i] = bb
        instr_map[id(bb)] = [(i, _make_instr(sz), va) for i, (va, sz) in enumerate(instrs)]

    fg = Mock()
    fg.basic_block_index = list(range(len(basic_blocks)))
    be2.flow_graph = [fg]
    be2.basic_block = basic_blocks

    def _bb_instructions(bb):
        return iter(instr_map.get(id(bb), []))

    idx.basic_block_instructions.side_effect = _bb_instructions

    return be2, idx


def test_get_code_ranges_basic(mock_pe):
    """Test basic extraction of code ranges."""
    # base_address = 0x400000, rva = va - base
    # bb1: va 0x401000, size 0x10 -> rva 0x1000, offset 0x2000 -> range (0x2000, 0x200F)
    # bb2: va 0x401020, size 0x15 -> rva 0x1020, offset 0x2020 -> range (0x2020, 0x2034)
    # bb3: va 0x402000, size 0x20 -> rva 0x2000, offset 0x3000 -> range (0x3000, 0x301F)
    be2, idx = _make_be2_mocks(
        [
            [(0x401000, 0x10)],
            [(0x401020, 0x15)],
            [(0x402000, 0x20)],
        ]
    )

    slice_ = Slice(buf=b"", range=Range(offset=0, length=0x5000))

    ranges = _get_code_ranges(be2, idx, 0x400000, mock_pe, slice_)

    assert ranges == [
        (0x2000, 0x200F),  # bb1: offset 0x2000, size 0x10
        (0x2020, 0x2034),  # bb2: offset 0x2020, size 0x15
        (0x3000, 0x301F),  # bb3: offset 0x3000, size 0x20
    ]


def test_get_code_ranges_skips_invalid_offset(mock_pe):
    """Test that it skips instructions that fall outside the slice."""
    be2, idx = _make_be2_mocks(
        [
            [(0x401000, 0x10)],  # offset 0x2000, fits in slice
            [(0x401020, 0x15)],  # offset 0x2020, outside slice
            [(0x402000, 0x20)],  # offset 0x3000, outside slice
        ]
    )

    # Slice only covers through offset 0x2010
    slice_ = Slice(buf=b"", range=Range(offset=0, length=0x2010))

    ranges = _get_code_ranges(be2, idx, 0x400000, mock_pe, slice_)

    # Only bb1 should be included
    assert ranges == [(0x2000, 0x200F)]


def test_get_code_ranges_handles_pe_error(mock_pe):
    """Test that it handles PEFormatError when getting an offset."""

    def get_offset_from_rva_with_error(rva):
        if rva == 0x1020:  # Corresponds to bb2
            raise pefile.PEFormatError("Test Error")
        return rva + 0x1000

    mock_pe.get_offset_from_rva.side_effect = get_offset_from_rva_with_error

    be2, idx = _make_be2_mocks(
        [
            [(0x401000, 0x10)],
            [(0x401020, 0x15)],
            [(0x402000, 0x20)],
        ]
    )

    slice_ = Slice(buf=b"", range=Range(offset=0, length=0x5000))

    ranges = _get_code_ranges(be2, idx, 0x400000, mock_pe, slice_)

    # bb2 should be skipped due to PEFormatError
    assert ranges == [
        (0x2000, 0x200F),
        (0x3000, 0x301F),
    ]

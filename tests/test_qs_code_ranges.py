import pytest
from unittest.mock import Mock, MagicMock

import pefile
import lancelot

from floss.qs.main import (
    Slice,
    Range,
    _get_code_ranges,
    _merge_overlapping_ranges,
)


# Tests for _merge_overlapping_ranges
def test_merge_empty_list():
    """Test merging an empty list of ranges."""
    assert _merge_overlapping_ranges([]) == []


def test_merge_no_overlap():
    """Test merging ranges that do not overlap."""
    ranges = [(10, 20), (30, 40), (50, 60)]
    assert _merge_overlapping_ranges(ranges) == [(10, 20), (30, 40), (50, 60)]


def test_merge_with_overlap():
    """Test merging ranges that partially overlap."""
    ranges = [(10, 20), (15, 25), (30, 40)]
    assert _merge_overlapping_ranges(ranges) == [(10, 25), (30, 40)]


def test_merge_adjacent():
    """Test merging ranges that are right next to each other."""
    ranges = [(10, 20), (21, 30), (31, 40)]
    assert _merge_overlapping_ranges(ranges) == [(10, 40)]


def test_merge_fully_contained():
    """Test merging ranges where some are fully contained within others."""
    ranges = [(10, 40), (15, 25), (20, 30)]
    assert _merge_overlapping_ranges(ranges) == [(10, 40)]


def test_merge_complex_mix():
    """Test a complex mixture of overlapping, adjacent, and contained ranges."""
    ranges = [(50, 60), (10, 20), (18, 30), (35, 40), (39, 55)]
    # After sorting: [(10, 20), (18, 30), (35, 40), (39, 55), (50, 60)]
    # (10, 20) and (18, 30) -> (10, 30)
    # (35, 40) and (39, 55) -> (35, 55)
    # (35, 55) and (50, 60) -> (35, 60)
    assert _merge_overlapping_ranges(ranges) == [(10, 30), (35, 60)]


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


@pytest.fixture
def mock_ws():
    """Fixture for a mocked lancelot.Workspace object."""
    ws = MagicMock(spec=lancelot.Workspace)
    ws.base_address = 0x400000

    # Mock functions and basic blocks
    func1 = Mock()
    func2 = Mock()
    ws.get_functions.return_value = [func1, func2]

    bb1 = Mock(address=0x401000, length=0x10)  # rva: 0x1000, offset: 0x2000
    bb2 = Mock(address=0x401020, length=0x15)  # rva: 0x1020, offset: 0x2020
    bb3 = Mock(address=0x402000, length=0x20)  # rva: 0x2000, offset: 0x3000

    # Setup cfg for each function
    cfg1 = Mock(basic_blocks={bb1.address: bb1, bb2.address: bb2})
    cfg2 = Mock(basic_blocks={bb3.address: bb3})

    def build_cfg(func):
        if func == func1:
            return cfg1
        return cfg2

    ws.build_cfg.side_effect = build_cfg
    return ws


def test_get_code_ranges_basic(mock_ws, mock_pe):
    """Test basic extraction of code ranges."""
    # Slice covers the entire mock file
    slice_ = Slice(buf=b"", range=Range(offset=0, length=0x5000))
    ranges = _get_code_ranges(mock_ws, mock_pe, slice_)

    assert ranges == [
        (0x2000, 0x200F),  # bb1: offset 0x2000, size 0x10
        (0x2020, 0x2034),  # bb2: offset 0x2020, size 0x15
        (0x3000, 0x301F),  # bb3: offset 0x3000, size 0x20
    ]


def test_get_code_ranges_skips_invalid_offset(mock_ws, mock_pe):
    """Test that it skips basic blocks that fall outside the slice."""
    # Slice is small and only covers the first basic block
    slice_ = Slice(buf=b"", range=Range(offset=0, length=0x2010))
    ranges = _get_code_ranges(mock_ws, mock_pe, slice_)

    # Only bb1 should be included
    assert ranges == [(0x2000, 0x200F)]


def test_get_code_ranges_handles_pe_error(mock_ws, mock_pe):
    """Test that it handles PEFormatError when getting an offset."""
    # Make one of the RVA lookups fail
    def get_offset_from_rva_with_error(rva):
        if rva == 0x1020:  # Corresponds to bb2
            raise pefile.PEFormatError("Test Error")
        return rva + 0x1000

    mock_pe.get_offset_from_rva.side_effect = get_offset_from_rva_with_error

    slice_ = Slice(buf=b"", range=Range(offset=0, length=0x5000))
    ranges = _get_code_ranges(mock_ws, mock_pe, slice_)

    # bb2 should be skipped
    assert ranges == [
        (0x2000, 0x200F),
        (0x3000, 0x301F),
    ]

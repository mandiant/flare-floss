import pytest

from floss.qs.main import OffsetRanges


def test_offset_ranges_init_empty():
    """Test initialization with no offsets."""
    offsets: set[int] = set()
    ranges = OffsetRanges.from_offsets(offsets)
    assert ranges.ranges == []


def test_offset_ranges_init():
    """Test initialization with a mix of contiguous and non-contiguous offsets."""
    offsets = {0, 1, 2, 5, 6, 8, 10}
    ranges = OffsetRanges.from_offsets(offsets)
    assert ranges.ranges == [(0, 2), (5, 6), (8, 8), (10, 10)]


def test_offset_ranges_init_single_range():
    """Test initialization with a single contiguous block of offsets."""
    offsets = {10, 11, 12, 13, 14}
    ranges = OffsetRanges.from_offsets(offsets)
    assert ranges.ranges == [(10, 14)]


def test_offset_ranges_from_merged_ranges():
    """Test the from_merged_ranges class method."""
    merged = [(10, 20), (30, 40)]
    ranges = OffsetRanges.from_merged_ranges(merged)
    assert ranges.ranges == [(10, 20), (30, 40)]


@pytest.fixture
def sample_ranges():
    """Provides a standard OffsetRanges instance for testing."""
    # Ranges will be: (10, 15), (20, 25), (30, 30)
    offsets = {10, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24, 25, 30}
    return OffsetRanges.from_offsets(offsets)


def test_contains_empty(sample_ranges):
    """Test __contains__ on an empty OffsetRanges instance."""
    empty_ranges = OffsetRanges()
    assert 10 not in empty_ranges


def test_contains_inside(sample_ranges):
    """Test __contains__ for an offset well within a range."""
    assert 12 in sample_ranges
    assert 23 in sample_ranges


def test_contains_edges(sample_ranges):
    """Test __contains__ for offsets at the exact start and end of ranges."""
    assert 10 in sample_ranges  # Start of first range
    assert 15 in sample_ranges  # End of first range
    assert 20 in sample_ranges  # Start of second range
    assert 25 in sample_ranges  # End of second range
    assert 30 in sample_ranges  # Single-point range


def test_contains_outside(sample_ranges):
    """Test __contains__ for offsets outside of any range."""
    assert 9 not in sample_ranges  # Before first range
    assert 16 not in sample_ranges  # Between ranges
    assert 29 not in sample_ranges  # Between ranges
    assert 31 not in sample_ranges  # After last range


def test_overlaps_empty(sample_ranges):
    """Test overlaps on an empty OffsetRanges instance."""
    empty_ranges = OffsetRanges()
    assert not empty_ranges.overlaps(10, 20)


def test_overlaps_fully_contained(sample_ranges):
    """Test overlaps where the query range is fully inside an existing range."""
    assert sample_ranges.overlaps(11, 14)  # Fully inside (10, 15)
    assert sample_ranges.overlaps(21, 22)  # Fully inside (20, 25)


def test_overlaps_contains_full_range(sample_ranges):
    """Test overlaps where the query range fully contains an existing range."""
    assert sample_ranges.overlaps(9, 16)  # Contains (10, 15)
    assert sample_ranges.overlaps(19, 26)  # Contains (20, 25)
    assert sample_ranges.overlaps(29, 31)  # Contains (30, 30)


def test_overlaps_start(sample_ranges):
    """Test overlaps where the query range overlaps the beginning of an existing range."""
    assert sample_ranges.overlaps(8, 12)  # Overlaps start of (10, 15)
    assert sample_ranges.overlaps(18, 20)  # Touches start of (20, 25)


def test_overlaps_end(sample_ranges):
    """Test overlaps where the query range overlaps the end of an existing range."""
    assert sample_ranges.overlaps(14, 17)  # Overlaps end of (10, 15)
    assert sample_ranges.overlaps(25, 28)  # Touches end of (20, 25)


def test_overlaps_multiple_ranges(sample_ranges):
    """Test overlaps where the query range spans across multiple existing ranges."""
    assert sample_ranges.overlaps(12, 22)  # Spans from first to second range
    assert sample_ranges.overlaps(14, 30)  # Spans all three ranges


def test_no_overlap(sample_ranges):
    """Test overlaps for ranges that do not overlap at all."""
    assert not sample_ranges.overlaps(0, 8)  # Before all ranges
    assert not sample_ranges.overlaps(16, 19)  # Between ranges
    assert not sample_ranges.overlaps(26, 29)  # Between ranges
    assert not sample_ranges.overlaps(31, 40)  # After all ranges


import pytest
from floss.ranges import Range, Slice

def test_range_slice():
    r = Range(offset=10, length=20)
    assert r.end == 30
    
    # Valid slice
    s = r.slice(5, 10)
    assert s.offset == 15
    assert s.length == 10
    
    # Boundary: offset 0
    s = r.slice(0, 5)
    assert s.offset == 10
    assert s.length == 5
    
    # Boundary: offset + size == length
    s = r.slice(15, 5)
    assert s.offset == 25
    assert s.length == 5
    
    # Boundary: offset == length, size 0
    s = r.slice(20, 0)
    assert s.offset == 30
    assert s.length == 0

    # Invalid: offset < 0
    with pytest.raises(AssertionError):
        r.slice(-1, 5)
        
    # Invalid: size < 0
    with pytest.raises(AssertionError):
        r.slice(5, -1)
        
    # Invalid: offset > length
    with pytest.raises(AssertionError):
        r.slice(21, 0)
        
    # Invalid: offset + size > length
    with pytest.raises(AssertionError):
        r.slice(15, 6)

def test_slice_contains_range():
    buf = b"A" * 100
    s = Slice(buf=buf, range=Range(offset=10, length=20))
    # s covers buf[10:30]
    
    # Valid sub-ranges (relative to slice start)
    assert s.contains_range(0, 20) is True
    assert s.contains_range(5, 10) is True
    assert s.contains_range(0, 0) is True
    assert s.contains_range(20, 0) is True  # Boundary at the very end
    
    # Invalid: offset < 0
    assert s.contains_range(-1, 5) is False
    
    # Invalid: offset > length
    assert s.contains_range(21, 0) is False
    
    # Invalid: size < 0
    assert s.contains_range(5, -1) is False
    
    # Invalid: offset + size > length
    assert s.contains_range(15, 6) is False
    assert s.contains_range(20, 1) is False
    
    # Edge case: offset == length, size == 0
    assert s.contains_range(20, 0) is True
    
    # Edge case: offset == length, size == -1 (handled by size < 0)
    assert s.contains_range(20, -1) is False

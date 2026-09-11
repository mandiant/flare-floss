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

"""
These tests document structural limitations involving static string extraction utilizing Python's FLOSS execution pipeline.
These binaries were natively hex-edited to isolate layout bounds and logic vulnerabilities 
which will be fully enforced as integration regressions against our new Rust port implementations.

Both of these tests currently XFAIL (expected to fail) on the Python implementation because:
1. `bug1_cross_section.exe`: Python slices the physical byte execution across layout boundary structures (e.g. `.text` vs `.rdata`). When strings span these cuts, they are violently split or dropped!
2. `bug2_rva_overflow.exe`: VirtualSize map overflows structurally overlap into `.rdata` on-disk mappings in `pefile`, inappropriately projecting wrong layout logic tags over purely static sections. 
"""

import pytest
from pathlib import Path
from floss.layout import compute_layout
from floss.ranges import Slice
from floss.tags import load_databases
from floss.layout.extract import collect_strings

@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures" / "test-fixtures"

@pytest.mark.xfail(reason="String fragmentation vulnerability on section bounds drops contiguous slicing.")
def test_cross_section_string_fragmentation(fixtures_dir: Path):
    """
    Assert that strings overlapping structural bounds natively retain monolithic extraction lengths.
    """
    binary = fixtures_dir / "bug1_cross_section.exe"
    buf = binary.read_bytes()
    file_slice = Slice.from_bytes(buf)
    parsed = compute_layout(file_slice)
    parsed.extract_strings(4)
    # taggers = load_databases()
    # parsed.tag_strings(taggers)
    
    strings = collect_strings(parsed)
    found = False
    for s in strings:
        if s.string.string == "FLOSS_CROSS_SECTION_BUG_1_STRING!":
            found = True
            
    assert found is True, "The fragmented contiguous string was dropped or severely severed across boundaries!"

@pytest.mark.xfail(reason="pefile structural overflow binds execution code tags identically across disjoint disk boundaries.")
def test_rva_overflow_mistagging(fixtures_dir: Path):
    """
    Assert that VirtualSize overrides correctly bound to SizeOfRawData natively without polluting layout mapping logic overlaps.
    """
    binary = fixtures_dir / "bug2_rva_overflow.exe"
    buf = binary.read_bytes()
    file_slice = Slice.from_bytes(buf)
    parsed = compute_layout(file_slice)
    parsed.extract_strings(4)
    
    strings = collect_strings(parsed)
    mistagged = False
    for s in strings:
        if "BUG2_FLOSS_MISTAGGED_CODE_NOW!" in s.string.string:
            if s.structure != ".rdata":
                mistagged = True # pefile inherently bound this to the wrong space (.text overlay logic)
                
    assert mistagged is False, "The RVA buffer overflow forced the extraction bounds algorithm to apply the layout tag incorrectly to an .rdata static string!"


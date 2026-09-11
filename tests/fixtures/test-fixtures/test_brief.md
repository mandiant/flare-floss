# Test Fixtures for FLOSS Layout Bugs

Generated regression test binaries for confirming fixes of the two structural layout bugs.

## Bug 1: Cross-Section String Fragmentation
- **Binary:** `bug1_cross_section.exe`
- **Mechanism:** The `.text` section ends exactly at file offset `0xae00`, and the `.rdata` section starts exactly at file offset `0xae00`. A continuous ASCII string `FLOSS_CROSS_SECTION_BUG_1_STRING!` is placed at offset `0xadf0` (16 bytes inside `.text` and 17 bytes flowing into `.rdata`). 
- **Testing:** 
  - Using Python FLOSS, slice-based string scanning iterates structurally by `pefile` mapped chunk, causing the string to be incorrectly severed at the threshold `0xae00` (emitting `FLOSS_CROSS_SECT` and `ION_BUG_1_STRING!`).
  - Rust FLOSS correctly treats the physical buffer boundary smoothly, preserving the full contiguous string `FLOSS_CROSS_SECTION_BUG_1_STRING!`.

## Bug 2: RVA Overflow Mistagged `#code`
- **Binary:** `bug2_rva_overflow.exe`
- **Mechanism:** The `.text` executable section's `VirtualSize` has been artificially set to `0xc000`, which is significantly larger than its physical `SizeOfRawData` (`0xaa00`), creating an overlap with `.rdata`'s RVA range (`0xc000`). An ASCII test string `BUG2_FLOSS_MISTAGGED_CODE_NOW!` exists securely in the physical space of `.rdata` at offset `0xaf00`.
- **Testing:** 
  - Under Python FLOSS and old Lancelot layouts, any basic blocks bleeding or jumping inside this extended `.text` virtual space overlaps the string. RVAs map incorrectly due to the inflated virtual memory boundary via `get_offset_from_rva`, resolving the `0xaf00` offset to the overlapping executable umbrella, thus mistagging it as `#code`. 
  - Rust FLOSS correctly bounds virtual mappings to their physical section extents on disk prior to string attribution, keeping `.rdata` strings structurally isolated as `#data`/clean tags.

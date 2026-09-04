

## 2026-08 String Rendering Profiling & JSON mode equivalence
Batch output limits for standard IO streaming during `Verbosity.DEFAULT` render cycles were observed as a massive Python standard pipe execution constraint. We deployed dynamic sizing bounds checking `isatty()` utilizing block batch sizes up to 10000 chunked layouts, bypassing sequential IO halting entirely. This natively only affects real terminal rendering. Because `--json` or `-j` structurally queues and serializes the document context natively over memory pools within `msgspec`/`json` internal loops directly into large IO writes, runtime parity between optimized visual terminal iterations and json serializations are equivalent.

## 2026-09 Static Code Tagging & RVA Mapping Parity
During the Rust FLOSS migration, discrepancies of ~100 missing `#code` tags were observed in certain packed binaries. Investigation revealed that the discrepancy is not due to CFG engine differences (both implementations use Lancelot underlying the extraction logic for static code), but rather PE header parsing and RVA-to-offset projection.

In Python FLOSS, `pefile.PE.get_offset_from_rva()` generously maps RVAs onto disk offsets irrespective of the section's `SizeOfRawData` bounding so long as it is within `VirtualSize`. For example, RVAs belonging to unmapped BSS memory in a `.text` section (where `VirtualSize` exceeds `SizeOfRawData`) are inadvertently projected down into the physical disk offsets of the adjacent `.rdata` section. This resulted in Python FLOSS mistakenly tagging physical `.rdata` strings as `#code`.

Rust FLOSS relies on `goblin::pe::utils::find_offset()`, which correctly enforces the section's `size_of_raw_data` physical bounds. RVAs that map to uninitialized memory natively fall out-of-bounds rather than projecting onto adjacent disk sections. We have decided that this behavior is architecturally correct and superior. No changes are required in `floss-rust/src/layout.rs` to mimic the flawed RVA projection of `pefile`.

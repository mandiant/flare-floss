# Plan: Rust Implementation of Static Strings Extraction and Tagging

## Objective
Implement a high-performance Rust module to replace FLOSS's current Python-based static string extraction and tagging, serving as the foundational step for a full Rust rewrite.

## Scope
*   **Target:** Standalone CLI executable for easy benchmarking and diffing.
*   **Encodings:** Strict Parity Mode (ASCII & UTF-16LE for classic extraction; language-specific UTF-8 blocs).
*   **Format Handling:** PE and ELF format understanding, including transparent XOR decoding for PE files.
*   **Tagging:** Layout-based and Database-driven.
*   **Excluding:** Deobfuscation (Emulation/Stackstrings/Tightstrings).

## Proposed Tech Stack
*   **Binary Parsing:** `goblin` (robust against malware).
*   **Code Discovery:** `lancelot` (Rust crate) directly for PE code bounds.
*   **Data Serialization:** `serde` & `serde_json`.
*   **Compression:** `flate2` (for reading `.jsonl.gz` databases).
*   **Concurrency:** `rayon` (for parallelizing extraction/tagging if needed).

---

## Detailed Implementation Steps

### Step 1: Basic Static String Extraction
1.  Implement a fast scanner over raw byte buffers for printable ASCII strings (>= 4 chars by default).
    *   Port existing heuristics (e.g., skipping blocks filled with a single character).
2.  Implement a scanner for simple UTF-16LE strings (Parity Mode).
3.  Optimize for zero-copy or minimal allocations to maximize performance.

### Step 2: Layout-Aware Parsing & Obfuscation Handling
1.  Implement transparent XOR detection (checking for XORed `MZ` headers) matching `floss.layout.compute_layout`.
2.  Integrate `goblin` to parse PE and ELF files.
3.  Identify key sections (e.g., `.text`, `.rdata`, `.data`).
4.  Identify relocation entries and import/export tables.
5.  Use `lancelot` crate primitives to identify precise code ranges (basic blocks) in PE files.
6.  Track byte ranges (address intervals) for:
    *   Code segments.
    *   Data segments.
    *   Relocation blocks.
    *   Structured headers.

### Step 3: Database Loading
1.  Implement loaders for the existing FLOSS tag databases (located in `floss/tags/data/`).
    *   **Direct Load:** Handle streaming decompression of `.gz` files and raw `.bin` hash files.
    *   Parse `.jsonl` format into Rust structs using `serde`.
2.  Load the following databases efficiently into in-memory `HashSet` or `HashMap` instances:
    *   Global Prevalence (`#common`).
    *   Expert Strings (`#expert`).
    *   Open Source Libraries (`#openssl`, `#zlib`, etc.).
    *   Windows API names (`#winapi`).

### Step 4: Tagging Logic
1.  **Layout-Derived Tags:**
    *   Tag strings falling within code ranges as `#code`.
    *   Tag strings overlapping with relocation data as `#reloc`.
2.  **Database-Derived Tags:**
    *   Look up extracted strings in the loaded database maps (case-sensitive or insensitive as required by specific tags/DLLs).
    *   Apply relevant tags (e.g., `#common`, `#winapi`).

### Step 5: Output Integration
1.  Define serializable Rust structs to represent the full `ResultDocument`, including `ResultLayout`, `Strings`, and `Metadata`.
2.  Build the full layout tree (`ResultLayout`) with extracted and tagged strings.
3.  Ensure output format compatibility (**Exact Schema Match**) with FLOSS's current JSON schema (`ResultDocument`) for easy diffing.

---

## Verification & Benchmarking
*   **Functional Parity:** Compare output against current FLOSS running with `--no-decoded-strings --no-stack-strings --no-tight-strings`.
*   **Coverage:** Verify counts of extracted strings and applied tags match closely.
*   **Performance:** Profile against Python implementation to measure speedup.

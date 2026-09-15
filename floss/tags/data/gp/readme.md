# Globally Prevalent Strings

This directory contains databases of strings that are globally prevalent.
In other words, they are seen widely, and may be difficult to attribute to a specific library.

There are two types of databases here:
  - jsonl.gz files that contain strings and metadata
  - hash databases that contain hashes of strings

## JSONL files

These databases are gzip-compressed JSONL files (one JSON document per line).
The first line contains metadata about the database, such as:

```json
{
    "type":"metadata",
    "version":"1.0",
    "timestamp":"2023-05-11T12:49:35.328896",
    "note":null
}
```

The subsequent lines look like:

```json
{
    "string":"!This program cannot be run in DOS mode.",
    "encoding":"ascii",
    "global_count":424466,
    "location":null
}
```

JSONL databases:

  - gp.jsonl.gz: a proof-of-concept GP database derived from an internal string database. All strings were seen at least 100,000 times across millions of files. This database doesn't provide much value.
  - cwindb-dotnet.jsonl.gz: strings seen in .NET modules found on a Windows 10 system during May 2023.
  - cwindb-native.jsonl.gz: strings seen in native PE files found on a Windows 10 system during May 2023.
  - junk-code.jsonl.gz: junk strings from .text section of native PE files found on a Windows 10 system during May 2023. These strings are likely instruction sequences and we use them to supplement our code analysis recovery solution.


## Hash databases

When collecting strings from a large number of files, we encounter a huge number of strings. For example, 100,000 files results in more than 3 million strings seen more than 100 times (and almost 600 million distinct strings).

The hash database format is a sorted list of eight byte truncated MD5 hashes of strings found in a large corpus like this. FLOSS can quickly check if a string is in the database by computing the hash of the string and performing a binary search in the database; however, it can't recover any additional metadata about the string.

Hash databases:

  - xaa-hashes.bin: strings seen more than 100 times in 100,000 files uploaded to VirusTotal on May 1, 2023. There's probably a substantial bias in this collection. See issue #722 for the history.
  - yaa-hashes.bin: strings seen more than 100 times in 100,000 files uploaded to VirusTotal between May 18 and 24, 2023. The samples are randomly selected from more than 3 million total candidates in this time range. There's probably less bias in this collection (I hope). Also see issue #722 for the history.
  - gp-2026-hashes.bin: Refined global prevalence database (82,269 hashes). Compiled from a 153k sample corpus (Sep 2023 - Jun 2026) to filter out common string noise.
  - gp-go-specific.bin: Go-specific runtime noise (41,585 hashes). Contains Go-specific runtime and type descriptor strings.
  - gp-rust-specific.bin: Rust-specific runtime noise (3,953 hashes). Contains Rust panic-handling and standard library strings.
  - gp-pyinstaller-specific.bin: PyInstaller-specific noise (13,702 hashes). Contains PyInstaller bootloader and standard library Python bytecode strings.

## Source Data (CSVs)

For transparency and future reference, the raw string lists (with counts and locations) used to generate the 2026 databases are included as compressed CSV files in the `raw/` directory:

  - raw/gp-2026-hashes.csv.gz: Raw strings and metadata for `gp-2026-hashes.bin`.
  - raw/gp-go-specific.csv.gz: Raw strings and metadata for `gp-go-specific.bin`.
  - raw/gp-rust-specific.csv.gz: Raw strings and metadata for `gp-rust-specific.bin`.
  - raw/gp-pyinstaller-specific.csv.gz: Raw strings and metadata for `gp-pyinstaller-specific.bin`.

## 2026 Database Generation

The 2026 prevalence databases were generated from a temporally balanced corpus to represent the modern threat landscape while filtering out campaign-specific noise.

### 1. Corpus Selection & Extraction
*   **Source**: 247,485 unique PE binaries collected from VirusTotal (balanced at ~250/day over 1,000 days from Sep 2023 to Jun 2026).
*   **Clustering**: Clustered by Vhash and TLSH to select at most 3 representatives per cluster, resulting in **153,913 representative samples** used for string extraction.

### 2. Global Database (`gp-2026-hashes.bin`)
To filter out general PE noise while avoiding malware campaign flooding:
*   **Imphash Grouping**: Grouped the 153k files into **54,996 unique imphash groups** (counting only 1 file per group) to normalize the weight of malware families.
*   **Section Filtering**: Restricted the database to strings from **14 standard PE sections** (e.g., `.text`, `.rdata`), removing packer and overlay noise.
*   **Campaign Pruning**: Removed low-frequency campaign noise by requiring strings to appear in >= 11 groups (or >= 1,000 raw samples).
*   *Result*: **82,269 unique hashes** (a clean, high-confidence global noise database).

### 3. Specialized Sub-Databases (Go, Rust, PyInstaller)
Statically linked runtimes share identical IATs and collapse into single imphash groups, hiding their runtime strings. To capture this noise:
*   **Classification**: Identified Go (1,574 samples), Rust (1,038 samples), and PyInstaller (1,229 samples) subsets using metadata.
*   **Raw Samples Approach**: Compiled strings using raw sample counts (no grouping) at a 5% threshold (10% for PyInstaller) to capture the runtime.
*   **Global Subtraction**: Subtracted the Global DB from each subset to remove redundant common APIs and keep the sub-databases lightweight.
*   *Results*:
    *   **`gp-go-specific.bin`** (41,585 hashes)
    *   **`gp-rust-specific.bin`** (3,953 hashes)
    *   **`gp-pyinstaller-specific.bin`** (13,702 hashes)



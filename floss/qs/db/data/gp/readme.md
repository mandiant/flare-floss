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

When collecting strings from a large number of files, we encounter a huge number of strings.
For example, 100,000 files results in more than 3 million strings seen more than 100 times
(and almost 600 million distinct strings).

The hash database format is a sorted list of eight byte truncated MD5 hashes of strings found
in a large corpus. FLOSS checks if a string is in the database by computing the hash of the
string and performing a binary search in the database. No metadata (count, location) is stored,
but the format is significantly more compact and faster to load than JSONL.

Hash databases:

  - xaa-hashes.bin: strings seen more than 100 times in 100,000 files uploaded to VirusTotal on May 1, 2023. There's probably a substantial bias in this collection. See issue #722 for the history.
  - yaa-hashes.bin: strings seen more than 100 times in 100,000 files uploaded to VirusTotal between May 18 and 24, 2023. The samples are randomly selected from more than 3 million total candidates in this time range. There's probably less bias in this collection (I hope). Also see issue #722 for the history.

## Building new databases

Use the pipeline scripts in `floss/qs/scripts/` to build new databases from a VT corpus.
See `floss/qs/scripts/README.md` for the full pipeline walkthrough.

The short version for a hash database:

```sh
# 1. collect hashes (VT feed or Intelligence export)
VT_API_KEY=... python fetch_vt_hashes.py 202501010000 202501080000 > hashes.txt

# 2. fetch metadata to enable cluster-aware download (no binary transfer)
VT_API_KEY=... python fetch_vt_metadata.py hashes.txt ./metadata/

# 3. group by Vhash, select representatives
python select_representatives.py ./metadata/ ./

# 4. download only the representatives
VT_API_KEY=... python download_vt_samples.py representatives.txt ./samples/

# 5. extract strings
python extract_strings.py ./samples/ ./extracted/ --pes

# 6. generate the database
python generate_gp_db.py ./extracted/ zaa-hashes.bin --output-format hash --min-count 100
```

Then copy the resulting `.bin` file here and add its path to `DEFAULT_PATHS` in `floss/qs/db/gp.py`.

### Near-duplicate mitigation

`generate_gp_db.py` counts strings by distinct **imphash group**, not by number of files.
This prevents large malware families from inflating counts: a family with thousands of variants
sharing one import profile contributes exactly 1 to every string's count.
`select_representatives.py` applies a coarser filter even earlier using VT's Vhash,
reducing the number of binaries that need to be downloaded and processed.

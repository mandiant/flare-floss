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


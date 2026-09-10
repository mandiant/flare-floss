# Expert String Database

This directory contains databases of strings manually curated by experts.

The format of the database is a gzip-compressed JSONL file (one JSON document per line).
Each document looks like:

```json
{
    "type":"string",
    "value":"This program cannot be run in DOS mode.",
    "tag":"#capa",
    "action":"highlight",
    "note":"contain an embedded PE file",
    "description":"",
    "authors":["moritz.raabe@mandiant.com"],
    "references":[]
}
```

The expert databases are:

  - `capa.jsonl`: strings extracted from [capa](https://github.com/mandiant/capa) rules using the `import_from_capa.py` script.
  - `capa_blocklist.json`: a list of noisy strings that are removed from the capa expert database to prevent false positives.
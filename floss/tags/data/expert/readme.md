# Expert String Database

This directory contains databases of strings manually curated by experts.

The format of the database is a JSONL file (one JSON document per line).
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

Regex rules store the bare pattern in `value`. Flags go into the optional `modifiers`
field (default `""`); currently only `i` (case-insensitive) is used.

The expert databases are:

  - `capa.jsonl`: strings extracted from [capa](https://github.com/mandiant/capa) rules.
    Regenerate it from a checkout of the capa rules repository with
    `python import_from_capa.py ~/code/capa/rules/ > capa.jsonl`.
  - `capa_blocklist.json`: a list of noisy capa strings that the importer leaves out of
    `capa.jsonl` to prevent false positives. Each entry has `type`, `value` and an
    optional `modifiers` key (missing means `""`). A rule is skipped only if its
    `type`, `value` and `modifiers` are all equal to an entry; an entry without
    `modifiers` therefore does not match a rule with `modifiers: "i"`.
    The importer resolves the blocklist relative to its own location, not the current
    working directory.
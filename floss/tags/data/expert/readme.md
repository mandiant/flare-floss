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
    Do not edit it by hand; regenerate it with the importer from a checkout of the capa
    rules repository:

    ```
    python floss/tags/data/expert/import_from_capa.py ~/code/capa/rules/ > floss/tags/data/expert/capa.jsonl
    ```

    The importer needs Python 3.10+ with capa 7 or newer, msgspec and FLOSS importable
    (for example `PYTHONPATH=.` from the repository root). Rules are visited sorted by
    rule name; a string that occurs in several rules is emitted once, attributed to the
    first rule. The output depends only on the rules checkout, not on the capa version.

    The committed file was generated from
    [capa-rules master at 805f9eac](https://github.com/mandiant/capa-rules/tree/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5)
    (2026-09-08, "rule: graduate .NET time delay rule (#1196)") using capa 9.4.0.
    When regenerating, update this paragraph and put the same link in the commit message
    so the database can be diffed against the rules it came from:
    `https://github.com/mandiant/capa-rules/compare/<old>...<new>`.
  - `capa_blocklist.json`: a list of noisy capa strings that the importer leaves out of
    `capa.jsonl` to prevent false positives. Each entry has `type`, `value` and an
    optional `modifiers` key (missing means `""`). A rule is skipped only if its
    `type`, `value` and `modifiers` are all equal to an entry; an entry without
    `modifiers` therefore does not match a rule with `modifiers: "i"`.
    The importer resolves the blocklist relative to its own location, not the current
    working directory.
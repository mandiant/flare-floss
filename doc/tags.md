# FLOSS tags

When layout-aware static string extraction is enabled, FLOSS annotates strings
with **tags**. Tags come from embedded databases and expert rules, and let you
filter the listing down to the strings that matter using `--tag`, `--no-tag`, and
`--interesting` (see [usage.md](usage.md#filtering-arguments)).

This document covers tag consumption: which tags exist and how to filter with
them. Rebuilding and installing the databases is maintenance, documented in
[scripts/tags/README.md](../scripts/tags/README.md). Per-database notes sit next
to the data under [floss/tags/data/](../floss/tags/data/).

## Tag families

A family name matches any tag in that family, so `--tag oss` matches every
open-source library tag, and `--no-tag oss` drops all of them at once.

The multi-tag families are:

| Family | Tags |
|---|---|
| `gp` | `#common`, `#code-junk` |
| `oss` | one tag per library, e.g. `#openssl`, `#zlib`, `#curl` |

The `oss` family derives each library tag from the file name in
`floss/tags/data/oss/` (for example `openssl.jsonl.gz` → `#openssl`).

The remaining tags are single tags, not families, and can be filtered directly:

| Tag | Source |
|---|---|
| `#winapi` | Windows API usage database (`floss/tags/data/winapi/`) |
| `#msvc` | Microsoft C runtime library (`floss/tags/data/crt/`) |
| `#capa` | Expert / capa rules (`floss/tags/data/expert/`) |

## Match behavior

Tag matching is normalized: a leading `#` is stripped and the tag is lowercased,
so `winapi`, `#WinAPI`, and `#winapi` all match the stored tag `#winapi`. Values
that do not name a family are compared directly. A string matches a `--tag` filter
if any of its tags matches any of the requested tags/families.

## Noisy tags and `--interesting`

Some tags mark strings that are rarely interesting during analysis — prevalent
strings, duplicates, or strings that overlap code or relocations:

```
#common  #duplicate  #code  #reloc  #code-junk
```

`--interesting` drops any string carrying a noisy tag, *unless* the string also
carries a highlight tag (such as `#capa` from the expert rules), which is
preserved. This is a fast way to hide boilerplate and focus on distinctive
strings.

## Where tags come from

Tagging is implemented in [`floss/tags/`](../floss/tags/):

- `gp.py` — global-prevalence (`#common`, `#code-junk`) and hashes
- `oss.py` — open-source library membership
- `winapi.py` — Windows API usage
- `expert.py` — expert/capa rules (`#capa`), plus an optional `#decoded` marker

The databases are tracked with Git LFS and loaded from `floss/tags/data/`. If they
are missing (for example, after a plain clone without Git LFS), tag extraction is
skipped; see [installation.md](installation.md#step-1-check-out-source-code).

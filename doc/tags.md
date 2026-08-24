# FLOSS tags

When layout-aware static string extraction is enabled, FLOSS annotates strings
with **tags**. Tags come from embedded databases and expert rules, and let you
filter the listing down to the strings that matter using `--tag`, `--no-tag`, and
`--interesting` (see [usage.md](usage.md#filtering-arguments)).

This document describes tag *consumption*. For *maintenance* of the databases,
see [scripts/tags/README.md](../scripts/tags/README.md).

## Tag families

Tags are grouped into families, one per tag-source directory under
[`floss/tags/data/`](../floss/tags/data/). A family name matches any tag in that
family, so `--tag winapi` matches every Windows API tag. The families are defined
in [`floss/render/filter.py`](../floss/render/filter.py).

| Family | Example tags | Source |
|---|---|---|
| `winapi` | `#winapi` | Windows API usage database (`floss/tags/data/winapi/`) |
| `crt` | `#msvc` | Microsoft C runtime library (`floss/tags/data/crt/`) |
| `expert` | `#capa` | Expert / capa rules (`floss/tags/data/expert/`) |
| `gp` | `#common`, `#code-junk` | Global-prevalence database (`floss/tags/data/gp/`) |
| `oss` | `#openssl`, `#zlib`, `#curl`, … | Open-source library databases (`floss/tags/data/oss/`) |

The `oss` family has one tag per library, derived from the file name in
`floss/tags/data/oss/` (for example `openssl.jsonl.gz` → `#openssl`).

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

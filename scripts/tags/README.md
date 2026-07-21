# Tag database maintenance

Scripts for building and inspecting the QuantumStrand tag databases shipped under `floss/qs/db/data/`.

## Pipeline overview

```
extract_strings.py  →  generate_gp_db.py  →  gp.jsonl.gz
                              ↑
                    (raw PE string JSON)

build_oss_db.py  →  <library>.jsonl.gz   (OSS tag databases)

fetch_vt_hashes.py  →  hash list          (VT feed sampling)

query_string.py     →  lookup GP tags     (debug / inspection)
```

## Global prevalence (GP)

1. **Extract** raw strings from PEs or `.lib` archives:

   ```console
   $ python scripts/tags/extract_strings.py C:\Windows outdir --pes
   ```

2. **Generate** the global-prevalence database from extracted JSON:

   ```console
   $ python scripts/tags/generate_gp_db.py outdir gp.jsonl.gz --type native
   ```

3. Install the result at `floss/qs/db/data/gp/gp.jsonl.gz` (and related hash files).

4. **Query** a string against the installed database:

   ```console
   $ python scripts/tags/query_string.py "kernel32.dll"
   ```

## Open-source library (OSS) databases

`build_oss_db.py` automates the [vcpkg & jh technique](../../floss/qs/db/data/oss/readme.md): install static libraries, extract features with jh, emit gzip-compressed JSONL, and merge with any existing databases in the output directory.

```console
$ python scripts/tags/build_oss_db.py --libraries zlib curl --output-dir floss/qs/db/data/oss
```

## VirusTotal feed sampling

`fetch_vt_hashes.py` downloads hashes for relevant file types from the VT feed over a time range (requires `virustotal3` and API credentials).

```console
$ python scripts/tags/fetch_vt_hashes.py 202305010000 202305020000
```
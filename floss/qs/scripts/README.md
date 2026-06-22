# QS Database Pipeline Scripts

Scripts for building and querying QS string prevalence databases.
Run them from the repo root with the project virtual environment active.

## Pipeline overview

The GP (global prevalence) database pipeline has five sequential steps.
Each step writes its output to disk, so the pipeline is fully resumable —
interrupting and restarting any step picks up where it left off.

```
Step 1   fetch_vt_hashes.py      collect SHA256s from VT file feed
Step 1.5 fetch_vt_metadata.py    fetch vhash/imphash/tlsh per hash (no download)
Step 2a  select_representatives.py  cluster by Vhash, pick representatives
Step 2b  download_vt_samples.py  download binaries for representatives only
Step 3   extract_strings.py      extract strings from PE files
Step 4   generate_gp_db.py       count strings, emit .bin or .jsonl.gz database
```

All VT steps require a `VT_API_KEY` environment variable.
Binary download (Step 2b) requires a VT premium subscription.

---

## Scripts

### `fetch_vt_hashes.py` — collect SHA256s from VT file feed

Fetches hashes of PE/ELF/DOS files submitted to VT in a given time window.
Results are cached locally (per-minute, keyed on script hash) so re-running
the same range is free.

```sh
VT_API_KEY=... python fetch_vt_hashes.py 202501010000 202501080000 >> raw_hashes.txt
sort -u raw_hashes.txt > hashes.txt
```

Arguments:
- `start` / `end` — time range in `YYYYMMDDhhmm` format (UTC)

---

### `fetch_vt_metadata.py` — fetch file metadata (no binary download)

For each SHA256 in a hash list, fetches the VT file report and saves a small
JSON with the fields needed for cluster selection: `vhash`, `imphash`,
`rich_pe_header_hash`, `tlsh`, `ssdeep`, `magic`.

Already-fetched hashes are skipped. Failed hashes are written to
`{outdir}/failed.txt` for separate retry.

```sh
VT_API_KEY=... python fetch_vt_metadata.py hashes.txt ./metadata/ --rate-limit 4
```

Output layout: `metadata/{sha256[:2]}/{sha256}.json`

At 4 req/s, 500k hashes takes ~35 hours. Run as a background job.

---

### `select_representatives.py` — cluster and select download targets

Groups all cached metadata by Vhash (then imphash for files without Vhash,
then singletons). Selects at most `--max-per-cluster` SHA256s per group —
reducing a cluster of 10k malware variants to 3 downloads.

No network access required. Reads the `metadata/` directory and writes:
- `representatives.txt` — SHA256s to download, one per line
- `cluster_assignments.json` — full cluster map for analysis

```sh
python select_representatives.py ./metadata/ ./ --max-per-cluster 3
```

Review `cluster_assignments.json` before downloading. The largest clusters
are usually popular malware families and rarely need more than 1–3 samples.

---

### `download_vt_samples.py` — download binaries

Downloads the binary for each SHA256 in a file, verifies the SHA256 after
download, and skips already-downloaded files. Logs failures to
`{outdir}/failed_downloads.txt`.

Requires VT premium for binary download access.

```sh
VT_API_KEY=... python download_vt_samples.py representatives.txt ./samples/ --rate-limit 2
```

Output layout: `samples/{sha256[:2]}/{sha256}.bin`

---

### `extract_strings.py` — extract strings from PE files

Extracts ASCII and UTF-16LE strings from PE files, records their section
location, and stores one JSON per file. Skips already-processed files.
On restart, scans the output directory to rebuild the seen-SHA256 set, so
duplicate work is never done.

```sh
python extract_strings.py ./samples/ ./extracted/ --pes --min-len 6
```

Output layout: `extracted/{sha256[:2]}/{sha256}.json`

Each output JSON includes: `sha256`, `imphash` (computed by pefile),
`dotnet` flag, and a list of `{offset, string, encoding, location}` records.

---

### `generate_gp_db.py` — build the prevalence database

Reads all extraction JSONs, counts how many **distinct imphash groups**
contain each string (not how many individual files), and emits a database.

Counting by imphash group prevents large malware families from inflating
string counts: a family with 10k variants sharing one import profile
contributes exactly 1 to every string's count.

Checkpoints progress every 10,000 files to `{outfile}.ckpt.pkl`.
On restart the checkpoint is loaded automatically (`--no-resume` to discard it).

```sh
# Compact hash database (recommended for shipping):
python generate_gp_db.py ./extracted/ zaa-hashes.bin \
    --output-format hash --min-count 100 --type native

# JSONL database with counts and section metadata:
python generate_gp_db.py ./extracted/ gp-custom.jsonl.gz \
    --output-format jsonl --min-count 500 --type all
```

`--type` selects `native`, `dotnet`, or `all`.

Threshold guidance by corpus size (after cluster deduplication):

| Corpus size | `--min-count` |
|-------------|---------------|
| 100k files  | 100           |
| 500k files  | 500           |
| 1M files    | 1000          |

---

### `query_string.py` — look up a string in the GP database

Quick check whether a string is in the shipped GP database and what its
global prevalence metadata looks like.

```sh
python query_string.py "kernel32.dll"
```

---

## Near-duplicate problem

Without mitigation, a malware family with just 0.1% representation in a
500k-file corpus (500 files) can push its distinctive strings above the
default threshold — getting them tagged `#common` and silencing potential IOCs.

`generate_gp_db.py` addresses this by counting **distinct imphash groups**:

```
count(string) = |{ imphash(f) : string ∈ strings(f) }|
```

Each unique import profile acts as one vote. Files sharing an imphash are
treated as the same "source program", so a family with thousands of variants
but one shared import profile contributes a count of 1, not thousands.

The `select_representatives.py` / `download_vt_samples.py` pair applies a
coarser filter earlier in the pipeline using VT's Vhash, reducing download
volume before extraction even starts.

---

## After building a new database

1. Copy the `.bin` or `.jsonl.gz` file into `floss/qs/db/data/gp/`
2. Add its path to `DEFAULT_PATHS` in `floss/qs/db/gp.py`
3. Run `pytest tests/test_gp_db.py`
4. Update `floss/qs/db/data/gp/readme.md` with corpus description and date

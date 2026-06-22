# Global Prevalence Database Pipeline

Plan for building a new `gp` database from a large, well-sampled corpus of Windows PE binaries pulled from VirusTotal.

## Background

QS tags strings as `#common` when they appear in a global prevalence database. The current databases ship with the tool:

| File | Description | Vintage |
|------|-------------|---------|
| `gp.jsonl.gz` | Proof-of-concept, ~100k occurrence threshold, internal corpus | 2023 |
| `cwindb-native.jsonl.gz` | Native PE strings from a Windows 10 system | May 2023 |
| `cwindb-dotnet.jsonl.gz` | .NET PE strings from a Windows 10 system | May 2023 |
| `junk-code.jsonl.gz` | Code-section byte patterns that look like strings | May 2023 |
| `xaa-hashes.bin` | MD5-truncated hashes from 100k VT files, May 1 2023 | May 2023 |
| `yaa-hashes.bin` | MD5-truncated hashes from 100k VT files, May 18–24 2023 | May 2023 |

Problems with the current state:
- The VT-derived hash databases (xaa, yaa) are only 100k files each and have a malware-heavy bias.
- The cwindb files are from a single Windows 10 install from 2023.
- `StringHashDatabase` had no `to_file()` method — now fixed.

## Goals

1. Produce a new `zaa-hashes.bin` covering at least 500k unique Windows PE binaries.
2. Bias the corpus toward benign/legitimate files so that `#common` is meaningful (not polluted by malware-specific strings).
3. Prevent near-duplicate file families from inflating string counts (imphash-group counting).
4. Keep the pipeline fully resumable — no step needs to be repeated if interrupted.

## Database format: hash `.bin`

Both the JSONL and hash approaches produce identical tagger output — just `("#common",)` or nothing. The `global_count`, `location`, and `encoding` stored in JSONL files is loaded into memory but **never used** by any tagging logic (see `query_global_prevalence_database` in `main.py:796`).

The hash format wins on every practical dimension:

| | Hash `.bin` | JSONL `.gz` |
|---|---|---|
| Storage | **8 bytes/string** — 1M strings ≈ 8 MB | ~60–80 bytes/string — 1M strings ≈ 60–80 MB |
| Load time | Raw binary read into set | Decompress + JSON-parse every line |
| Threshold | Can use ≥100 (lower = better coverage) | Must use ≥500 to stay manageable |
| Output | `#common` | `#common` — identical |

## Near-duplicate problem and solution

The VT corpus is heavily family-biased. Without mitigation, a malware family with only 0.1% representation (500 files in a 500k corpus) can push its distinctive strings above the threshold and get them tagged `#common`. This mutes real IOCs.

**Solution: count by distinct imphash groups, not files.**

`count(string) = |{ imphash(f) : string ∈ strings(f) }|`

For each unique imphash value (= distinct import profile = proxy for distinct source program), only the first file seen is counted. Additional files with the same imphash are skipped. This means a family with 10k variants and a shared import profile contributes exactly 1 to every string's count, regardless of how many variants are in the corpus.

VT provides imphash and the coarser Vhash in its file metadata — fetched without downloading the binary — so both signals are available before the download step.

---

## Corpus strategy

### Track A — VT Intelligence clean sample (primary)

Query VT Intelligence for PE files with zero AV detections:

```
positives:0 (type:peexe OR type:pedll) size:10kb+
```

Target: **500k unique SHA256s**, spread across multiple weeks to avoid temporal bias.
Requires: VT Intelligence / premium API access.

### Track B — VT file feed random sample (breadth)

Use `fetch_vt_hashes.py` across several weeks. Target: 100k–200k additional files.

### Track C — Windows system files (refresh)

Re-run `extract_strings.py --pes` against Windows 11 23H2 and Windows Server 2022. This refreshes the cwindb files. (JSONL format is appropriate here since the corpus is small and manually curated.)

---

## Data persistence: what is stored where

Every intermediate artifact is written to disk so any step can be resumed without repeating earlier work.

```
hashes.txt                              # one sha256 per line (deduplicated); feed for Steps 1.5–2
metadata/{sha256[:2]}/{sha256}.json     # VT metadata per file (Step 1.5); no binary download
cluster_assignments.json                # vhash/imphash -> sha256 groups (Step 2a)
representatives.txt                     # selected sha256s to download (Step 2a output)
samples/{sha256[:2]}/{sha256}.bin       # raw binary downloads (Step 2b)
extracted/{sha256[:2]}/{sha256}.json    # per-file string extraction (Step 3)
{output}.bin / {output}.jsonl.gz        # final database (Step 4)
{output}.ckpt.pkl                       # rolling checkpoint during DB generation (auto-deleted on success)
```

Each step checks for existing output before doing work:
- **fetch_vt_metadata**: skip if `metadata/{sha256[:2]}/{sha256}.json` exists
- **select_representatives**: reads all metadata, regenerates deterministically
- **download_vt_samples**: skip if `samples/{sha256[:2]}/{sha256}.bin` exists
- **extract_strings**: skip if `extracted/{sha256[:2]}/{sha256}.json` exists (keyed on SHA256, not filename)
- **generate_gp_db**: resumes from `{outfile}.ckpt.pkl` if present; checkpoint written every 10k files

---

## Pipeline steps

### Step 1 — Hash collection

**Script:** `fetch_vt_hashes.py` (existing). Caches per-minute feed results in a local shelve.

```sh
python fetch_vt_hashes.py 202501010000 202501080000 >> raw_hashes.txt
python fetch_vt_hashes.py 202502010000 202502080000 >> raw_hashes.txt
python fetch_vt_hashes.py 202503010000 202503080000 >> raw_hashes.txt
sort -u raw_hashes.txt > hashes.txt
```

Track A: export from VT Intelligence, append to `hashes.txt`, re-deduplicate.

---

### Step 1.5 — VT metadata fetch (no binary download)

**Script:** `fetch_vt_metadata.py` (new)

Fetches vhash, imphash, rich PE header hash, TLSH, ssdeep, and magic for each SHA256 via the VT API. No binary is transferred. Fully resumable — skips already-fetched hashes.

```sh
VT_API_KEY=... python fetch_vt_metadata.py hashes.txt ./metadata/ --rate-limit 4
```

At 4 req/s, 500k hashes takes ~35 hours. Since this is I/O-bound and resumable, it can run as a background job.

Failed hashes (404, quota, etc.) are written to `metadata/failed.txt` for separate retry.

---

### Step 2a — Cluster selection (no network)

**Script:** `select_representatives.py` (new)

Groups all metadata by Vhash (then imphash for files without Vhash, then singletons). Selects at most `--max-per-cluster` representatives per group. Writes `representatives.txt` and `cluster_assignments.json`.

```sh
python select_representatives.py ./metadata/ ./ --max-per-cluster 3
```

Check `cluster_assignments.json` to see the largest clusters before downloading — large clusters are likely popular malware families and don't need many representatives.

---

### Step 2b — Sample download

**Script:** `download_vt_samples.py` (new)

Downloads binaries for each SHA256 in `representatives.txt`. Verifies SHA256 after download. Skips already-downloaded files. Requires VT premium for binary download.

```sh
VT_API_KEY=... python download_vt_samples.py representatives.txt ./samples/ --rate-limit 2
```

Failed downloads are logged to `samples/failed_downloads.txt`.

---

### Step 3 — String extraction

**Script:** `extract_strings.py --pes` (existing, fixed)

```sh
python extract_strings.py ./samples/ ./extracted/ --pes --min-len 6
```

Skip logic is now SHA256-based: output is `extracted/{sha256[:2]}/{sha256}.json`. An existing output file means that SHA256 was already processed — correct regardless of where the binary lives. `imphash` (computed by pefile) is stored in the output JSON.

---

### Step 4 — Database generation

**Script:** `generate_gp_db.py` (updated)

Counting uses distinct imphash groups, not total files. Checkpoints every 10k files to `{outfile}.ckpt.pkl`; resumes automatically on restart.

```sh
python generate_gp_db.py \
    ./extracted/ zaa-hashes.bin \
    --output-format hash \
    --min-count 100 \
    --type native
```

Threshold guidance by corpus size:

| Files (after cluster dedup) | min-count |
|-----------------------------|-----------|
| 100k                        | 100       |
| 500k                        | 500       |
| 1M                          | 1000      |

---

### Step 5 — Integration

1. Place `zaa-hashes.bin` in `floss/qs/db/data/gp/`.
2. Add to `DEFAULT_PATHS` in `gp.py`.
3. Run `pytest tests/test_gp_db.py`.
4. Update `floss/qs/db/data/gp/readme.md`.

---

## Bugs fixed

| File | Issue | Fix |
|------|-------|-----|
| `extract_strings.py` | `elif args.libs` → dead branch, max_len always wrong for PE mode | Fixed to `elif args.pes`, correct constant |
| `extract_strings.py` | Skip check compared file path strings instead of SHA256 | Now uses SHA256-keyed output files; skip-if-exists is correct |
| `extract_strings.py` | `seen_hashes` lost on restart → duplicates re-processed | Pre-populated from existing output JSONs on startup |
| `generate_gp_db.py` | Positional args in `StringGlobalPrevalence(...)` | Switched to kwargs |
| `generate_gp_db.py` | No near-duplicate mitigation — family variants inflate counts | Imphash-group counting: one representative per import profile |
| `generate_gp_db.py` | No checkpointing — crash at 490k/500k = full restart | Pickle checkpoint every 10k files, auto-resume |
| `gp.py` | `StringHashDatabase` had no `to_file()` — couldn't build new `.bin` DBs | Added |

## Code changes summary

| File | Status | Change |
|------|--------|--------|
| `floss/qs/db/gp.py` | Modified | Add `StringHashDatabase.to_file()` |
| `floss/qs/scripts/extract_strings.py` | Modified | SHA256-based output, imphash field, startup dedup scan, bug fixes |
| `floss/qs/scripts/generate_gp_db.py` | Modified | Imphash-group counting, `--output-format hash`, pickle checkpointing, kwargs |
| `floss/qs/scripts/fetch_vt_metadata.py` | **New** | Metadata-only VT fetch, per-SHA256 cache, resumable |
| `floss/qs/scripts/select_representatives.py` | **New** | Vhash/imphash clustering, representative selection |
| `floss/qs/scripts/download_vt_samples.py` | **New** | Binary download with SHA256 verification, resumable |
| `floss/qs/db/gp.py` | Pending | Add `zaa-hashes.bin` to `DEFAULT_PATHS` after DB is built |
| `floss/qs/db/data/gp/readme.md` | Pending | Document new database |

## Open questions

- **VT access tier:** VT Intelligence (needed for `positives:0` filtering and binary download) or file feed only?
- **Scale target:** 100k, 500k, or 1M files? Drives threshold and run time.
- **Native vs .NET split:** Single `zaa-hashes.bin` or separate `zaa-native-hashes.bin` + `zaa-dotnet-hashes.bin`?

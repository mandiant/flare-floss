# FLOSS Scripts

Auxiliary scripts live under `scripts/`, grouped by purpose:

| Directory | Purpose |
|-----------|---------|
| [`disassemblers/`](disassemblers/) | Convert classic FLOSS JSON output into import scripts for Binary Ninja, Ghidra, IDA Pro, Radare2, and x64dbg; includes the IDA plugin |
| [`tags/`](tags/) | Build and maintain QuantumStrand tag databases (global prevalence, OSS libraries, VT feeds) |
| [`analysis/`](analysis/) | Batch analysis helpers |

## disassemblers/

Turn FLOSS JSON (`floss -j sample.exe > results.json`) into tool-specific artifacts.

1. Run a render script, redirecting stdout to a file.
2. Import or run the generated artifact in the target tool.

Example (Ghidra):

```console
$ python scripts/disassemblers/render-ghidra-import-script.py results.json > apply_floss.py
```

See [`disassemblers/`](disassemblers/) for per-tool scripts and the [IDA plugin](disassemblers/idaplugin.py) (`File → Script file…` in IDA Pro).

Install FLOSS from source first; see [installation](../doc/installation.md).

## tags/

Scripts that extract strings, build tag databases, and query them. See [`tags/README.md`](tags/README.md) for the full pipeline.

## analysis/

- [`bulk_analyze.py`](analysis/bulk_analyze.py) — run `floss` or `floss quantum` over every binary in a directory and write JSON results.

Language-specific data maintenance (for example regenerating the Rust version hash database) lives alongside the implementation under `floss/language/`.
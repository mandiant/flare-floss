# FLOSS Scripts

Auxiliary scripts live under `scripts/`, grouped by purpose:

| Directory | Purpose |
|-----------|---------|
| [`disassemblers/`](disassemblers/) | Convert classic FLOSS JSON output into import scripts for Binary Ninja, Ghidra, IDA Pro, Radare2, and x64dbg; includes the IDA plugin |
| [`tags/`](tags/) | Build and maintain FLOSS tag databases (global prevalence, OSS libraries, VT feeds) |
| [`analysis/`](analysis/) | Batch analysis helpers |

## disassemblers/

Turn FLOSS JSON (`floss -j sample.exe > results.json`) into tool-specific artifacts.

1. Run a render script, redirecting stdout to a file.
2. Import or run the generated artifact in the target tool.

Example (Ghidra):

```console
$ python render-ghidra-import-script.py results.json > apply_floss.py
```

See [`disassemblers/`](disassemblers/) for per-tool scripts and the [IDA plugin](disassemblers/idaplugin.py) (`File → Script file…` in IDA Pro).

Install FLOSS from source first; see [installation](../doc/installation.md).

> **Note**: Static and language-specific strings store file offsets in the JSON.
> The render scripts translate those offsets to virtual addresses using the PE
> section table, which requires the original sample to still exist at the path
> recorded in the JSON (or pass `--sample PATH` to the render script). Relative
> `file_path` values resolve against the render command's current working
> directory. VAs assume the sample is loaded at its preferred base; if your
> database is rebased, annotations must be subtracted/adjusted by the rebase
> delta. Strings that cannot be mapped (for example overlay data, or
> samples that are not PE files such as shellcode, ELF, or Mach-O) are skipped
> with a warning.

## tags/

Scripts that extract strings, build tag databases, and query them. See [`tags/README.md`](tags/README.md) for the full pipeline.

## analysis/

- [`bulk_analyze.py`](analysis/bulk_analyze.py) — run `floss` over every binary in a directory and write JSON results.

Language-specific data maintenance (for example regenerating the Rust version hash database) lives alongside the implementation under `floss/language/`.
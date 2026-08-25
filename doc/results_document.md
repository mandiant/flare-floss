# FLOSS results document

`floss -j sample.exe` emits the full analysis result as a single, versioned JSON
object. This is the interchange format for all of the tools under
[`scripts/`](../scripts/README.md) and the [web viewer](../viewer/README.md). The
model is defined in [`floss/results.py`](../floss/results.py).

## Loading

The format is self-describing: run

```
floss sample.exe -j > sample.json
```

and pass it back to FLOSS to re-render it (as text, summary, or JSON) without
re-running the analysis:

```
floss sample.json
floss sample.json --summary
```

Scripts can load and validate a document programmatically:

```python
from floss.results import ResultDocument
doc = ResultDocument.parse_file(path)
```

`layout`, `analysis`, and `strings` are always present (possibly empty); the
`metadata` block is always first so a document is recognizable from its leading
bytes. Loading via the CLI mutates a copy of the document: `--analyze-functions`
and `-n/--minimum-length` are re-applied on load, and a `-n` looser than the one
used to build the document is an error, because those shorter strings were
already dropped at extraction time.

## Top-level structure

```jsonc
{
  "metadata": { "...": "..." },
  "analysis": { "...": "..." },
  "strings": { "...": "..." },
  "layout":  { "...": "..." }
}
```

| Key | Type | Description |
|---|---|---|
| `metadata` | object | Sample metadata: file path, hashes, tool version, runtime, thresholds |
| `analysis` | object | Which string types were enabled and function analysis counts |
| `strings` | object | The recovered strings, grouped by type |
| `layout` | object \| null | Layout-aware static string context tree |

`metadata` carry the sample identity and the settings used for extraction:

- `file_path`, `md5`, `sha1`, `sha256`
- `version` — the FLOSS version that produced the document (cached documents are
  keyed on this)
- `imagebase` — the base address (0 for non-PE/ELF inputs such as shellcode)
- `min_length` — the extraction minimum string length
- `language`, `language_version`, `language_selected` — Go/Rust identification
- `runtime` — per-stage elapsed time, e.g. `static_strings`, `layout`, `tags`

`analysis` records the extraction configuration and supporting counts:

- `enable_static_strings`, `enable_stack_strings`, `enable_tight_strings`,
  `enable_decoded_strings`, `enable_language_strings`, `enable_layout`,
  `enable_tags`
- `functions` — `discovered`, `library`, and per-stage counts such as
  `analyzed_decoded_strings` and `decoding_function_scores`

`strings` groups the results by extraction technique:

- `static_strings` — plain ASCII/UTF-16LE strings
- `stack_strings` — strings constructed on the stack at run time
- `tight_strings` — a special form of stack strings decoded in a tight loop
- `decoded_strings` — strings decoded in a function
- `language_strings` / `language_strings_missed` — language-specific strings
  (Go/Rust) and candidates that were not recovered

Each element carries the string value, its address/offset, and its encoding
(`ASCII`, `UTF-16LE`, `UTF-8`). Decoded/stack strings additionally record the
decoding function (`decoding_routine`, `decoded_at`) or stack frame details.

### Layout

When layout and static string extraction are enabled, `layout` is a tree whose
nodes describe the binary structure. A node is:

```jsonc
{
  "name": ".rdata",
  "offset": 1890752,
  "length": 1476336,
  "strings": [
    {
      "string": "open",
      "offset": 1906840,
      "size": 4,
      "encoding": "ASCII",
      "tags": ["#winapi"],
      "structure": "import-table"
    }
  ],
  "children": [ { "...": "..." } ]
}
```

- `name` is the section or structure name (e.g. `.text`, `.rdata`, or a
  structure like `import-table`).
- `offset`/`length` give the node's byte range; each string records its `offset`,
  `size`, `encoding`, `tag` list, and the `structure` it lives in.

## Stability

The document carries `metadata.version`. While FLOSS is under active
development, the schema is allowed to change between releases: the top-level
keys and their meaning are intended to be stable, but new fields may be added and
the presence of a field is not a guarantee between minor versions. Tools that
consume the document should treat unknown keys as ignorable and should pin the
`flare-floss` version that produced it. The [`scripts/`](../scripts) import tools
and the viewer are kept in sync with the current schema.

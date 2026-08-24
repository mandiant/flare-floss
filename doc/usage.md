# FLARE Obfuscated String Solver

## Usage

You can use FLOSS just like you'd use `strings.exe`
 to extract human-readable strings from binary data.
The enhancement that FLOSS provides is that it statically
 analyzes executable files and decodes obfuscated strings.
These include:
* strings encrypted in global memory or deobfuscated onto the heap
* strings manually created on the stack (stackstrings)
* strings created on the stack and then further modified (tight strings)

Since FLOSS also extracts static strings (like `strings.exe`),
 you should consider replacing `strings.exe` with FLOSS
 within your analysis workflow.

Here's a summary of the command line flags and options you
 can provide to FLOSS to modify its behavior.

See `floss -h` for all supported arguments and usage examples.

### Extract static, obfuscated, and stack strings (default mode)

    floss.exe malware.exe

The default mode for FLOSS is to extract the following string types from an executable file:
- static ASCII and UTF-16LE strings
- stack strings
- tight strings
- obfuscated strings

See the section on [Shellcode analysis](#shellcode) below on how to analyze raw binary files
containing shellcode.

By default, FLOSS uses a minimum string length of four (4).

### Language-specific strings
FLOSS can identify programs compiled from selected programming languages and extract strings that are easier to inspect by humans.

By default, this process is automatic. However, you can use the `--language` argument to manually select or disable this feature.

### Disable string type extraction (`--no-string-type {static,stack,tight,decoded,language,all}`)

When FLOSS searches for static strings, it looks for
 human-readable ASCII and UTF-16 strings across the
 entire binary contents of the file.
This means you may be able to replace `strings.exe` with
 FLOSS in your analysis workflow. However, you may disable
 the extraction of static strings via the `--no-string-type static` switch.

    floss.exe --no-string-type static -- malware.exe

Since `--no-string-type` supports multiple arguments, end the command options with a double dash `--`.

Analogous, you can disable the extraction of obfuscated strings, stackstrings or any combination.

    floss.exe --no-string-type decoded -- malware.exe
    floss.exe --no-string-type stack tight -- malware.exe


### Enable string type extraction (`--string-type {static,stack,tight,decoded,language,all}`)

Sometimes it's easier to specify only the string type(s) you want to extract.
Use the `--string-type` option for that.

    floss.exe --string-type decoded -- malware.exe

Please note that `--string-type` and `--no-string-type` cannot be used at the same time.

### Filtering arguments

These options let you drill into the layout-aware static string listing by
binary section, structure, semantic tag, or content. They are the primary
controls for the layout-aware output that FLOSS enables by default (see the
[Tags](#tags) section and [layout-aware static strings](../README.md#layout-aware-static-strings)
in the README).

Filtering by binary section:

    floss.exe --section .rdata -- malware.exe
    floss.exe --no-section .text -- malware.exe

`--section` keeps only static strings whose containing section is in the given
list; `--no-section` drops them. Both accept multiple names and repeat.

Filtering by binary structure (PE/ELF/Mach-O structures such as the import
table, section headers, etc.):

    floss.exe --structure import-table -- malware.exe
    floss.exe --no-structure symbol-table -- malware.exe

Structure names are slugs and match regardless of separators, so `import-table`,
`import_table`, and `import table` are equivalent. Run `--summary` to see the
structures present in a specific sample.

Filtering by semantic tag:

    floss.exe --tag winapi openssl -- malware.exe
    floss.exe --no-tag crt -- malware.exe

`--tag` keeps strings that carry any of the given tags (or tag families, see the
[Tags](#tags) section); `--no-tag` drops them. Run `--summary` to see the tags
present in a specific sample.

Convenience shortcuts:

    floss.exe --interesting -- malware.exe
    floss.exe --query "http://" -- malware.exe
    floss.exe --max-strings 50 -- malware.exe

- `--interesting` drops strings that carry a "noisy" tag (prevalent, duplicated,
  code, or relocation-related strings, e.g. `#common`, `#duplicate`, `#code`),
  unless they also carry a highlight tag (such as `#capa`).
- `--query REGEX` keeps only strings matching the given regular expression(s).
  Repeatable; patterns are ORed.
- `--max-strings N` caps the emitted strings per section to the top `N` by
  relevance (highlighted first, then untagged, then tagged, ascending by offset).

`--interesting` is a shorthand for the noisy-tag exclusion; the section,
structure, and tag filters can all be combined with each other and with
`--query`.

### Output options

Not all renderers produce the full layout-aware listing. These options select
alternative views:

    floss.exe --plain malware.exe
    floss.exe --summary malware.exe
    floss.exe --columns tags offset structure -- malware.exe

- `--plain` renders the classic flat list of strings without layout context or
  tags, matching FLOSS v1-style output. Useful for feeding the output into
  `strings.exe`-style tooling.
- `--summary` emits a concise summary (sample metadata, per-type string counts,
  section counts, a tag histogram, and high-value strings). It is static-only by
  default unless string types are explicitly selected. This is the quickest way
  to see which sections, structures, and tags a sample contains.
- `--columns {tags,offset,structure,encoding}` selects which columns appear in
  the layout view. Valid values are `tags`, `offset`, `structure`, `encoding`;
  the default is `tags` and `offset`.

### Advanced options

    floss.exe -L malware.exe
    floss.exe --signatures /path/to/lib.sig malware.exe
    floss.exe -dd malware.exe
    floss.exe --color never malware.exe

- `-L`/`--large-file` allows processing files larger than the default 16 MB
  limit. Files above this limit abort deobfuscation with an error unless this
  flag is set, because stack/tight/decoded string extraction is expensive.
- `--signatures PATH` specifies a `.sig`/`.pat` file (or directory) used to
  identify library functions for deobfuscation. FLOSS uses its embedded FLIRT
  signatures by default. Signature databases are tracked with Git LFS; see the
  [README](../README.md) for the LFS note.
- `-d`/`--debug` enables debugging output on STDERR. Specify it multiple times
  to increase verbosity: `-d` (debug), `-dd` (TRACE), `-ddd` (SUPERTRACE). These
  levels are most useful to FLOSS developers and when reporting bugs.
- `--color {auto,always,never}` controls ANSI color codes in the results.
  `auto` (the default) colors only during an interactive session.

### Tags

FLOSS tags static strings with semantic context from embedded databases. There
are several tag families, each matching a tag directory under `floss/tags/data/`:

| Family | Tags | Source |
|---|---|---|
| `winapi` | `#winapi` | Windows API usage |
| `crt` | `#msvc` | Microsoft C runtime |
| `expert` | `#capa` | expert rules (e.g. capa) |
| `gp` | `#common`, `#code-junk` | global prevalence |
| `oss` | per-library, e.g. `#openssl`, `#zlib` | open-source libraries |

A tag family matches any tag in its family, so `--tag winapi`, `--tag oss`, and
`--tag gp` all work as selectors. Individual tags can also be matched directly
(e.g. `--tag openssl`). Tag names are normalized by stripping a leading `#` and
lowercasing, so `winapi`, `#WinAPI`, and `#winapi` are equivalent.

The databases are maintained out-of-tree and installed via Git objects/LFS; see
[scripts/tags/README.md](../scripts/tags/README.md) for the maintenance pipeline
(global prevalence, open-source libraries, and VirusTotal feed sampling).

### Environment variables

FLOSS reads the following environment variables:

| Variable | Effect |
|---|---|
| `FLOSS_CACHE_DIR` | directory for the analysis result cache (default: the platform cache directory) |
| `FLOSS_CACHE_ENABLE` | set to `0` to disable result caching (enabled by default) |
| `FLOSS_CACHE_REFRESH` | set to `1` to ignore the cached result and overwrite the entry (disabled by default) |
| `FLOSS_SAVE_WORKSPACE` | set to `0`/`no` to prevent saving the vivisect workspace to disk during deobfuscation |

Result caching is **enabled by default**. The full result document is cached on
first run and reused on later runs, so repeated analyses of the same sample are
fast. Because a cache hit may serve a document written by an earlier run, disable
it with `FLOSS_CACHE_ENABLE=0` (or point `FLOSS_CACHE_DIR` at a scratch
directory) when reproducing or diffing output across code changes.

### Write output as JSON (`-j/--json`)

Write FLOSS results to `stdout` structured in JSON to make it easy to ingest by a script.

    floss.exe -j malware.exe > malware_strings.json

The JSON document is the versioned `FLOSS` results schema. You can explore it
interactively in the [web viewer](../viewer/README.md), which supports uploading,
filtering, and copying this output. See the [results document](results_document.md)
for the schema overview.

### Load FLOSS results (automatic)

Loading a saved FLOSS results JSON document is automatic and detected from the file
content, so you can explore results without re-running the analysis.

    floss.exe malware_floss_results.json


### Verbose results (`-v`)

Enable verbose results output, e.g. including function offsets and string encoding.
This does not affect the JSON output.

    floss.exe -v malware.exe


### Quiet mode (`-q/--quiet`)

You can suppress the formatting of FLOSS output by providing
 the flags `-q` or `--quiet`.
These flags are appropriate if you will pipe the results of FLOSS
 into a filtering or searching program such as grep, and
 want to avoid matches on the section headers.
In quiet mode, each recovered string is printed on its
 own line.
The "type" of the string (static, decoded, stackstring, tightstring)
 is not included.

     floss.exe -q malware.exe


### Minimum string length (`-n/--minimum-length`)

By default, FLOSS searches for human-readable strings
 with a length of at least four characters.
You can use the `-n` or `--minimum-length` options to
 specific a different minimum length.
Supplying a larger minimum length reduces the chances
 of identifying random data that appears to be ASCII;
 however, FLOSS may then pass over short legitimate
 human-readable strings

    floss.exe -n 10 malware.exe


### Decoding function specification (`--analyze-functions`)

You can instruct FLOSS to decode the strings provided
 to specific functions by using the `--analyze-functions`
 option.
By default, FLOSS uses heuristics to identify decoding
 routines in malware.
This mode circumvents the identification phase and skips
 directly to the decoding phase.
If you've previously done analysis on an executable program
 and manually identified the decoding routines, use
 this mode.
This can improve performance as FLOSS by perhaps one-third
 (on the order of seconds, so it is usually _not_ worth it
  to always manually identify decoding routines).
Specify functions by using their hex-encoded virtual address.
Since `--analyze-functions` accepts multiple arguments, end the command options with a double dash `--`.

    floss.exe --analyze-functions 0x401000 0x402000 -- malware.exe


### Install/Uninstall right click menu option for Windows (`--install-right-click-menu/--uninstall-right-click-menu`)

You can use the `--install-right-click-menu` and `--uninstall-right-click-menu` 
 options to install/remove the `Open with FLOSS` option from the right-click menu 
 of the Windows file explorer.

After this option is installed, you can right-click on any file and select `Open with FLOSS`
 to quickly open the target file with FLOSS for analysis.


## <a name="shellcode"></a>Shellcode analysis options

Malicious shellcode often times contains obfuscated strings or stackstrings.
FLOSS can analyze raw binary files containing shellcode via the `-f/--format` switch. All
options mentioned above can also be applied when analyzing shellcode.

    floss -f sc32 malware.raw32
    floss -f sc64 malware.raw64

With `--format auto` (the default), FLOSS infers the sample format from its
contents. Shellcode is detected from the file name extension when the extension
matches `.sc32`/`.raw32` (32-bit) or `.sc64`/`.raw64` (64-bit); otherwise a file
is treated as a PE or ELF. You only need `-f sc32`/`-f sc64` when the file name
does not follow these conventions or the contents do not identify themselves as
PE/ELF.

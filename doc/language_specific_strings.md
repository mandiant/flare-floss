## Go String Extraction

Programs compiled by the Go compiler use a string representation that is difficult to interpret by humans. Although they are UTF-8 encoded, and therefore show up in the output of `strings.exe`, program strings are not NULL-terminated. This means separate strings within the binary may appear as a large chunk of indistinguishable string data.

FLOSS implements an algorithm to handle the unusual characteristics of strings in Go binaries. This approach analyzes instances of the `struct String` type to identify candidate strings and reasons about the length-sorted order to avoid false positives. Crucially, FLOSS automatically handles the complexities of Go strings and displays strings as written in the program's source code.

It's important to mention that there are other types of strings, such as runtime strings, which are not derived from the program strings.

### Algorithm:

1. Analyze the string instances within the binary.
    - In Go, strings are encoded as structs (see source code links below) containing two fields: a pointer to the string's underlying data and the length of the string.
    - By examining these instances, we can identify the strings and their locations within the binary.
2. Identify the longest continuous sequence of monotonically increasing string lengths to find the string blob.
3. Use the byte sequence `00 00 00 00` as a delimiter to accurately mark the boundaries of the string blob.
4. Extract the string blob located between the identified boundaries.
5. Split the identified string blob, based on the cross-references available in the binary to separate the individual strings.

Please note that while FLOSS handles many scenarios effectively, there are certain optimizations, such as inlined constants, that may not be fully supported yet.
For more information on Go strings, you can refer to the Go project's documentation and the source code of the struct String layout.

Learn more:

    Go Project: [Go Project](https://github.com/golang/go)
    Blog post: [Unveiling Go Strings: A Google Summer of Code Journey](https://medium.com/p/92f6d9fee97c)
    Source code:
    - https://github.com/golang/go/blob/36ea4f9680f8296f1c7d0cf7dbb1b3a9d572754a/src/builtin/builtin.go#L70-L73
    - https://github.com/golang/go/blob/38e2376f35907ebbb98419f1f4b8f28125bf6aaf/src/go/types/builtins.go#L824-L825

## Rust String Extraction

Similar to Go, Rust binaries may contain strings that are not NULL terminated. Separate strings within the binary may appear as larger chunks of indistinguishable string data.

FLOSS analyzes the data and code in Rust binaries to identify individual candidate strings.

### Algorithm:

1. Extract all UTF-8 encoded strings
2. Analyze data and code references to identify substring boundaries
3. Split strings from step 1 into individual parts as found in step 2

For more information on Rust strings, you can refer to the Rust project's documentation and the source code of the Rust String layout.

Learn more:

    Rust Project: [Rust Project](https://github.com/rust-lang/rust)
    Source code:
    - https://github.com/rust-lang/rust/blob/3911a63b7777e19dad4043542f908018e70c0bdd/library/alloc/src/string.rs

## Zig String Extraction

FLOSS identifies Zig binaries before applying language-specific string extraction. A single string such as `ZIG_PROGRESS` is not reliable evidence: it is absent from many normal Zig binaries and can be copied into non-Zig programs. The current detector therefore requires a weighted combination of PE structure, imports, and mapped runtime strings.

### Identification methodology

The scoring method was derived from a controlled corpus of Zig 0.12 through 0.16 `x86_64-windows` console executables covering Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Other architectures, binary formats, custom runtime configurations, and future Zig versions are outside that validated scope.

The detector assigns the following weights:

| Evidence                                                                      | Score |
| ----------------------------------------------------------------------------- | ----: |
| A `.tls` section and a populated TLS data directory                           |     4 |
| An `ntdll!RtlExitUserProcess` import                                          |     4 |
| An exact observed Zig Windows section bundle                                  |     2 |
| At least three mapped Zig-like runtime markers                                |     2 |
| `AcquireSRWLockExclusive`, `ReleaseSRWLockExclusive`, and `WriteFile` imports |     1 |

The observed section bundles are:

```text
.text .rdata .data .pdata .CRT .tls .reloc
.text .rdata .buildid .data .pdata .tls .reloc
```

The runtime marker set is:

```text
integer overflow
reached unreachable code
index out of bounds
thread\x20
panic:\x20
stack trace
```

A binary is identified as Zig only when it scores at least eight points, has both structural and runtime evidence, and has distinctive runtime evidence. Distinctive runtime evidence means either at least three runtime markers or the complete SRW-lock/`WriteFile` import trio. This final requirement rejects simple C programs built with `zig cc` that share Zig's linker characteristics but do not contain the Zig language runtime.

Runtime strings are searched only in bytes mapped by PE sections, bounded by each section's virtual and raw sizes. Strings appended to the PE overlay or stored in certificates do not contribute evidence.

This method identifies a match to the tested Zig Windows runtime lineage; it is not compiler attestation. Custom startup code, renamed sections, packing, obfuscation, alternate linkers, or removed runtime strings and imports may cause false negatives. Deliberately reproducing the same structure and runtime evidence may cause false positives. FLOSS does not infer a Zig compiler version or optimization mode from this evidence and reports the version as `version unknown`.

Zig has no dedicated string type. Strings are commonly represented as UTF-8 encoded `[]const u8` slices, whose runtime representation consists of a pointer to the underlying bytes and an exact byte length. The bytes referenced by separate slices may be adjacent in `.rdata`, causing conventional string extraction tools to display them as a single UTF-8 blob. FLOSS analyzes these slices and code references to recover the original string boundaries.

Currently, Zig language-specific string extraction supports 32-bit and 64-bit PE binaries. Automatic Zig identification does not support ELF or Mach-O binaries.

### Extraction algorithm

1. Locate the PE `.rdata` section and extract its candidate strings.
2. Identify string boundaries from valid Zig slice candidates. Each slice provides both the start address and exact byte length of a UTF-8 string.
3. Add boundaries discovered from code references:
    - On 32-bit x86, inspect `LEA`, `PUSH`, and `MOV` references.
    - On 64-bit x86, inspect `LEA` references.
4. Correct cases where `binary2strings` interprets referenced UTF-8 bytes as wide strings.
5. Split UTF-8 blobs at the collected boundaries, discard invalid or shorter-than-requested strings, and remove duplicates.

Learn more:

    Zig language reference: [Ziglang Org](https://ziglang.org/documentation/master/#Slices)
    Strings in Zig: [Ziggit](https://ziggit.dev/t/working-with-strings-in-zig/2384)
    Source code:
    - https://codeberg.org/ziglang/zig/src/commit/7b02ab758845d553ef4399548274ef2e23eaeb2f/src/Air.zig#L710-L719

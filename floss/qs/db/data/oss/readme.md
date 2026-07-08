# Strings from Open Source libraries

This directory contains databases of strings extracted from open soure software. FLOSS uses these databases to show the user when a string is likely from a library.

There is one file for each database. Each database is a gzip-compressed, JSONL (one JSON document per line) file.
The JSON document looks like this:

    string: "1.0.8, 13-Jul-2019"
    library_name: "bzip2"
    library_version: "1.0.8#3"
    file_path: "CMakeFiles/bz2.dir/bzlib.c.obj"
    function_name: "BZ2_bzlibVersion"
    line_number: null

The following databases were extracted via the vkpkg & jh technique:

  - brotli 1.0.9#5
  - bzip2 1.0.8#3
  - cryptopp 8.7.0
  - curl 7.86.0#1
  - detours 4.0.1#7
  - jemalloc 5.3.0#1
  - jsoncpp 1.9.5
  - kcp 1.7
  - liblzma 5.2.5#6
  - libsodium 1.0.18#8
  - libpcap 1.10.1#3
  - mbedtls 2.28.1
  - openssl 3.0.7#1
  - sqlite3 3.40.0#1
  - tomcrypt 1.18.2#2
  - wolfssl 5.5.0
  - zlib 1.2.13

## The vkpkg & jh technique

Major steps:

  1. build static libraries via vcpkg
  2. extract features via jh
  3. convert to JSONL format with `jh_to_qs.py`
  4. compress with gzip

### Build static libraries via vcpkg

[vcpkg](https://vcpkg.io/en/) is a free C/C++ package manager for acquiring and managing libraries.
We use it to easily build common open source libraries, like zlib.
Use the triplet `x64-windows-static` to build static archives (.lib files that are AR archives containing COFF object files):

```console
PS > C:\vcpkg\vcpkg.exe install --triplet x64-windows-static zlib
```

### Why these build parameters

We use `triplet=x64-windows-static`, `compiler=msvc143`, `profile=release` to match FLOSS's primary target (PE binaries on Windows). MSVC v143 was the current Visual Studio toolchain at the time the databases were first generated; switching to a newer toolchain would be expected to shift extracted string counts only marginally, since most strings come from source-level literals and symbol names.

A cross-platform check (macOS arm64 vs. MinGW x86_64) showed total counts stay similar but per-string overlap is low: most non-overlap is random printable byte runs in compiled code (which differ per ISA), section/segment names (`.rdata` vs. `__TEXT,__cstring`), and symbol conventions (Mach-O prefixes C symbols with `_`, COFF does not). We keep the databases Windows-only since FLOSS targets PE.

### Extract features via jh

[jh](https://github.com/williballenthin/lancelot/blob/master/bin/src/bin/jh.rs)
is a lancelot-based utility that parses AR archives containing COFF object files,
reconstructs their control flow, finds functions, and extracts features.
jh extracts numbers, API calls, and strings; we are only interested in the string features.

For each feature, jh emits a CSV line with the fields
  - target triplet
  - compiler
  - library
  - version
  - build profile
  - path
  - function
  - feature type
  - feature value

For example:

```csv
x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffCompress,number,0x00000100
```

For example, to invoke jh:

```console
$ ~/lancelot/target/release/jh x64-windows-static msvc143 zlib 1.2.13 release /mnt/c/vcpkg/installed/x64-windows-static/lib/zlib.lib > ~/flare-floss/floss/qs/db/data/oss/zlib.csv
```

### Convert to OSS database format

We use the script `jh_to_qs.py` to convert these CSV lines into JSONL file prepared for FLOSS:

```console
$ python3 jh_to_qs.py zlib.csv > zlib.jsonl
```

These files are then gzip'd:

```console
$  gzip -c zlib.jsonl > zlib.jsonl.gz
```

The `build_oss_db.py` script automates the steps above and merges into
any `.jsonl.gz` already present in the output directory rather than
replacing them. For each library being rebuilt, the newly-extracted
entries are combined with the existing entries (new entries win on
string collisions, which is the right behavior when the library version
changes).


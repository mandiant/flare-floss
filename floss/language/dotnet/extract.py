# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Extract strings from .NET PE binaries by parsing the CLI metadata heaps.

Background
----------
.NET (CLI) executables store their user strings in a dedicated metadata heap
called the **#US** (User Strings) heap.  This is separate from the #Strings
heap which stores identifiers (type names, field names, etc.).

Structure overview:

    PE file
    └── .text section (or whichever section the CLR header lands in)
        └── IMAGE_COR20_HEADER  (pointed to by DataDirectory[14])
            ├── MetaData RVA  →  Metadata root  ("BSJB" magic)
            │   ├── StreamHeaders[]
            │   │   ├── "#~"  / "#-"  – compressed / uncompressed tables
            │   │   ├── "#Strings"   – identifier strings (null-terminated UTF-8)
            │   │   ├── "#US"        – user strings (length-prefixed UTF-16LE)
            │   │   ├── "#GUID"
            │   │   └── "#Blob"
            │   └── …
            └── …

The #US heap format (ECMA-335 §II.24.2.4):
  - Offset 0 is always a single 0x00 byte (the "empty string" sentinel).
  - Each subsequent entry is:
      <compressed-uint: byte count including trailing flag byte>
      <UTF-16LE data>
      <1 trailing flag byte (0x00 or 0x01)>
  - "byte count" includes the trailing flag byte, so the number of UTF-16LE
    code units is  (byte_count - 1) / 2.

References
----------
  * ECMA-335 6th edition, §II.24
  * https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md
  * https://github.com/0xd4d/dnlib  (C# reference implementation)
  * https://github.com/mandiant/flare-floss/issues/718
"""

import sys
import struct
import logging
import pathlib
import argparse
from typing import List, Iterator, Tuple, Optional

import pefile

from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4

# Magic bytes that mark the start of CLI metadata
_METADATA_MAGIC = b"BSJB"

# Name of the user-string heap
_US_HEAP_NAME = b"#US"

# The CLR COM descriptor sits at DataDirectory index 14
_CLR_DIRECTORY_INDEX = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _read_compressed_uint(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Read an ECMA-335 compressed unsigned integer from *data* at *offset*.

    Returns (value, bytes_consumed).

    The encoding (ECMA-335 §II.23.2):
      - 1 byte  if high bit is 0:           value = byte & 0x7F
      - 2 bytes if high bits are 10:        value = ((byte & 0x3F) << 8) | next
      - 4 bytes if high bits are 110:       value = ((byte & 0x1F) << 24) | …
    """
    first = data[offset]
    if first & 0x80 == 0:
        return first, 1
    elif first & 0xC0 == 0x80:
        if offset + 1 >= len(data):
            raise ValueError("truncated 2-byte compressed uint")
        second = data[offset + 1]
        return ((first & 0x3F) << 8) | second, 2
    elif first & 0xE0 == 0xC0:
        if offset + 3 >= len(data):
            raise ValueError("truncated 4-byte compressed uint")
        b1, b2, b3 = data[offset + 1], data[offset + 2], data[offset + 3]
        return ((first & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3, 4
    else:
        raise ValueError(f"invalid compressed uint first byte: 0x{first:02x}")


def _find_metadata_root(pe: pefile.PE) -> Optional[Tuple[int, int]]:
    """
    Locate the CLI metadata root inside the PE.

    Returns (file_offset, rva) of the BSJB magic, or None if not found.
    """
    try:
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_CLR_DIRECTORY_INDEX]
    except IndexError:
        logger.debug("no CLR data directory entry")
        return None

    if clr_dir.VirtualAddress == 0 or clr_dir.Size == 0:
        logger.debug("CLR data directory entry is empty")
        return None

    # The IMAGE_COR20_HEADER is at the CLR directory RVA.
    # Layout (§II.25.3.3):
    #   DWORD Cb;                    //  0
    #   WORD  MajorRuntimeVersion;   //  4
    #   WORD  MinorRuntimeVersion;   //  6
    #   IMAGE_DATA_DIRECTORY MetaData;  // 8  (VirtualAddress + Size, 8 bytes)
    #   …
    clr_rva = clr_dir.VirtualAddress
    try:
        clr_data = pe.get_data(clr_rva, 16)
    except pefile.PEFormatError as e:
        logger.debug("cannot read CLR header: %s", e)
        return None

    metadata_rva, _metadata_size = struct.unpack_from("<II", clr_data, 8)
    if metadata_rva == 0:
        logger.debug("metadata RVA is zero")
        return None

    try:
        metadata_file_offset = pe.get_offset_from_rva(metadata_rva)
    except pefile.PEFormatError as e:
        logger.debug("cannot convert metadata RVA to file offset: %s", e)
        return None

    return metadata_file_offset, metadata_rva


def _get_us_heap(buf: bytes, metadata_file_offset: int) -> Optional[Tuple[int, int]]:
    """
    Parse the metadata stream headers and return (file_offset, size) of the
    #US heap, or None if not found.

    Metadata root layout (ECMA-335 §II.24.2.1):
      DWORD  Signature;           // "BSJB"
      WORD   MajorVersion;
      WORD   MinorVersion;
      DWORD  Reserved;
      DWORD  Length;              // length of version string (padded to 4-byte boundary)
      CHAR   Version[Length];
      WORD   Flags;
      WORD   Streams;             // number of stream headers
      StreamHeader[] {
          DWORD Offset;           // offset from metadata root
          DWORD Size;
          CHAR  Name[];           // null-terminated, padded to 4-byte boundary
      }
    """
    offs = metadata_file_offset

    # Check BSJB magic
    if buf[offs : offs + 4] != _METADATA_MAGIC:
        logger.debug("BSJB magic not found at offset 0x%x", offs)
        return None

    offs += 4  # Signature
    offs += 2  # MajorVersion
    offs += 2  # MinorVersion
    offs += 4  # Reserved

    # Version string
    version_length = struct.unpack_from("<I", buf, offs)[0]
    offs += 4
    offs += version_length  # skip version string bytes (already padded)

    offs += 2  # Flags
    num_streams = struct.unpack_from("<H", buf, offs)[0]
    offs += 2

    for _ in range(num_streams):
        stream_offset = struct.unpack_from("<I", buf, offs)[0]
        stream_size = struct.unpack_from("<I", buf, offs + 4)[0]
        offs += 8

        # Read null-terminated stream name, padded to 4-byte boundary
        name_start = offs
        while offs < len(buf) and buf[offs] != 0:
            offs += 1
        name = buf[name_start:offs]
        offs += 1  # consume null terminator

        # Align to 4-byte boundary
        offs = (offs + 3) & ~3

        if name == _US_HEAP_NAME:
            us_file_offset = metadata_file_offset + stream_offset
            logger.debug("#US heap: file_offset=0x%x size=0x%x", us_file_offset, stream_size)
            return us_file_offset, stream_size

    logger.debug("#US heap not found in metadata streams")
    return None


# ---------------------------------------------------------------------------
# Public extraction API
# ---------------------------------------------------------------------------


def iter_dotnet_user_strings(buf: bytes, us_file_offset: int, us_size: int) -> Iterator[Tuple[str, int]]:
    """
    Walk the #US (User Strings) heap and yield (string, file_offset) tuples.

    Each entry in the heap:
      <compressed-uint>  – total byte count of (UTF-16LE data + trailing flag)
      <UTF-16LE data>    – (byte_count - 1) bytes
      <flag byte>        – 0x00 or 0x01 (high-surrogate / special chars hint)

    The first byte of the heap is always 0x00 (empty string sentinel), which
    we skip.
    """
    pos = 1  # skip first sentinel byte

    while pos < us_size:
        entry_file_offset = us_file_offset + pos
        try:
            byte_count, size_of_compressed = _read_compressed_uint(buf, us_file_offset + pos)
        except (ValueError, IndexError) as e:
            logger.debug("error reading compressed uint at 0x%x: %s", us_file_offset + pos, e)
            break

        pos += size_of_compressed

        if byte_count == 0:
            # empty string entry – skip
            continue

        # byte_count includes the trailing flag byte
        utf16_byte_count = byte_count - 1
        data_start = us_file_offset + pos

        if data_start + utf16_byte_count > len(buf):
            logger.debug("string data extends beyond buffer at 0x%x", data_start)
            break

        raw = buf[data_start : data_start + utf16_byte_count]

        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
        else:
            yield s, entry_file_offset

        pos += byte_count  # advance past data + flag byte


def extract_dotnet_strings(sample: pathlib.Path, min_length: int = MIN_STR_LEN) -> List[StaticString]:
    """
    Extract user strings from a .NET PE binary.

    Parses the CLI metadata #US (User Strings) heap to recover the string
    literals that the .NET author embedded in the binary.  These strings are
    stored as length-prefixed UTF-16LE entries and are NOT found by ordinary
    printable-character scanners.

    Args:
        sample:     path to the .NET PE file
        min_length: minimum string length (in characters) to include

    Returns:
        list of StaticString instances, one per #US heap entry
    """
    p = pathlib.Path(sample)
    buf = p.read_bytes()

    try:
        pe = pefile.PE(data=buf, fast_load=True)
    except pefile.PEFormatError as e:
        logger.error("cannot parse PE file %s: %s", sample, e)
        return []

    result = _find_metadata_root(pe)
    if result is None:
        logger.warning("could not locate .NET metadata root in %s", sample)
        return []

    metadata_file_offset, _ = result

    us_heap = _get_us_heap(buf, metadata_file_offset)
    if us_heap is None:
        logger.warning("could not find #US heap in %s", sample)
        return []

    us_file_offset, us_size = us_heap

    strings: List[StaticString] = []
    seen: set = set()

    for s, file_offset in iter_dotnet_user_strings(buf, us_file_offset, us_size):
        if len(s) < min_length:
            continue

        # Strip null characters that may be present inside UTF-16LE strings
        s = s.rstrip("\x00")
        if len(s) < min_length:
            continue

        if not s.isprintable() and not any(c in s for c in "\n\r\t"):
            continue

        # Deduplicate (same string may appear at distinct offsets in the heap,
        # e.g. when a string literal is shared across methods).
        key = (s, file_offset)
        if key in seen:
            continue
        seen.add(key)

        strings.append(StaticString(string=s, offset=file_offset, encoding=StringEncoding.UTF16LE))

    logger.debug("extracted %d .NET user strings from %s", len(strings), sample)
    return strings


# ---------------------------------------------------------------------------
# CLI entry point (mirrors Go/Rust extractor pattern)
# ---------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract .NET user strings from a PE binary")
    parser.add_argument("path", help="path to .NET PE file to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length (default: %(default)s)",
    )
    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.DEBUG)

    dotnet_strings = sorted(
        extract_dotnet_strings(pathlib.Path(args.path), args.min_length),
        key=lambda s: s.offset,
    )
    for string in dotnet_strings:
        print(f"0x{string.offset:08x}: {string.string}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

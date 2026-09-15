# Copyright 2026 Google LLC
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

import sys
import logging
import pathlib
import argparse
import itertools
from typing import List, Tuple, Iterable, Optional

import pefile
import binary2strings as b2s

from floss.results import StaticString
from floss.language.utils import (
    find_lea_xrefs,
    find_mov_xrefs,
    find_push_xrefs,
    get_rdata_section,
    get_struct_string_candidates,
)

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4

B2SString = Tuple[str, str, Tuple[int, int], bool]


def fix_b2s_wide_strings(
    strings: List[B2SString],
    boundaries: Iterable[int],
    min_length: int,
    buffer: bytes,
    start_rdata: int,
) -> List[B2SString]:
    """Recover referenced UTF-8 strings that binary2strings parsed as wide strings."""

    boundaries = set(boundaries)
    fixed_strings: List[B2SString] = []
    last_fixup: Optional[B2SString] = None

    for string in strings:
        value, string_type, (start, _), _ = string

        if string_type == "WIDE_STRING":
            encoded = value.encode("utf-16le", "ignore")
            corrected_start = start + 1
            if (
                encoded
                and encoded[0] == 0
                and start_rdata + corrected_start in boundaries
            ):
                recovered = b2s.extract_string(buffer[corrected_start:])
                last_fixup = (
                    recovered[0],
                    recovered[1],
                    (
                        recovered[2][0] + corrected_start,
                        recovered[2][1] + corrected_start,
                    ),
                    recovered[3],
                )
                if recovered[1] != "UTF8" or len(recovered[0]) < min_length:
                    last_fixup = None
        else:
            if last_fixup and value in last_fixup[0]:
                fixed_strings.append(last_fixup)
            else:
                fixed_strings.append(string)
            last_fixup = None

    if last_fixup:
        fixed_strings.append(last_fixup)

    return fixed_strings


def get_static_strings_from_rdata(
    sample: pathlib.Path, static_strings: List[StaticString]
) -> List[StaticString]:
    pe = pefile.PE(data=sample.read_bytes(), fast_load=True)

    try:
        rdata_section = get_rdata_section(pe)
    except ValueError:
        return []

    start_rdata = rdata_section.PointerToRawData
    end_rdata = start_rdata + rdata_section.SizeOfRawData
    return [
        string for string in static_strings if start_rdata <= string.offset < end_rdata
    ]


def get_slice_strings(pe: pefile.PE) -> Iterable[StaticString]:
    """Yield complete UTF-8 slices with virtual addresses and unmodified contents."""

    image_base = pe.OPTIONAL_HEADER.ImageBase

    for candidate in get_struct_string_candidates(pe):
        data = pe.get_data(candidate.address - image_base, candidate.length)
        if len(data) != candidate.length:
            continue
        try:
            # Preserve valid slice boundaries regardless of the output length threshold.
            yield StaticString.from_utf8(data, candidate.address, 1)
        except ValueError:
            continue


def get_string_boundaries(
    pe: pefile.PE, slice_strings: Optional[Iterable[StaticString]] = None
) -> Iterable[int]:
    """Yield virtual addresses that delimit Zig strings."""

    if slice_strings is None:
        slice_strings = get_slice_strings(pe)

    for string in slice_strings:
        # Zig slices store both the pointer and the exact byte length.
        yield string.offset
        yield string.offset + len(string.string.encode("utf-8"))

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        yield from itertools.chain(
            find_lea_xrefs(pe), find_push_xrefs(pe), find_mov_xrefs(pe)
        )
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        yield from find_lea_xrefs(pe)
    else:
        raise ValueError(f"unsupported architecture: {pe.FILE_HEADER.Machine}")


def split_utf8_strings(
    strings: List[B2SString],
    start_rdata: int,
    boundaries: Iterable[int],
    min_length: int,
) -> List[StaticString]:
    """Split UTF-8 blobs at referenced byte offsets."""

    boundaries = sorted(set(boundaries))
    extracted_strings: List[StaticString] = []

    for value, string_type, (relative_start, _), _ in strings:
        if string_type != "UTF8":
            continue

        data = value.encode("utf-8")
        start = start_rdata + relative_start
        end = start + len(data)
        split_offsets = [start]
        split_offsets.extend(
            boundary for boundary in boundaries if start < boundary < end
        )
        split_offsets.append(end)

        for part_start, part_end in zip(split_offsets, split_offsets[1:]):
            relative_part_start = part_start - start
            relative_part_end = part_end - start

            try:
                part = (
                    data[relative_part_start:relative_part_end]
                    .decode("utf-8")
                    .replace("\n", "")
                )
                extracted_strings.append(
                    StaticString.from_utf8(part.encode("utf-8"), part_start, min_length)
                )
            except ValueError:
                continue

    return list(dict.fromkeys(extracted_strings))


def get_string_blob_strings(pe: pefile.PE, min_length: int) -> Iterable[StaticString]:
    try:
        rdata_section = get_rdata_section(pe)
    except ValueError as error:
        logger.error("cannot extract Zig strings: %s", error)
        return []

    image_base = pe.OPTIONAL_HEADER.ImageBase
    section_va = image_base + rdata_section.VirtualAddress
    section_start = rdata_section.PointerToRawData
    try:
        slice_strings = list(get_slice_strings(pe))
        boundaries = [
            address - section_va + section_start
            for address in get_string_boundaries(pe, slice_strings)
            if section_va <= address < section_va + rdata_section.SizeOfRawData
        ]
        strings = b2s.extract_all_strings(rdata_section.get_data(), min_length)
        strings = fix_b2s_wide_strings(
            strings,
            boundaries,
            min_length,
            rdata_section.get_data(),
            rdata_section.PointerToRawData,
        )
        extracted_strings = split_utf8_strings(
            strings, section_start, boundaries, min_length
        )
        # Boundary splitting cannot preserve overlapping slices; emit their exact ranges too.
        for string in slice_strings:
            slice_end = string.offset + len(string.string.encode("utf-8"))
            if not (
                section_va
                <= string.offset
                < slice_end
                <= section_va + rdata_section.SizeOfRawData
            ):
                continue
            try:
                extracted_strings.append(
                    StaticString.from_utf8(
                        string.string.replace("\n", "").encode("utf-8"),
                        string.offset - section_va + section_start,
                        min_length,
                    )
                )
            except ValueError:
                continue
        return list(dict.fromkeys(extracted_strings))
    except ValueError as error:
        logger.error("cannot extract Zig strings: %s", error)
        return []


def extract_zig_strings(sample: pathlib.Path, min_length: int) -> List[StaticString]:
    """Extract strings from a Zig PE binary."""

    pe = pefile.PE(data=sample.read_bytes(), fast_load=True)
    return list(get_string_blob_strings(pe, min_length))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Get Zig strings")
    parser.add_argument("path", type=pathlib.Path, help="file to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length",
    )
    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.DEBUG)

    zig_strings = sorted(
        extract_zig_strings(args.path, args.min_length),
        key=lambda string: string.offset,
    )
    for string in zig_strings:
        print(f"{string.offset:#x}: {string.string}")


if __name__ == "__main__":
    sys.exit(main())

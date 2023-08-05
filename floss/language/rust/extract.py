# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import sys
import logging
import pathlib
import argparse
from typing import List, Tuple, Iterable, Optional

import pefile
import binary2strings as b2s
from typing_extensions import TypeAlias

from floss.results import StaticString, StringEncoding
from floss.language.utils import find_lea_xrefs, get_struct_string_candidates

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4

VA: TypeAlias = int


def get_rdata_section_info(pe: pefile.PE) -> Tuple[int, int, int, int]:
    """
    Retrieve info about .rdata section
    """
    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            virtual_address = section.VirtualAddress
            pointer_to_raw_data = section.PointerToRawData
            section_size = section.SizeOfRawData
            break

    start_address = pointer_to_raw_data
    end_address = pointer_to_raw_data + section_size

    return start_address, end_address, virtual_address, pointer_to_raw_data


def filter_strings(
    strings: List[Tuple[str, str, Tuple[int, int], bool]], start_rdata: int, end_rdata: int
) -> List[Tuple[str, int, int]]:
    """
    Extract strings only from .rdata segment, discard others
    """

    ref_data = []

    for string in strings:
        start = string[2][0] + start_rdata
        end = string[2][1] + start_rdata
        string_type = string[1]
        if not (start_rdata <= start < end_rdata):
            continue
        if not (start_rdata <= end < end_rdata):
            continue
        if string_type != "UTF8":
            continue

        ref_data.append((string[0], start, end))

    return ref_data


def split_string(ref_data: List[Tuple[str, int, int]], address: int) -> None:
    """
    if address is in between start and end of a string in ref data then split the string
    """

    for ref in ref_data:
        if ref[1] < address < ref[2]:
            # split the string and add it to ref_data
            ref_data.append((ref[0][0 : address - ref[1]], ref[1], address))
            ref_data.append((ref[0][address - ref[1] :], address, ref[2]))

            # remove the original string
            ref_data.remove(ref)

            break


def extract_utf8_strings(sample: pefile.PE, min_length: int) -> List[StaticString]:
    """
    Extract UTF-8 strings from the given PE file using binary2strings
    """

    p = pathlib.Path(sample)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    image_base = pe.OPTIONAL_HEADER.ImageBase

    start_rdata, end_rdata, virtual_address, pointer_to_raw_data = get_rdata_section_info(pe)

    # extract utf-8 strings
    strings = list(b2s.extract_all_strings(buf[start_rdata:end_rdata], min_length))

    # Filtering out strings that are not in .rdata
    ref_data = filter_strings(strings, start_rdata, end_rdata)

    # Get Struct string instances for .rdata section
    candidates = get_struct_string_candidates(pe)

    for can in candidates:
        address = can.address - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        split_string(ref_data, address)

    # Get references from .text segment
    xrefs = find_lea_xrefs(pe)

    for xref in xrefs:
        address = xref - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        split_string(ref_data, address)

    static_strings = []

    for ref in ref_data:
        try:
            string = StaticString.from_utf8(ref[0].replace("\n", "").encode("utf-8"), ref[1], min_length)
            static_strings.append(string)
        except ValueError:
            pass

    return static_strings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Get Rust strings")
    parser.add_argument("path", help="file or path to analyze")
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

    rust_strings = sorted(extract_utf8_strings(args.path, args.min_length), key=lambda s: s.offset)
    for string in rust_strings:
        print(f"{string.offset:#x}: {string.string}")


if __name__ == "__main__":
    sys.exit(main())

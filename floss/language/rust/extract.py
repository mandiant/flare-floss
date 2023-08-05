# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
import sys
import array
import struct
import logging
import pathlib
import argparse
from typing import List, Tuple, Iterable, Optional
from pathlib import Path
from itertools import chain
from dataclasses import dataclass

import pefile
import binary2strings as b2s
from typing_extensions import TypeAlias

import floss.utils
from floss.results import StaticString, StringEncoding
from floss.language.utils import StructString, find_lea_xrefs, get_struct_string_candidates

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4

VA: TypeAlias = int

def extract_utf8_strings(sample, min_length) -> List[StaticString]:
    """
    extract UTF-8 strings from the given PE file using binary2strings
    """
    p = pathlib.Path(sample)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    image_base = pe.OPTIONAL_HEADER.ImageBase

    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            virtual_address = section.VirtualAddress
            pointer_to_raw_data = section.PointerToRawData
            section_size = section.SizeOfRawData
            break

    start_rdata = pointer_to_raw_data
    end_rdata = pointer_to_raw_data + section_size

    with floss.utils.timing("extract UTF-8 strings"):
        strings = list(b2s.extract_all_strings(buf[start_rdata:end_rdata], min_length))

    ref_data = []

    # Filtering out some strings
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

    # Get Struct string instances for .rdata section
    candidates = get_struct_string_candidates(pe)

    for can in candidates:
        address = can.address - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        # if address is in between start and end of a string in ref data then split the string
        for ref in ref_data:
            if ref[1] < address < ref[2]:
                # split the string and add it to ref_data
                ref_data.append((ref[0][0 : address - ref[1]], ref[1], address))
                ref_data.append((ref[0][address - ref[1] :], address, ref[2]))

                # remove the original string
                ref_data.remove(ref)

                break

    # Get references from .text segment
    xrefs = find_lea_xrefs(pe)

    for xref in xrefs:
        address = xref - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        # if address is in between start and end of a string in ref data then split the string
        for ref in ref_data:
            if ref[1] < address < ref[2]:
                # split the string and add it to ref_data
                ref_data.append((ref[0][0 : address - ref[1]], ref[1], address))
                ref_data.append((ref[0][address - ref[1] :], address, ref[2]))

                # remove the original string
                ref_data.remove(ref)

                break

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

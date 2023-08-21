# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import sys
import logging
import pathlib
import argparse
from typing import List, Tuple, Iterable, Optional
from collections import namedtuple

import pefile
import binary2strings as b2s
from typing_extensions import TypeAlias

from floss.results import StaticString, StringEncoding
from floss.language.utils import find_lea_xrefs, get_struct_string_candidates

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4

VA: TypeAlias = int

Strings = namedtuple("Strings", ["string", "start_address", "end_address"])


def get_rdata_section_info(pe: pefile.PE) -> pefile.SectionStructure:
    """
    Retrieve info about .rdata section
    """
    rdata_structure = None

    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            rdata_structure = section
            break
    else:
        logger.error("No .rdata section found")

    return rdata_structure


def filter_and_transform_utf8_strings(
    strings: List[Tuple[str, str, Tuple[int, int], bool]], start_rdata: int
) -> List[Strings]:
    ref_data = []

    for string in strings:
        start = string[2][0] + start_rdata
        end = string[2][1] + start_rdata
        string_type = string[1]
        if string_type != "UTF8":
            continue

        ref_data.append(Strings(string[0], start, end))

    return ref_data


def split_string(ref_data: List[Strings], static_strings: List[StaticString], address: int) -> None:
    """
    if address is in between start and end of a string in ref data then split the string
    """

    for ref in ref_data:
        if ref[1] <= address < ref[2]:
            # split the string and add it to ref_data
            ref_data.append(Strings(ref[0][0 : address - ref[1]], ref[1], address))
            ref_data.append(Strings(ref[0][address - ref[1] :], address, ref[2]))

            # split the string and add it to static_strings
            try:
                static_strings.append(
                    StaticString.from_utf8(ref[0][0 : address - ref[1]].encode("utf-8"), ref[1], MIN_STR_LEN)
                )
            except ValueError:
                pass

            try:
                static_strings.append(
                    StaticString.from_utf8(ref[0][address - ref[1] :].encode("utf-8"), address, MIN_STR_LEN)
                )
            except ValueError:
                pass

            # remove from static strings if it exists
            for string in static_strings:
                if string.string == ref[0]:
                    static_strings.remove(string)
                    break

            # remove the original string
            ref_data.remove(ref)

            break


def extract_rust_strings(sample: pefile.PE, min_length: int) -> List[StaticString]:
    """
    Extract UTF-8 strings from the given PE file using binary2strings
    """

    p = pathlib.Path(sample)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)
    static_strings = []

    image_base = pe.OPTIONAL_HEADER.ImageBase

    rdata_section = get_rdata_section_info(pe)

    # If .rdata section is not found
    if rdata_section == None:
        return []

    start_rdata = rdata_section.PointerToRawData
    end_rdata = start_rdata + rdata_section.SizeOfRawData
    virtual_address = rdata_section.VirtualAddress
    pointer_to_raw_data = rdata_section.PointerToRawData

    # extract utf-8 strings
    strings = list(b2s.extract_all_strings(buf[start_rdata:end_rdata], min_length))

    # filter out strings that are not UTF-8 and transform them
    ref_data = filter_and_transform_utf8_strings(strings, start_rdata)

    # append all the ref_data strings to static_strings
    for ref in ref_data:
        try:
            static_strings.append(StaticString.from_utf8(ref[0].encode("utf-8"), ref[1], min_length))
        except ValueError:
            pass

    # Get Struct string instances for .rdata section
    candidates = get_struct_string_candidates(pe)

    for can in candidates:
        address = can.address - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        split_string(ref_data, static_strings, address)

    # Get references from .text segment
    xrefs = find_lea_xrefs(pe)

    for xref in xrefs:
        address = xref - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        split_string(ref_data, static_strings, address)

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

    rust_strings = sorted(extract_rust_strings(args.path, args.min_length), key=lambda s: s.offset)
    for string in rust_strings:
        print(f"{string.offset:#x}: {string.string}")


if __name__ == "__main__":
    sys.exit(main())
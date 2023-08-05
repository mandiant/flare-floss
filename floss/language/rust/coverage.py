# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import sys
import logging
import pathlib
import argparse
from typing import List, Tuple, Iterable, Optional

import pefile

from floss.results import StaticString
from floss.strings import extract_ascii_unicode_strings
from floss.language.rust.extract import extract_utf8_strings

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4


def main():
    parser = argparse.ArgumentParser(description="Get Go strings")
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length",
    )
    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="disable all status output except fatal errors",
    )
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    try:
        pe = pefile.PE(args.path)
    except pefile.PEFormatError as err:
        logger.debug(f"NOT a valid PE file: {err}")
        return 1

    path = pathlib.Path(args.path)

    # see only .rdata section
    buf = path.read_bytes()
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

    static_strings: List[StaticString] = extract_ascii_unicode_strings(buf[start_rdata:end_rdata], args.min_length)

    rust_strings = extract_utf8_strings(path, args.min_length)

    get_extract_stats(pe, static_strings, rust_strings, args.min_length)


def get_extract_stats(pe, static_strings, rust_strings, min_length):
    total_static_string_length = 0
    for static_string in static_strings:
        string = static_string.string
        total_static_string_length += len(string)

    total_extracted_rust_string_length = 0

    for rust_string in rust_strings:
        string = rust_string.string
        total_extracted_rust_string_length += len(string)

    percentage = format((total_extracted_rust_string_length / total_static_string_length) * 100, ".2f")

    print("Percentage of string extracted: ", percentage)


if __name__ == "__main__":
    sys.exit(main())

# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
import sys
import logging
import pathlib
import argparse
from typing import Any, List, Tuple, Iterable, Optional

import pefile

MIN_STR_LEN = 4

logger = logging.getLogger(__name__)


def get_rdata_section(pe: pefile.PE) -> pefile.SectionStructure:
    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            return section

    raise ValueError("no .rdata section found")


def extract_utf8_strings_from_buffer(buf, min_length=MIN_STR_LEN) -> List[List[Any]]:
    """
    Extracts UTF-8 strings from a buffer.
    """

    # Reference: https://en.wikipedia.org/wiki/UTF-8

    strings = []

    for i in range(0, len(buf)):
        # for 1 byte
        if buf[i] & 0x80 == 0x00:
            character = buf[i].to_bytes(1, "big").decode("utf-8", "ignore")
            strings.append([character, i])

        # for 2 bytes
        elif buf[i] & 0xE0 == 0xC0:
            temp = buf[i] << 8 | buf[i + 1]
            character = temp.to_bytes(2, "big").decode("utf-8", "ignore")
            i += 1
            strings.append([character, i])

        # for 3 bytes
        elif buf[i] & 0xF0 == 0xE0:
            temp = buf[i] << 16 | buf[i + 1] << 8 | buf[i + 2]
            character = temp.to_bytes(3, "big").decode("utf-8", "ignore")
            i += 2
            strings.append([character, i])

        # for 4 bytes
        elif buf[i] & 0xF8 == 0xF0:
            temp = buf[i] << 24 | buf[i + 1] << 16 | buf[i + 2] << 8 | buf[i + 3]
            character = temp.to_bytes(4, "big").decode("utf-8", "ignore")
            i += 3
            strings.append([character, i])

    prev = False

    for i in range(0, len(strings)):
        if strings[i][0].isprintable() == True:
            if prev == False:
                strings.append([strings[i][0], strings[i][1]])
                prev = True
            else:
                strings[-1][0] += strings[i][0]
                strings[-1][1] = strings[i][1]
        else:
            prev = False

    # filter strings less than min length
    strings = [string for string in strings if len(string[0]) >= min_length]

    print(strings)

    return strings


def extract_utf8_strings(pe: pefile.PE, min_length=MIN_STR_LEN) -> List[List[Any]]:
    """
    Extracts UTF-8 strings from the .rdata section of a PE file.
    """
    try:
        rdata_section = get_rdata_section(pe)
    except ValueError as e:
        print("cannot extract rust strings: %s", e)
        return []

    buf = pe.get_memory_mapped_image()[
        rdata_section.VirtualAddress : rdata_section.VirtualAddress + rdata_section.SizeOfRawData
    ]
    strings = extract_utf8_strings_from_buffer(buf, min_length)
    return strings


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

    pe = pathlib.Path(args.path)
    buf = pe.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    strings = extract_utf8_strings(pe, args.min_length)
    for string in strings:
        print(string[0])


if __name__ == "__main__":
    sys.exit(main())

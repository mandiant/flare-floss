# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
import sys
import pathlib
import argparse
from typing import Any, List, Tuple, Iterable, Optional
from collections import namedtuple

import pefile

import floss.logging_
from floss.language.utils import get_rdata_section

MIN_STR_LEN = 4

logger = floss.logging_.getLogger(__name__)


def extract_utf8_strings_from_buffer(buf, min_length=MIN_STR_LEN) -> List[List[Tuple[str, int, int]]]:
    """
    Extracts UTF-8 strings from a buffer.
    """

    # Reference: https://en.wikipedia.org/wiki/UTF-8

    character_info = namedtuple("character_info", ["character", "position", "length"])
    character_and_index = []

    for i in range(0, len(buf)):
        # for 1 byte
        if buf[i] & 0x80 == 0x00:
            # ignore is used below because decode function throws an exception
            # when there is an character where the if condition is satisfied but it is not a valid utf-8 character
            character = buf[i].to_bytes(1, "big").decode("utf-8", "ignore")
            character_and_index.append(character_info(character, i, 1))

        # for 2 bytes
        elif buf[i] & 0xE0 == 0xC0:
            temp = buf[i] << 8 | buf[i + 1]
            character = temp.to_bytes(2, "big").decode("utf-8", "ignore")
            i += 1
            character_and_index.append(character_info(character, i, 2))

        # for 3 bytes
        elif buf[i] & 0xF0 == 0xE0:
            temp = buf[i] << 16 | buf[i + 1] << 8 | buf[i + 2]
            character = temp.to_bytes(3, "big").decode("utf-8", "ignore")
            i += 2
            character_and_index.append(character_info(character, i, 3))

        # for 4 bytes
        elif buf[i] & 0xF8 == 0xF0:
            temp = buf[i] << 24 | buf[i + 1] << 16 | buf[i + 2] << 8 | buf[i + 3]
            character = temp.to_bytes(4, "big").decode("utf-8", "ignore")
            i += 3
            character_and_index.append(character_info(character, i, 4))

        else:
            logger.trace("Invalid UTF-8 character at offset %d", i)

    prev = False
    strings = []

    for i in range(0, len(character_and_index)):
        if character_and_index[i].character.isprintable():
            if prev == False:
                strings.append(
                    [character_and_index[i].character, character_and_index[i].position, character_and_index[i].position]
                )
                prev = True
            else:
                strings[-1][0] += character_and_index[i].character
                strings[-1][2] = character_and_index[i].position
        else:
            prev = False

    # filter strings less than min length
    strings = [string for string in strings if len(string[0]) >= min_length]

    return strings


def extract_rdata_utf8_strings(pe: pefile.PE, min_length=MIN_STR_LEN) -> List[List[Tuple[str, int, int]]]:
    """
    Extracts UTF-8 strings from the .rdata section of a PE file.
    """
    try:
        rdata_section = get_rdata_section(pe)
    except ValueError as e:
        logger.error("cannot extract rust strings: %s", e)
        return []

    buf = pe.get_memory_mapped_image()[
        rdata_section.VirtualAddress : rdata_section.VirtualAddress + rdata_section.SizeOfRawData
    ]
    strings = extract_utf8_strings_from_buffer(buf, min_length)
    return strings


def extract_utf8_strings(pe: pefile.PE, min_length=MIN_STR_LEN) -> List[List[Tuple[str, int, int]]]:
    """
    Extracts UTF-8 strings from a PE file.
    """
    # Can be extended to extract strings from other sections
    return extract_rdata_utf8_strings(pe, min_length)


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

    pe = pathlib.Path(args.path)
    buf = pe.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    strings = extract_utf8_strings(pe, args.min_length)
    print(strings)
    for string in strings:
        print(string[0])


if __name__ == "__main__":
    sys.exit(main())

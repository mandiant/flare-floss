# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
import sys
import logging
import pathlib
import argparse

import pefile

MIN_STR_LEN = 4

logger = logging.getLogger(__name__)


def get_rdata_section(pe: pefile.PE) -> pefile.SectionStructure:
    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            return section

    raise ValueError("no .rdata section found")


def extract_utf8_strings(pe: pefile.PE, min_length=MIN_STR_LEN):
    """
    Extracts UTF-8 strings from the .rdata section of a PE file.
    """
    try:
        rdata_section = get_rdata_section(pe)
    except ValueError as e:
        print("cannot extract rust strings: %s", e)
        return []

    strings = rdata_section.get_data()

    character_and_index = []

    # Reference: https://en.wikipedia.org/wiki/UTF-8

    for i in range(0, len(strings)):
        # for 1 byte
        if strings[i] & 0x80 == 0x00:
            character = strings[i].to_bytes(1, "big").decode("utf-8", "ignore")
            character_and_index.append([character, i, 1])

        # for 2 bytes
        elif strings[i] & 0xE0 == 0xC0:
            temp = strings[i] << 8 | strings[i + 1]
            character = temp.to_bytes(2, "big").decode("utf-8", "ignore")
            i += 1
            character_and_index.append([character, i, 2])

        # for 3 bytes
        elif strings[i] & 0xF0 == 0xE0:
            temp = strings[i] << 16 | strings[i + 1] << 8 | strings[i + 2]
            character = temp.to_bytes(3, "big").decode("utf-8", "ignore")
            i += 2
            character_and_index.append([character, i, 3])

        # for 4 bytes
        elif strings[i] & 0xF8 == 0xF0:
            temp = strings[i] << 24 | strings[i + 1] << 16 | strings[i + 2] << 8 | strings[i + 3]
            character = temp.to_bytes(4, "big").decode("utf-8", "ignore")
            i += 3
            character_and_index.append([character, i, 4])

    strings = []  # string, start index, end index

    # check for consecutive characters and convert to string
    for i in range(0, len(character_and_index)):
        if i == 0:
            strings.append([character_and_index[i][0], character_and_index[i][1], character_and_index[i][1]])
        else:
            if (
                character_and_index[i - 1][1] + character_and_index[i - 1][2] == character_and_index[i][1]
                and character_and_index[i][0].isprintable() == True
            ):
                strings[-1][0] += character_and_index[i][0]
                strings[-1][2] = character_and_index[i][1]
            else:
                if character_and_index[i][0].isprintable() == True:
                    strings.append([character_and_index[i][0], character_and_index[i][1], character_and_index[i][1]])

    # filter strings less than min length
    strings = [string for string in strings if len(string[0]) >= min_length]

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

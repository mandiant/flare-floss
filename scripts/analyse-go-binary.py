# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import sys
import logging
import argparse

from floss.main import get_static_strings
from floss.language.go.extract import extract_go_strings

logger = logging.getLogger(__name__)


MIN_STR_LEN = 6


def main(argv=None):
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
    args = parser.parse_args(args=argv)

    static_strings = extract_go_strings(args.path, min_length=args.min_length)
    all_static_strings = get_static_strings(args.path, args.min_length)

    extracted_static_strings = []
    extracted_static_strings_count = 0

    for strings_obj in static_strings:
        string = strings_obj.string
        extracted_static_strings.append(string)
        extracted_static_strings_count += 1

    all_static_string_list = []

    for string_obj in all_static_strings:
        if string_obj.string.isprintable():
            all_static_string_list.append(string_obj.string)

    for string in all_static_string_list:
        if string not in extracted_static_strings:
            print(string)

    print("Total number of strings extracted via strings.exe: ", len(all_static_string_list))

    print(
        "Percentage of strings extracted: ",
        format((extracted_static_strings_count * 100 / len(all_static_string_list)), ".2f"),
    )

    print("Number of strings extracted: ", extracted_static_strings_count)


if __name__ == "__main__":
    sys.exit(main())

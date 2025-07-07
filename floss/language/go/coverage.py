# Copyright 2023 Google LLC
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
from typing import List

import pefile

from floss.utils import get_static_strings
from floss.results import StaticString, StringEncoding
from floss.language.utils import get_extract_stats
from floss.language.go.extract import extract_go_strings

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

    static_strings: List[StaticString] = get_static_strings(path, args.min_length)

    go_strings = extract_go_strings(path, args.min_length)

    # The value 2800 was chosen based on experimentaion on different samples
    # of go binaries that include versions 1.20, 1.18, 1.16, 1.12. and
    # architectures amd64 and i386.
    # See: https://github.com/mandiant/flare-floss/issues/807#issuecomment-1636087673
    get_extract_stats(pe, static_strings, go_strings, args.min_length, 2800)


if __name__ == "__main__":
    sys.exit(main())

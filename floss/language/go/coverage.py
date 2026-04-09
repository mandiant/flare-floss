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

from floss.utils import get_static_strings
from floss.results import StaticString, StringEncoding
from floss.language.utils import get_extract_stats
from floss.language.cli_common import add_common_args, open_pe_or_none, configure_logging
from floss.language.go.extract import extract_go_strings

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4


def main():
    parser = argparse.ArgumentParser(description="Get Go strings")
    add_common_args(parser, MIN_STR_LEN)
    args = parser.parse_args()

    configure_logging(args)

    pe = open_pe_or_none(args.path)
    if pe is None:
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

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
from typing import List, Tuple, Iterable, Optional

import pefile

from floss.strings import extract_ascii_unicode_strings
from floss.language.utils import get_extract_stats
from floss.language.cli_common import add_common_args, open_pe_or_none, configure_logging
from floss.language.rust.extract import extract_rust_strings

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4


def main():
    parser = argparse.ArgumentParser(description="Get Rust strings")
    add_common_args(parser, MIN_STR_LEN)
    args = parser.parse_args()

    configure_logging(args)

    pe = open_pe_or_none(args.path)
    if pe is None:
        return 1

    path = pathlib.Path(args.path)

    # see only .rdata section
    buf = path.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    static_strings = list(extract_ascii_unicode_strings(buf, args.min_length))

    rust_strings = extract_rust_strings(path, args.min_length)

    # The min_blob_length value was chosen as 0 because in rust binaries, the
    # string blobs are small and the min_blob_length value is not needed.
    get_extract_stats(pe, static_strings, rust_strings, args.min_length, 0)


if __name__ == "__main__":
    sys.exit(main())

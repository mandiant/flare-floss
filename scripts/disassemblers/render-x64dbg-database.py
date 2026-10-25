#!/usr/bin/env python3
# Copyright 2021 Google LLC
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


"""
render-x64dbg-database.py

Translate a floss result document into an x64dbg database.

Usage:

  $ floss suspicious.exe -j > floss-results.json
  $ python render-x64dbg-database.py floss-results.json > database.json
  # open `database.json` in x64dbg
"""

import sys
import json
import logging
import argparse
import dataclasses
from typing import Dict, List
from pathlib import Path
from dataclasses import field

from pydantic.dataclasses import dataclass

try:
    from va_map import load_and_resolve_static_strings  # type: ignore[import-not-found]
except ModuleNotFoundError as e:
    if e.name != "va_map":
        raise
    from scripts.disassemblers.va_map import load_and_resolve_static_strings

from floss.results import AddressType, ResultDocument

logger = logging.getLogger("floss.render-x64dbg-import-script")


@dataclass
class Comment:
    text: str
    manual: bool
    module: str
    address: str


@dataclass
class Export:
    comments: List[Comment] = field(default_factory=list)


def render_x64dbg_database(result_document: ResultDocument, sample_override=None) -> str:
    """
    Create x64dbg database/json file contents for file annotations.
    """
    export = Export()
    module = Path(result_document.metadata.file_path).name
    processed: Dict[str, str] = {}

    def add_comment(rva: int, text: str) -> None:
        address = hex(rva)
        if address in processed:
            processed[address] += "\t" + text
        else:
            processed[address] = "FLOSS: " + text

    for ds in result_document.strings.decoded_strings:
        if ds.string != "":
            if ds.address_type == AddressType.GLOBAL:
                add_comment(ds.address - result_document.metadata.imagebase, ds.string)
            else:
                add_comment(ds.decoded_at - result_document.metadata.imagebase, ds.string)

    mapped_static_strings, unmapped = load_and_resolve_static_strings(result_document, sample_override)
    for static_string in mapped_static_strings:
        add_comment(static_string.rva, static_string.string)

    if unmapped:
        logger.warning(
            "%d static and language strings could not be translated to VAs, and are not imported",
            unmapped,
        )

    for i in list(processed.keys()):
        comment = Comment(text=processed[i], manual=False, module=module, address=i)
        export.comments.append(comment)

    return json.dumps(dataclasses.asdict(export), indent=1)


def main():
    parser = argparse.ArgumentParser(description="Generate an x64dbg script to apply FLOSS results.")
    parser.add_argument("/path/to/report.json", help="path to JSON document from `floss --json`")
    parser.add_argument(
        "--sample",
        metavar="PATH",
        default=None,
        help="path to the analyzed sample if it is not available at the path recorded in the result document",
    )

    logging_group = parser.add_argument_group("logging arguments")

    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
    )

    args = parser.parse_args()
    args.report_path = getattr(args, "/path/to/report.json")

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    result_document = ResultDocument.parse_file(Path(args.report_path))

    print(render_x64dbg_database(result_document, args.sample))
    return 0


if __name__ == "__main__":
    sys.exit(main())

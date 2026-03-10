# Copyright 2024 Google LLC
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

import logging
import argparse
from typing import Optional

import pefile

logger = logging.getLogger(__name__)


def add_common_argparse_options(parser: argparse.ArgumentParser, min_str_len: int = 4):
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=min_str_len,
        help="minimum string length",
    )
    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument(
        "-d", "--debug", action="store_true", help="enable debugging output on STDERR"
    )
    logging_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="disable all status output except fatal errors",
    )


def configure_logging(args: argparse.Namespace):
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)


def open_and_validate_pe(path: str) -> Optional[pefile.PE]:
    try:
        pe = pefile.PE(path)
        return pe
    except pefile.PEFormatError as err:
        logger.debug(f"NOT a valid PE file: {err}")
        return None

# Copyright 2026 Google LLC
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

import os
import sys
import logging
import pathlib
import argparse

from floss.tags.gp import StringGlobalPrevalence, StringGlobalPrevalenceDatabase

logger = logging.getLogger(__name__)


def load_db_gp():
    gpfile = os.path.join(os.path.dirname(__file__), "..", "db", "data", "gp", "gp.jsonl.gz")
    compress = gpfile.endswith(".gz")
    return StringGlobalPrevalenceDatabase.from_file(pathlib.Path(gpfile), compress=compress)


def query_string(string) -> StringGlobalPrevalence:
    gpdb = load_db_gp()
    return gpdb.query(string)


def main():
    parser = argparse.ArgumentParser(description="Query string databases.")
    parser.add_argument("string", help="string to query for")

    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
    )
    args = parser.parse_args()

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    result = query_string(args.string)
    print(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())

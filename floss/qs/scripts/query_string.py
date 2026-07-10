# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
import os
import sys
import logging
import pathlib
import argparse

from floss.qs.db.gp import StringGlobalPrevalence, StringGlobalPrevalenceDatabase

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

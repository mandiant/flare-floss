# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

# examples:
# $ generate_gp_db.py cwinpes cwindb-native.jsonl.gz --type native
# scanned 24,212 files with 43,918,395 strings
# final db contains 3,631 strings (more than 500 occurrences)
#
# $ generate_gp_db.py cwinpes cwindb-dotnet.jsonl.gz --type dotnet
# scanned 24,212 files with 24,767,670 strings
# final db contains 1,683 strings (more than 500 occurrences)

import os
import sys
import json
import logging
import argparse
import collections
from typing import Dict, Tuple

from floss.qs.db.gp import Encoding, Location, StringGlobalPrevalence, StringGlobalPrevalenceDatabase
from floss.qs.scripts.extract_strings import PeStrings

MIN_COUNT = 500


logger = logging.getLogger(__name__)


def generate_gp_db(path: str, min_count: int, type_: str) -> "StringGlobalPrevalenceDatabase":
    if not os.path.exists(path):
        raise IOError(f"path {path} does not exist or cannot be accessed")
    if not os.path.isdir(path):
        raise IOError(f"path {path} is not a directory")

    db: Dict[Tuple[str, Encoding, Location], int] = collections.defaultdict(int)
    seen_hashes = set()
    nfiles = 0
    nstrings = 0
    for root, dirs, files in os.walk(path):
        for file in files:
            nfiles += 1
            file_path = os.path.join(root, file)
            logger.debug("found file: %s", os.path.abspath(os.path.normpath(file_path)))

            with open(file_path, "r", encoding="utf-8") as f:
                d = json.load(f)
                pestrings = PeStrings(**d)

                dotnative = "dotnet" if pestrings.dotnet else "native"
                if type_ != "all" and dotnative != type_:
                    logger.debug("skipping unwanted type %s: %s", dotnative, file_path)
                    continue

                if pestrings.sha256 in seen_hashes:
                    logger.debug("skipping already indexed file with sha256 hash %s: %s", pestrings.sha256, file_path)
                seen_hashes.add(pestrings.sha256)

                nstrings += len(pestrings.strings)
                for s in pestrings.strings:
                    db[(s.string, s.encoding, s.location)] += 1

    print(f"scanned {nfiles:,} files with {nstrings:,} strings")

    gpdb = StringGlobalPrevalenceDatabase.new_db()
    for (string, encoding, location), n in db.items():
        if n < min_count:
            continue
        gpdb.insert(StringGlobalPrevalence(string, encoding, n, location))

    print(f"final db contains {len(gpdb):,} strings (more than {MIN_COUNT} occurrences)")
    return gpdb


def main():
    parser = argparse.ArgumentParser(description="Generate global prevalence database from raw files.")
    parser.add_argument("path", help="path containing extracted string data")
    parser.add_argument("outfile", help="file to store results to")
    parser.add_argument(
        "--type", choices=("dotnet", "native", "all"), default="all", help="include strings from dotnet, native or all"
    )
    parser.add_argument("--min-count", type=int, default=MIN_COUNT, help="minimum count string needs to occur")

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

    if os.path.exists(args.outfile):
        logger.error("%s already exists", args.outfile)
        use = input("overwrite existing file? y/[n] ")
        if use != "y":
            return -1

    gp = generate_gp_db(args.path, args.min_count, args.type)

    compress = args.outfile.endswith(".gz")
    gp.to_file(args.outfile, compress=compress)

    return 0


if __name__ == "__main__":
    sys.exit(main())

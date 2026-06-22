# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

# examples:
# $ generate_gp_db.py ./extracted/ zaa-hashes.bin --output-format hash --type native
# $ generate_gp_db.py ./extracted/ cwindb-native.jsonl.gz --output-format jsonl --type native

import os
import sys
import json
import pickle
import hashlib
import logging
import pathlib
import argparse
import collections
from typing import Dict, Set, Tuple

from floss.qs.db.gp import (
    Encoding,
    Location,
    StringGlobalPrevalence,
    StringGlobalPrevalenceDatabase,
    StringHashDatabase,
)
from floss.qs.scripts.extract_strings import FileString, PeStrings

MIN_COUNT = 500

logger = logging.getLogger(__name__)


def _load_pestrings(file_path: str) -> PeStrings:
    with open(file_path, "r", encoding="utf-8") as f:
        d = json.load(f)
    # backward compat: imphash field may be absent in older extraction JSONs
    d.setdefault("imphash", None)
    # json.load returns dicts for nested objects; reconstruct FileString instances
    strings = [FileString(**s) for s in d.pop("strings", [])]
    return PeStrings(**d, strings=strings)


def generate_gp_db(
    path: str,
    min_count: int,
    type_: str,
    output_format: str,
    checkpoint_path: pathlib.Path,
) -> "StringGlobalPrevalenceDatabase | StringHashDatabase":
    if not os.path.exists(path):
        raise IOError(f"path {path} does not exist or cannot be accessed")
    if not os.path.isdir(path):
        raise IOError(f"path {path} is not a directory")

    # db maps (string, encoding, location) -> count of distinct imphash groups
    # seen_imphashes: imphash groups already counted (one representative per group)
    # seen_sha256s: sha256 dedup across files
    db: Dict[Tuple[str, Encoding, Location], int]
    seen_imphashes: Set[str]
    seen_sha256s: Set[str]
    nfiles: int

    if checkpoint_path.exists():
        logger.info("resuming from checkpoint %s", checkpoint_path)
        with open(checkpoint_path, "rb") as f:
            state = pickle.load(f)
        db = state["db"]
        seen_imphashes = state["seen_imphashes"]
        seen_sha256s = state["seen_sha256s"]
        nfiles = state["nfiles"]
        logger.info("checkpoint: %d files, %d imphash groups, %d strings", nfiles, len(seen_imphashes), len(db))
    else:
        db = collections.defaultdict(int)
        seen_imphashes = set()
        seen_sha256s = set()
        nfiles = 0

    nstrings = 0
    ntype_skipped = 0
    checkpoint_interval = 10_000

    for root, dirs, files in os.walk(path):
        for filename in files:
            if not filename.endswith(".json"):
                continue

            file_path = os.path.join(root, filename)

            try:
                pestrings = _load_pestrings(file_path)
            except Exception as e:
                logger.warning("failed to load %s: %s", file_path, e)
                continue

            dotnative = "dotnet" if pestrings.dotnet else "native"
            if type_ != "all" and dotnative != type_:
                ntype_skipped += 1
                continue

            if pestrings.sha256 in seen_sha256s:
                logger.debug("skipping duplicate sha256 %s", pestrings.sha256)
                continue
            seen_sha256s.add(pestrings.sha256)

            # use imphash as the group key; fall back to sha256 for files with no imports
            group_key = pestrings.imphash or pestrings.sha256
            if group_key in seen_imphashes:
                logger.debug("skipping already-counted imphash group %s", group_key)
                nfiles += 1
                continue
            seen_imphashes.add(group_key)

            nfiles += 1
            nstrings += len(pestrings.strings)
            for s in pestrings.strings:
                db[(s.string, s.encoding, s.location)] += 1

            if nfiles % checkpoint_interval == 0:
                logger.info("checkpoint: %d files processed, %d imphash groups, %d unique strings", nfiles, len(seen_imphashes), len(db))
                _write_checkpoint(checkpoint_path, db, seen_imphashes, seen_sha256s, nfiles)

    logger.info(
        "scanned %d files (%d type-skipped), %d imphash groups, %d strings, %d unique (string, encoding, location) tuples",
        nfiles, ntype_skipped, len(seen_imphashes), nstrings, len(db),
    )

    if output_format == "hash":
        string_hashes: Set[bytes] = set()
        nabove = 0
        for (string, _encoding, _location), count in db.items():
            if count >= min_count:
                nabove += 1
                m = hashlib.md5()
                m.update(string.encode("utf-8"))
                string_hashes.add(m.digest()[:8])
        logger.info("hash db: %d strings above min_count=%d", nabove, min_count)
        return StringHashDatabase(string_hashes=string_hashes)
    else:
        gpdb = StringGlobalPrevalenceDatabase.new_db()
        for (string, encoding, location), count in db.items():
            if count < min_count:
                continue
            gpdb.insert(StringGlobalPrevalence(
                string=string,
                encoding=encoding,
                global_count=count,
                location=location,
            ))
        logger.info("jsonl db: %d strings above min_count=%d", len(gpdb), min_count)
        return gpdb


def _write_checkpoint(checkpoint_path, db, seen_imphashes, seen_sha256s, nfiles):
    tmp = pathlib.Path(str(checkpoint_path) + ".tmp")
    with open(tmp, "wb") as f:
        pickle.dump({
            "db": db,
            "seen_imphashes": seen_imphashes,
            "seen_sha256s": seen_sha256s,
            "nfiles": nfiles,
        }, f)
    tmp.replace(checkpoint_path)
    logger.debug("wrote checkpoint %s", checkpoint_path)


def main():
    parser = argparse.ArgumentParser(description="Generate global prevalence database from extracted string data.")
    parser.add_argument("path", help="directory containing extracted string JSONs")
    parser.add_argument("outfile", help="output file (.jsonl.gz for jsonl, .bin for hash)")
    parser.add_argument(
        "--output-format",
        choices=("jsonl", "hash"),
        default="hash",
        help="output format: hash (.bin, compact, no metadata) or jsonl (.jsonl.gz, with counts)",
    )
    parser.add_argument(
        "--type",
        choices=("dotnet", "native", "all"),
        default="all",
        help="include strings from dotnet, native or all",
    )
    parser.add_argument("--min-count", type=int, default=MIN_COUNT, help="minimum imphash-group count")
    parser.add_argument("--no-resume", action="store_true", help="ignore any existing checkpoint and start fresh")

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

    checkpoint_path = pathlib.Path(args.outfile + ".ckpt.pkl")
    if args.no_resume and checkpoint_path.exists():
        checkpoint_path.unlink()
        logger.info("removed existing checkpoint")

    if os.path.exists(args.outfile):
        logger.warning("%s already exists", args.outfile)
        use = input("overwrite existing file? y/[n] ")
        if use != "y":
            return -1

    result = generate_gp_db(args.path, args.min_count, args.type, args.output_format, checkpoint_path)

    if args.output_format == "hash":
        assert isinstance(result, StringHashDatabase)
        result.to_file(pathlib.Path(args.outfile))
    else:
        assert isinstance(result, StringGlobalPrevalenceDatabase)
        compress = args.outfile.endswith(".gz")
        result.to_file(args.outfile, compress=compress)

    if checkpoint_path.exists():
        checkpoint_path.unlink()
        logger.debug("removed checkpoint after successful completion")

    return 0


if __name__ == "__main__":
    sys.exit(main())

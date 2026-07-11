# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Layout-aware static string analysis entrypoints."""

from __future__ import annotations

import io
import sys
import hashlib
import logging
import pathlib
import argparse
import datetime

import colorama
import rich.traceback
from rich.console import Console

import floss.main
from floss.tags import TagRules, load_databases, hide_strings_by_rules, remove_false_positive_lib_strings
from floss.layout import MIN_STR_LEN, compute_layout, extract_layout_strings
from floss.ranges import Slice
from floss.document import Sample, Metadata, ResultDocument
from floss.render.layout_text import render_strings

logger = logging.getLogger("floss.analyze_static")

VERSION = "0.3.0"


def analyze_path(path: pathlib.Path, min_length: int = MIN_STR_LEN) -> ResultDocument:
    with path.open("rb") as f:
        buf = f.read()

    md5 = hashlib.md5(buf).hexdigest()
    sha1 = hashlib.sha1(buf).hexdigest()
    sha256 = hashlib.sha256(buf).hexdigest()

    file_slice = Slice.from_bytes(buf=buf)
    layout = compute_layout(file_slice)
    extract_layout_strings(layout, min_length)
    taggers = load_databases()
    layout.tag_strings(taggers)
    layout.mark_structures()
    remove_false_positive_lib_strings(layout)

    sample = Sample(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        path=str(path.resolve()),
    )
    meta = Metadata(
        version=VERSION,
        timestamp=datetime.datetime.now(),
        sample=sample,
        min_str_len=min_length,
    )
    return ResultDocument.from_qs(meta, layout)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract human readable strings from binary data with layout and tags."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
        help="show program's version number and exit",
    )
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length",
    )
    parser.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("-l", "--load", action="store_true", help="load from existing results document")
    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="disable all status output except fatal errors",
    )
    args = parser.parse_args(argv)

    floss.main.set_log_config(args.debug, args.quiet)
    rich.traceback.install()
    if isinstance(sys.stdout, io.TextIOWrapper) or hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    colorama.just_fix_windows_console()

    path = pathlib.Path(args.path)
    if not path.exists():
        logging.error("%s does not exist", path)
        return 1

    if args.load:
        with path.open("r") as f:
            results = ResultDocument.model_validate_json(f.read())
    else:
        results = analyze_path(path, args.min_length)

    if args.json:
        print(results.model_dump_json(indent=0))
    else:
        tag_rules: TagRules = {
            "#capa": "highlight",
            "#common": "mute",
            "#duplicate": "mute",
            "#code": "hide",
            "#reloc": "hide",
        }
        hide_strings_by_rules(results.layout, tag_rules)
        console = Console()
        render_strings(console, results.layout, tag_rules)

    return 0


if __name__ == "__main__":
    sys.exit(main())

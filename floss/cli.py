# Copyright 2017 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""CLI argument parsing for FLOSS."""

from __future__ import annotations

import sys
import logging
import argparse
import textwrap
from enum import Enum
from typing import List, Optional
from pathlib import Path

import floss.logging_
from floss.const import (
    MEGABYTE,
    MAX_FILE_SIZE,
    MIN_STRING_LENGTH,
)
from floss.version import __version__
from floss.render import Verbosity
from floss.logging_ import TRACE, DebugLevel
from floss.language.identify import Language
from floss.utils import set_vivisect_log_level

logger = floss.logging_.getLogger("floss")

SIGNATURES_PATH_DEFAULT_STRING = "(embedded signatures)"


EXTENSIONS_SHELLCODE_32 = ("sc32", "raw32")
EXTENSIONS_SHELLCODE_64 = ("sc64", "raw64")


class StringType(str, Enum):
    STATIC = "static"
    STACK = "stack"
    TIGHT = "tight"
    DECODED = "decoded"


class WorkspaceLoadError(ValueError):
    pass


class ArgumentValueError(ValueError):
    pass


class ArgumentParser(argparse.ArgumentParser):
    """
    argparse will call sys.exit upon parsing invalid arguments.
    we don't want that, because we might be parsing args within test cases, run as a module, etc.
    so, we override the behavior to raise a ArgumentValueError instead.

    this strategy is originally described here: https://stackoverflow.com/a/16942165/87207
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        args = {"prog": self.prog, "message": message}
        raise ArgumentValueError("%(prog)s: error: %(message)s" % args)


def make_parser(argv):
    desc = (
        "The FLARE team's open-source tool to extract ALL strings from malware.\n"
        f"  %(prog)s {__version__} - https://github.com/mandiant/flare-floss/\n\n"
        "FLOSS extracts the following string types:\n"
        ' 1. static strings:  "regular" ASCII and UTF-16LE strings\n'
        " 2. stack strings:   strings constructed on the stack at run-time\n"
        " 3. tight strings:   special form of stack strings, decoded on the stack\n"
        " 4. decoded strings: strings decoded in a function\n\n"
        "Language-specific strings:\n"
        " 1. Go:   strings from binaries written in Go\n"
        " 2. Rust: strings from binaries written in Rust\n"
    )
    epilog = textwrap.dedent("""
        only displaying core arguments, run `floss -H` to see all supported options

        examples:
          extract all strings from an executable
            floss suspicious.exe

          do not extract static strings
            floss --no static -- suspicious.exe

          only extract stack and tight strings
            floss --only stack tight -- suspicious.exe
        """)
    epilog_advanced = textwrap.dedent("""
        examples:
          extract all strings from 32-bit shellcode
            floss -f sc32 shellcode.bin

          only decode strings from the specified functions
            floss --functions 0x401000 0x401100 suspicious.exe
        
          extract strings from a binary written in Go (if automatic language identification fails)
            floss --language go program.exe
        """)

    show_all_options = "-H" in argv

    parser = ArgumentParser(
        description=desc,
        epilog=epilog_advanced if show_all_options else epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-H", action="help", help="show advanced options and exit")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STRING_LENGTH,
        help="minimum string length",
    )

    parser.add_argument(
        "sample",
        type=argparse.FileType("rb"),
        help="path to sample to analyze",
    )

    analysis_group = parser.add_argument_group("analysis arguments")
    analysis_group.add_argument(
        "--no",
        action="extend",
        dest="disabled_types",
        nargs="+",
        choices=[t.value for t in StringType],
        default=[],
        help="do not extract specified string type(s)",
    )
    analysis_group.add_argument(
        "--only",
        action="extend",
        dest="enabled_types",
        nargs="+",
        choices=[t.value for t in StringType],
        default=[],
        help="only extract specified string type(s)",
    )

    advanced_group = parser.add_argument_group("advanced arguments")
    formats = [
        ("auto", "(default) detect file type automatically"),
        ("pe", "Windows PE file"),
        ("sc32", "32-bit shellcode"),
        ("sc64", "64-bit shellcode"),
    ]
    format_help = ", ".join(["%s: %s" % (f[0], f[1]) for f in formats])
    advanced_group.add_argument(
        "-f",
        "--format",
        choices=[f[0] for f in formats],
        default="auto",
        help="select sample format, %s" % format_help if show_all_options else argparse.SUPPRESS,
    )
    advanced_group.add_argument(
        "--language",
        type=str,
        choices=[l.value for l in Language if l != Language.UNKNOWN],
        default=Language.UNKNOWN.value,
        help=(
            "use language-specific string extraction, auto-detect language by default, disable using 'none'"
            if show_all_options
            else argparse.SUPPRESS
        ),
    )
    advanced_group.add_argument(
        "-l",
        "--load",
        action="store_true",
        help="load from existing FLOSS results document" if show_all_options else argparse.SUPPRESS,
    )
    advanced_group.add_argument(
        "--functions",
        type=lambda x: int(x, 0x10),
        default=None,
        nargs="+",
        help=(
            "only analyze the specified functions, hex-encoded like 0x401000, space-separate multiple functions"
            if show_all_options
            else argparse.SUPPRESS
        ),
    )
    advanced_group.add_argument(
        "--disable-progress",
        action="store_true",
        help="disable all progress bars" if show_all_options else argparse.SUPPRESS,
    )
    advanced_group.add_argument(
        "--signatures",
        type=str,
        default=SIGNATURES_PATH_DEFAULT_STRING,
        help=(
            "path to .sig/.pat file or directory used to identify library functions, use embedded signatures by default"
            if show_all_options
            else argparse.SUPPRESS
        ),
    )
    advanced_group.add_argument(
        "-L",
        "--large-file",
        action="store_true",
        help=(
            "allow processing files larger than {} MB".format(int(MAX_FILE_SIZE / MEGABYTE))
            if show_all_options
            else argparse.SUPPRESS
        ),
    )
    advanced_group.add_argument(
        "--version",
        action="version",
        version="%(prog)s {:s}".format(__version__),
        help="show program's version number and exit" if show_all_options else argparse.SUPPRESS,
    )
    if sys.platform == "win32":
        advanced_group.add_argument(
            "--install-right-click-menu",
            action=floss.utils.InstallContextMenu,
            help=(
                "install FLOSS to the right-click context menu for Windows Explorer and exit"
                if show_all_options
                else argparse.SUPPRESS
            ),
        )

        advanced_group.add_argument(
            "--uninstall-right-click-menu",
            action=floss.utils.UninstallContextMenu,
            help=(
                "uninstall FLOSS from the right-click context menu for Windows Explorer and exit"
                if show_all_options
                else argparse.SUPPRESS
            ),
        )

    output_group = parser.add_argument_group("rendering arguments")
    output_group.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    output_group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=Verbosity.DEFAULT,
        help="enable verbose results, e.g. including function offsets (does not affect JSON output)",
    )

    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument(
        "-d",
        "--debug",
        action="count",
        default=DebugLevel.NONE,
        help="enable debugging output on STDERR, specify multiple times to increase verbosity",
    )
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output on STDOUT except fatal errors"
    )
    logging_group.add_argument(
        "--color",
        type=str,
        choices=("auto", "always", "never"),
        default="auto",
        help="enable ANSI color codes in results, default: only during interactive session",
    )

    return parser

def set_log_config(debug, quiet):
    if quiet:
        log_level = logging.WARNING
    elif debug >= DebugLevel.TRACE:
        log_level = TRACE
    elif debug >= DebugLevel.DEFAULT:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    if debug < DebugLevel.SUPERTRACE:
        # these loggers are too verbose even for the TRACE level, enable via `-ddd`
        logging.getLogger("floss.api_hooks").setLevel(logging.WARNING)
        logging.getLogger("floss.function_argument_getter").setLevel(logging.WARNING)

    # configure vivisect-related logging, it's verbose and not relevant for regular FLOSS users
    # enable to do more vigorous testing
    if debug < DebugLevel.TRACE:
        set_vivisect_log_level(logging.CRITICAL)
    else:
        set_vivisect_log_level(logging.DEBUG)

    # configure viv-utils logging
    if debug == DebugLevel.DEFAULT:
        logging.getLogger("viv_utils.emulator_drivers").setLevel(logging.DEBUG)
    elif debug <= DebugLevel.TRACE:
        logging.getLogger("viv_utils.emulator_drivers").setLevel(logging.ERROR)

    # install the log message colorizer to the default handler.
    # because basicConfig is just above this,
    # handlers[0] is a StreamHandler to STDERR.
    #
    # calling this code from outside script main may do something unexpected.
    logging.getLogger().handlers[0].setFormatter(floss.logging_.ColorFormatter())


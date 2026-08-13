# Copyright 2017 Google LLC
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

"""CLI argument parsing for FLOSS."""

from __future__ import annotations

import sys
import logging
import argparse
import textwrap
from enum import Enum
from typing import List, Optional
from pathlib import Path

import floss.utils
import floss.logging_
from floss.const import (
    MEGABYTE,
    MAX_FILE_SIZE,
    MIN_STRING_LENGTH,
)
from floss.utils import set_vivisect_log_level
from floss.render import Verbosity
from floss.version import __version__
from floss.logging_ import TRACE, DebugLevel
from floss.language.identify import Language

logger = floss.logging_.getLogger("floss")

SIGNATURES_PATH_DEFAULT_STRING = "(embedded signatures)"


EXTENSIONS_SHELLCODE_32 = ("sc32", "raw32")
EXTENSIONS_SHELLCODE_64 = ("sc64", "raw64")


class StringType(str, Enum):
    STATIC = "static"
    STACK = "stack"
    TIGHT = "tight"
    DECODED = "decoded"


# string types selectable via --string-type / --no-string-type
STRING_TYPE_CHOICES = [t.value for t in StringType]


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


def make_parser():
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
        " 2. Rust: strings from binaries written in Rust\n\n"
        "By default, static strings are layout-aware with tags for PE/ELF/Mach-O\n"
        "(section context, prevalence/library/expert tags).\n"
    )
    epilog = textwrap.dedent("""
        examples:
          extract all strings from an executable
            floss suspicious.exe

          classic flat list of strings without layout and tags
            floss --plain suspicious.exe

          do not extract static strings
            floss --no-string-type static -- suspicious.exe

          only extract stack and tight strings
            floss --string-type stack tight -- suspicious.exe

          extract strings from 32-bit shellcode
            floss -f sc32 shellcode.bin

          only decode strings from the specified functions
            floss --analyze-functions 0x401000 0x401100 -- suspicious.exe

          extract strings from a binary written in Go (if automatic language identification fails)
            floss --language go program.exe
        """)

    parser = ArgumentParser(
        description=desc,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
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
        "--string-type",
        action="extend",
        dest="enabled_string_types",
        nargs="+",
        choices=STRING_TYPE_CHOICES,
        default=[],
        help="only extract specified string type(s); valid values: %s" % ", ".join(STRING_TYPE_CHOICES),
    )
    analysis_group.add_argument(
        "--no-string-type",
        action="extend",
        dest="disabled_string_types",
        nargs="+",
        choices=STRING_TYPE_CHOICES,
        default=[],
        help="do not extract specified string type(s); valid values: %s" % ", ".join(STRING_TYPE_CHOICES),
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
        help="select sample format, %s" % format_help,
    )
    advanced_group.add_argument(
        "--language",
        type=str,
        choices=[l.value for l in Language if l != Language.UNKNOWN],
        default=Language.UNKNOWN.value,
        help="use language-specific string extraction, auto-detect language by default, disable using 'none'",
    )
    advanced_group.add_argument(
        "--analyze-functions",
        dest="functions",
        type=lambda x: int(x, 0x10),
        default=None,
        nargs="+",
        help="only analyze the specified functions, hex-encoded like 0x401000, space-separate multiple functions",
    )
    advanced_group.add_argument(
        "--signatures",
        type=str,
        default=SIGNATURES_PATH_DEFAULT_STRING,
        help="path to .sig/.pat file or directory used to identify library functions, use embedded signatures by default",
    )
    advanced_group.add_argument(
        "-L",
        "--large-file",
        action="store_true",
        help="allow processing files larger than {} MB".format(int(MAX_FILE_SIZE / MEGABYTE)),
    )
    advanced_group.add_argument(
        "--version",
        action="version",
        version="%(prog)s {:s}".format(__version__),
        help="show program's version number and exit",
    )
    if sys.platform == "win32":
        advanced_group.add_argument(
            "--install-right-click-menu",
            action=floss.utils.InstallContextMenu,
            help="install FLOSS to the right-click context menu for Windows Explorer and exit",
        )

        advanced_group.add_argument(
            "--uninstall-right-click-menu",
            action=floss.utils.UninstallContextMenu,
            help="uninstall FLOSS from the right-click context menu for Windows Explorer and exit",
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
    output_group.add_argument(
        "--plain",
        action="store_true",
        default=False,
        help="render the classic flat list of strings without layout and tags",
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
    root_handlers = logging.getLogger().handlers
    if root_handlers:
        root_handlers[0].setFormatter(floss.logging_.ColorFormatter())

#!/usr/bin/env python
# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.
import os
import sys
import mmap
import codecs
import logging
import argparse
import textwrap
import contextlib
from enum import Enum
from time import time
from typing import Set, List, Optional

import halo
import colorama
import viv_utils
import viv_utils.flirt
from vivisect import VivWorkspace

import floss.utils
import floss.results
import floss.version
import floss.logging_
import floss.render.json
import floss.render.default
from floss.const import MEGABYTE, MAX_FILE_SIZE, MIN_STRING_LENGTH, SUPPORTED_FILE_MAGIC
from floss.utils import (
    hex,
    get_imagebase,
    get_runtime_diff,
    get_vivisect_meta_info,
    is_string_type_enabled,
    set_vivisect_log_level,
)
from floss.render import Verbosity
from floss.results import Analysis, Metadata, ResultDocument, load
from floss.strings import extract_ascii_unicode_strings
from floss.version import __version__
from floss.identify import (
    append_unique,
    get_function_fvas,
    get_top_functions,
    get_tight_function_fvas,
    get_functions_with_tightloops,
    find_decoding_function_features,
    get_functions_without_tightloops,
)
from floss.logging_ import DebugLevel
from floss.stackstrings import extract_stackstrings
from floss.tightstrings import extract_tightstrings
from floss.string_decoder import decode_strings

SIGNATURES_PATH_DEFAULT_STRING = "(embedded signatures)"
EXTENSIONS_SHELLCODE_32 = ("sc32", "raw32")
EXTENSIONS_SHELLCODE_64 = ("sc64", "raw64")

logger = floss.logging_.getLogger("floss")


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
        "The FLARE team's open-source tool to extract obfuscated strings from malware.\n"
        f"  %(prog)s {__version__} - https://github.com/mandiant/flare-floss/\n\n"
        "FLOSS extracts all the following string types:\n"
        ' 1. static strings:  "regular" ASCII and UTF-16LE strings\n'
        " 2. stack strings:   strings constructed on the stack at run-time\n"
        " 3. tight strings:   special form of stack strings, decoded on the stack\n"
        " 4. decoded strings: strings decoded in a function\n"
    )
    epilog = textwrap.dedent(
        """
        only displaying core arguments, run `floss -H` to see all supported options

        examples:
          extract all strings from an executable
            floss suspicious.exe

          do not extract static strings
            floss --no static -- suspicious.exe

          only extract stack and tight strings
            floss --only stack tight -- suspicious.exe
        """
    )
    epilog_advanced = textwrap.dedent(
        """
        examples:
          extract all strings from 32-bit shellcode
            floss -f sc32 shellcode.bin

          only decode strings from the specified functions
            floss --functions 0x401000 0x401100 suspicious.exe
        """
    )

    show_all_options = "-H" in argv

    parser = ArgumentParser(
        description=desc,
        epilog=epilog_advanced if show_all_options else epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.register("action", "extend", floss.utils.ExtendAction)
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
        help="only analyze the specified functions, hex-encoded like 0x401000, space-separate multiple functions"
        if show_all_options
        else argparse.SUPPRESS,
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
        help="path to .sig/.pat file or directory used to identify library functions, use embedded signatures by default"
        if show_all_options
        else argparse.SUPPRESS,
    )
    advanced_group.add_argument(
        "-L",
        "--large-file",
        action="store_true",
        help="allow processing files larger than {} MB".format(int(MAX_FILE_SIZE / MEGABYTE))
        if show_all_options
        else argparse.SUPPRESS,
    )
    advanced_group.add_argument(
        "--version",
        action="version",
        version="%(prog)s {:s}".format(__version__),
        help="show program's version number and exit" if show_all_options else argparse.SUPPRESS,
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
        "-o",
        "--outfile",
        type=str,
        help="write results to output file, instead of default STDOUT",
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


def set_color_config(color):
    sys.stdout.reconfigure(encoding="utf-8")
    colorama.just_fix_windows_console()

    if color == "always":
        colorama.init(strip=False)
    elif color == "auto":
        # colorama will detect:
        #  - when on Windows console, and fixup coloring, and
        #  - when not an interactive session, and disable coloring
        # renderers should use coloring and assume it will be stripped out if necessary.
        colorama.init()
    elif color == "never":
        colorama.init(strip=True)
    else:
        raise RuntimeError("unexpected --color value: " + color)


def set_log_config(debug, quiet):
    if quiet:
        log_level = logging.WARNING
    elif debug >= DebugLevel.TRACE:
        log_level = logging.TRACE
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


def select_functions(vw, asked_functions: Optional[List[int]]) -> Set[int]:
    """
    Given a workspace and an optional list of function addresses,
    collect the set of valid functions,
    or all valid function addresses.

    arguments:
      asked_functions: the functions a user wants, or None.

    raises:
      ValueError: if an asked for function does not exist in the workspace.
    """
    functions = set(vw.getFunctions())
    if not asked_functions:
        # user didn't specify anything, so return them all.
        logger.debug("selected ALL functions")
        return functions

    asked_functions_ = set(asked_functions or [])

    # validate that all functions requested by the user exist.
    missing_functions = sorted(asked_functions_ - functions)
    if missing_functions:
        raise ValueError("failed to find functions: %s" % (", ".join(map(hex, sorted(missing_functions)))))

    logger.debug("selected %d functions", len(asked_functions_))
    logger.trace("selected the following functions: %s", ", ".join(map(hex, sorted(asked_functions_))))

    return asked_functions_


def is_supported_file_type(sample_file_path):
    """
    Return if FLOSS supports the input file type, based on header bytes
    :param sample_file_path:
    :return: True if file type is supported, False otherwise
    """
    with open(sample_file_path, "rb") as f:
        magic = f.read(2)

    if magic in SUPPORTED_FILE_MAGIC:
        return True
    else:
        return False


class Architecture(str, Enum):
    i386 = "i386"
    amd64 = "amd64"


def load_vw(
    sample_path: str,
    format: str,
    sigpaths: List[str],
    should_save_workspace: bool = False,
) -> VivWorkspace:
    if format not in ("sc32", "sc64"):
        if not is_supported_file_type(sample_path):
            raise WorkspaceLoadError(
                "FLOSS currently supports the following formats for string decoding and stackstrings: PE\n"
                "You can analyze shellcode using the --format sc32|sc64 switch. See the help (-h) for more information."
            )

    # get shellcode type based on sample file extension
    if format == "auto" and sample_path.endswith(EXTENSIONS_SHELLCODE_32):
        format = "sc32"
    elif format == "auto" and sample_path.endswith(EXTENSIONS_SHELLCODE_64):
        format = "sc64"

    if format == "sc32":
        vw = viv_utils.getShellcodeWorkspaceFromFile(sample_path, arch="i386", analyze=False)
    elif format == "sc64":
        vw = viv_utils.getShellcodeWorkspaceFromFile(sample_path, arch="amd64", analyze=False)
    else:
        vw = viv_utils.getWorkspace(sample_path, analyze=False, should_save=False)

    viv_utils.flirt.register_flirt_signature_analyzers(vw, sigpaths)

    vw.analyze()

    if should_save_workspace:
        logger.debug("saving workspace")
        try:
            vw.saveWorkspace()
        except IOError:
            logger.info("source directory is not writable, won't save intermediate workspace")
    else:
        logger.debug("not saving workspace")

    return vw


def is_running_standalone() -> bool:
    """
    are we running from a PyInstaller'd executable?
    if so, then we'll be able to access `sys._MEIPASS` for the packaged resources.
    """
    return hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS")


def get_default_root() -> str:
    """
    get the file system path to the default resources directory.
    under PyInstaller, this comes from _MEIPASS.
    under source, this is the root directory of the project.
    """
    if is_running_standalone():
        # pylance/mypy don't like `sys._MEIPASS` because this isn't standard.
        # its injected by pyinstaller.
        # so we'll fetch this attribute dynamically.
        return getattr(sys, "_MEIPASS")
    else:
        return os.path.join(os.path.dirname(__file__))


def get_signatures(sigs_path):
    if not os.path.exists(sigs_path):
        raise IOError("signatures path %s does not exist or cannot be accessed" % sigs_path)

    paths = []
    if os.path.isfile(sigs_path):
        paths.append(sigs_path)
    elif os.path.isdir(sigs_path):
        logger.debug("reading signatures from directory %s", os.path.abspath(os.path.normpath(sigs_path)))
        for root, dirs, files in os.walk(sigs_path):
            for file in files:
                if file.endswith((".pat", ".pat.gz", ".sig")):
                    sig_path = os.path.join(root, file)
                    paths.append(sig_path)

    # nicely normalize and format path so that debugging messages are clearer
    paths = [os.path.abspath(os.path.normpath(path)) for path in paths]

    # load signatures in deterministic order: the alphabetic sorting of filename.
    # this means that `0_sigs.pat` loads before `1_sigs.pat`.
    paths = sorted(paths, key=os.path.basename)

    for path in paths:
        logger.debug("found signature file: %s", path)

    return paths


def write(results: ResultDocument, json_: bool, verbose: Verbosity, quiet: bool, outfile: Optional[str]):
    if json_:
        r = floss.render.json.render(results)
    else:
        r = floss.render.default.render(results, verbose, quiet)
    if outfile:
        logger.info("writing results to %s", outfile)
        with open(outfile, "wb") as f:
            f.write(r.encode("utf-8"))
    else:
        print(r)


def main(argv=None) -> int:
    """
    arguments:
      argv: the command line arguments
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = make_parser(argv)
    try:
        args = parser.parse_args(args=argv)
        # manual check here, because add_mutually_exclusive_group() on argument_group("...") appears wrong
        if args.enabled_types and args.disabled_types:
            parser.error("--no and --only arguments are not allowed together")
    except ArgumentValueError as e:
        print(e)
        return -1

    set_log_config(args.debug, args.quiet)
    set_color_config(args.color)

    # Since Python 3.8 cp65001 is an alias to utf_8, but not for Python < 3.8
    # TODO: remove this code when only supporting Python 3.8+
    # https://stackoverflow.com/a/3259271/87207
    codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)

    if hasattr(args, "signatures"):
        if args.signatures == SIGNATURES_PATH_DEFAULT_STRING:
            logger.debug("-" * 80)
            logger.debug(" Using default embedded signatures.")
            logger.debug(
                " To provide your own signatures, use the form `floss.exe --signature ./path/to/signatures/  /path/to/mal.exe`."
            )
            logger.debug("-" * 80)

            sigs_path = os.path.join(get_default_root(), "sigs")
        else:
            sigs_path = args.signatures
            logger.debug("using signatures path: %s", sigs_path)

        args.signatures = sigs_path

    # alternatively: pass buffer along instead of file path, also should work for stdin
    sample = args.sample.name
    args.sample.close()

    if args.functions:
        if is_string_type_enabled(StringType.STATIC, args.disabled_types, args.enabled_types):
            logger.warning("analyzing specified functions, not showing static strings")
        args.disabled_types.append(StringType.STATIC)

    analysis = Analysis(
        enable_static_strings=is_string_type_enabled(StringType.STATIC, args.disabled_types, args.enabled_types),
        enable_stack_strings=is_string_type_enabled(StringType.STACK, args.disabled_types, args.enabled_types),
        enable_tight_strings=is_string_type_enabled(StringType.TIGHT, args.disabled_types, args.enabled_types),
        enable_decoded_strings=is_string_type_enabled(StringType.DECODED, args.disabled_types, args.enabled_types),
    )

    if args.load:
        try:
            results = load(sample, analysis, args.functions, args.min_length)
        except floss.results.InvalidResultsFile as e:
            logger.error("cannot load JSON results file: %s", e)
            return -1
        except floss.results.InvalidLoadConfig as e:
            logger.error("%s", e)
            return -1

        write(results, args.json, args.verbose, args.quiet, args.outfile)
        return 0

    results = ResultDocument(metadata=Metadata(file_path=sample, min_length=args.min_length), analysis=analysis)

    time0 = time()
    interim = time0
    sample_size = os.path.getsize(sample)

    # in order of expected run time, fast to slow
    # 1. static strings
    # 2. stack strings
    # 3. tight strings
    # 4. decoded strings

    if results.analysis.enable_static_strings:
        logger.info("extracting static strings...")

        if sample_size > sys.maxsize:
            logger.warning("file is very large, strings listings may be truncated.")

        with open(sample, "rb") as f:
            with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                static_strings = list(extract_ascii_unicode_strings(buf, args.min_length))

        results.strings.static_strings = static_strings
        results.metadata.runtime.static_strings = get_runtime_diff(interim)
        interim = time()

    if (
        results.analysis.enable_decoded_strings
        or results.analysis.enable_stack_strings
        or results.analysis.enable_tight_strings
    ):
        if sample_size > MAX_FILE_SIZE:
            if not args.large_file:
                logger.error(
                    "cannot deobfuscate strings from files larger than 0x%x bytes",
                    MAX_FILE_SIZE,
                )
                return -1
            else:
                logger.warning(
                    "a large file was provided with a size of %i bytes, this may take much more time and system resource to process",
                    sample_size,
                )

        sigpaths = get_signatures(args.signatures)

        should_save_workspace = os.environ.get("FLOSS_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)
        try:
            with halo.Halo(
                text="analyzing program",
                spinner="simpleDots",
                stream=sys.stderr,
                enabled=not (args.quiet or args.disable_progress),
            ):
                vw = load_vw(sample, args.format, sigpaths, should_save_workspace)
                results.metadata.runtime.vivisect = get_runtime_diff(interim)
                interim = time()
        except WorkspaceLoadError as e:
            logger.error("failed to analyze sample: %s", e)
            return -1

        results.metadata.imagebase = get_imagebase(vw)

        try:
            selected_functions = select_functions(vw, args.functions)
            results.analysis.functions.discovered = len(vw.getFunctions())
        except ValueError as e:
            # failed to find functions in workspace
            logger.error(e.args[0])
            return -1

        decoding_function_features, library_functions = find_decoding_function_features(
            vw, selected_functions, disable_progress=args.quiet or args.disable_progress
        )
        results.analysis.functions.library = len(library_functions)
        results.metadata.runtime.find_features = get_runtime_diff(interim)
        interim = time()

        logger.trace("analysis summary:")
        for k, v in get_vivisect_meta_info(vw, selected_functions, decoding_function_features).items():
            logger.trace("  %s: %s", k, v or "N/A")

        if results.analysis.enable_stack_strings:
            if results.analysis.enable_tight_strings:
                # don't run this on functions with tight loops as this will likely result in FPs
                # and should be caught by the tightstrings extraction below
                selected_functions = get_functions_without_tightloops(decoding_function_features)

            results.strings.stack_strings = extract_stackstrings(
                vw,
                selected_functions,
                args.min_length,
                verbosity=args.verbose,
                disable_progress=args.quiet or args.disable_progress,
            )
            results.analysis.functions.analyzed_stack_strings = len(selected_functions)
            results.metadata.runtime.stack_strings = get_runtime_diff(interim)
            interim = time()

        if results.analysis.enable_tight_strings:
            tightloop_functions = get_functions_with_tightloops(decoding_function_features)
            results.strings.tight_strings = extract_tightstrings(
                vw,
                tightloop_functions,
                min_length=args.min_length,
                verbosity=args.verbose,
                disable_progress=args.quiet or args.disable_progress,
            )
            results.analysis.functions.analyzed_tight_strings = len(tightloop_functions)
            results.metadata.runtime.tight_strings = get_runtime_diff(interim)
            interim = time()

        if results.analysis.enable_decoded_strings:
            # TODO select more based on score rather than absolute count?!
            top_functions = get_top_functions(decoding_function_features, 20)

            fvas_to_emulate = get_function_fvas(top_functions)
            fvas_tight_functions = get_tight_function_fvas(
                decoding_function_features
            )  # TODO exclude tight functions from stackstrings analysis?!
            fvas_to_emulate = append_unique(fvas_to_emulate, fvas_tight_functions)

            if len(fvas_to_emulate) == 0:
                logger.info("no candidate decoding functions found.")
            else:
                logger.debug("identified %d candidate decoding functions", len(fvas_to_emulate))
                for fva in fvas_to_emulate:
                    results.analysis.functions.decoding_function_scores[fva] = decoding_function_features[fva]["score"]
                    logger.debug("  - 0x%x: %.3f", fva, decoding_function_features[fva]["score"])

            # TODO filter out strings decoded in library function or function only called by library function(s)
            results.strings.decoded_strings = decode_strings(
                vw,
                fvas_to_emulate,
                args.min_length,
                verbosity=args.verbose,
                disable_progress=args.quiet or args.disable_progress,
            )
            results.analysis.functions.analyzed_decoded_strings = len(fvas_to_emulate)
            results.metadata.runtime.decoded_strings = get_runtime_diff(interim)

    results.metadata.runtime.total = get_runtime_diff(time0)
    logger.info("finished execution after %.2f seconds", results.metadata.runtime.total)

    write(results, args.json, args.verbose, args.quiet, args.outfile)

    return 0


if __name__ == "__main__":
    sys.exit(main())

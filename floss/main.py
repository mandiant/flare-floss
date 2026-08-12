#!/usr/bin/env python
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

import sys
import json
from pathlib import Path

import rich.traceback

import floss.results
import floss.logging_
import floss.render.json
import floss.render.default
from floss.cli import (
    SIGNATURES_PATH_DEFAULT_STRING,
    StringType,
    ArgumentValueError,
    make_parser,
    set_log_config,
)
from floss.utils import is_string_type_enabled
from floss.results import Analysis, load
from floss.pipeline import Options, PipelineError, analyze

logger = floss.logging_.getLogger("floss")


def is_running_standalone() -> bool:
    """
    are we running from a PyInstaller'd executable?
    if so, then we'll be able to access `sys._MEIPASS` for the packaged resources.
    """
    return hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS")


def is_results_document(sample: Path) -> bool:
    """
    Detect a saved FLOSS results document from its content.

    A results document is a JSON object with the top-level ResultDocument
    fields metadata, analysis, and strings. The top-level schema is stable
    across the migration iterations, so this check does not need a version.

    Binary samples are rejected cheaply by peeking the first non-whitespace
    byte. The full file is loaded and parsed only when the content looks
    like JSON, so large binaries are not read for the check.
    """
    try:
        with sample.open("rb") as f:
            for byte in iter(lambda: f.read(1), b""):
                if not byte.strip():
                    continue
                if byte != b"{":
                    return False
                break
    except OSError:
        return False

    try:
        data = json.loads(sample.read_bytes())
    except (OSError, ValueError):
        return False

    return isinstance(data, dict) and all(k in data for k in ("metadata", "analysis", "strings"))


def get_default_root() -> Path:
    """
    get the file system path to the default resources directory.
    under PyInstaller, this comes from _MEIPASS.
    under source, this is the root directory of the project.
    """
    if is_running_standalone():
        # pylance/mypy don't like `sys._MEIPASS` because this isn't standard.
        # its injected by pyinstaller.
        # so we'll fetch this attribute dynamically.
        return Path(getattr(sys, "_MEIPASS"))
    else:
        return Path(__file__).resolve().parent


def main(argv=None) -> int:
    """
    arguments:
      argv: the command line arguments
    """
    rich.traceback.install(show_locals=True)

    if argv is None:
        argv = sys.argv[1:]

    parser = make_parser()
    try:
        if not argv:
            # no arguments: print the full option list and exit with code 1
            parser.print_help()
            return 1
        args = parser.parse_args(args=argv)
        if args.enabled_string_types and args.disabled_string_types:
            parser.error("--string-type and --no-string-type arguments are not allowed together")
    except ArgumentValueError as e:
        print(e)
        return -1

    set_log_config(args.debug, args.quiet)

    if hasattr(args, "signatures"):
        if args.signatures == SIGNATURES_PATH_DEFAULT_STRING:
            logger.debug("-" * 80)
            logger.debug(" Using default embedded signatures.")
            logger.debug(
                " To provide your own signatures, use the form `floss.exe --signature ./path/to/signatures/  /path/to/mal.exe`."
            )
            logger.debug("-" * 80)

            sigs_path = get_default_root() / "sigs"
        else:
            sigs_path = Path(args.signatures)
            logger.debug("using signatures path: %s", str(sigs_path))

        args.signatures = sigs_path

    sample = Path(args.sample.name)
    args.sample.close()

    disabled_string_types = list(args.disabled_string_types or [])
    enabled_string_types = list(args.enabled_string_types or [])

    if args.functions:
        if is_string_type_enabled(StringType.STATIC, disabled_string_types, enabled_string_types):
            logger.warning("analyzing specified functions, not showing static strings")
        if StringType.STATIC.value not in disabled_string_types:
            disabled_string_types.append(StringType.STATIC.value)

    # layout/tags are always on: automatic and detected from the sample content
    analysis = Analysis(
        enable_static_strings=is_string_type_enabled(StringType.STATIC, disabled_string_types, enabled_string_types),
        enable_stack_strings=is_string_type_enabled(StringType.STACK, disabled_string_types, enabled_string_types),
        enable_tight_strings=is_string_type_enabled(StringType.TIGHT, disabled_string_types, enabled_string_types),
        enable_decoded_strings=is_string_type_enabled(StringType.DECODED, disabled_string_types, enabled_string_types),
        enable_layout=True,
        enable_tags=True,
    )

    if is_results_document(sample):
        try:
            results = load(sample, analysis, args.functions, args.min_length)
        except floss.results.InvalidResultsFile as e:
            logger.error("cannot load JSON results file: %s", e)
            return -1
        except floss.results.InvalidLoadConfig as e:
            logger.error("%s", e)
            return -1

        if args.json:
            r = floss.render.json.render(results)
        else:
            r = floss.render.default.render(results, args.verbose, args.quiet, args.color)

        print(r)
        return 0

    options = Options(
        sample=sample,
        min_length=args.min_length,
        analysis=analysis,
        format=args.format,
        language=args.language,
        enabled_string_types=enabled_string_types,
        disabled_string_types=disabled_string_types,
        functions=args.functions,
        signatures=args.signatures,
        large_file=args.large_file,
        quiet=args.quiet,
        verbose=args.verbose,
        prompt_deobfuscation=True,
    )

    try:
        analysis_results = analyze(options)
    except PipelineError as e:
        if e.exit_code in (1, 130):
            logger.info("%s", e)
        else:
            logger.error("%s", e)
        return e.exit_code

    if analysis_results is None:
        return 0

    if args.json:
        r = floss.render.json.render(analysis_results)
    else:
        # this may be slow when there's many strings, so informing users what's happening
        logger.info("rendering results")
        r = floss.render.default.render(analysis_results, args.verbose, args.quiet, args.color)

    print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())

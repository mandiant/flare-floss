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

import re
import sys
import json
from pathlib import Path

import rich.traceback

import floss.cache
import floss.results
import floss.logging_
import floss.render.json
import floss.render.default
import floss.render.summary
from floss.cli import (
    SIGNATURES_PATH_DEFAULT_STRING,
    StringType,
    ArgumentValueError,
    make_parser,
    set_log_config,
)
from floss.utils import FileType, detect_file_type, expand_string_types, is_string_type_enabled
from floss.results import Analysis, load
from floss.pipeline import Options, PipelineError, analyze
from floss.render.filter import LayoutFilter
from floss.language.identify import Language

logger = floss.logging_.getLogger("floss")


def is_running_standalone() -> bool:
    """
    are we running from a PyInstaller'd executable?
    if so, then we'll be able to access `sys._MEIPASS` for the packaged resources.
    """
    return hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS")


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


def emit_json_error(message: str, code: int = 1) -> None:
    """emit a structured JSON error on STDERR for the JSON output modes."""
    sys.stderr.write(json.dumps({"error": message, "code": code}) + "\n")


def report_error(parser, message: str) -> None:
    """emit an error in the active output mode: JSON object on STDERR for
    JSON modes, otherwise a plain message on STDERR."""
    if parser.json_mode:
        emit_json_error(message)
    else:
        print(message, file=sys.stderr)


def json_requested(argv) -> bool:
    """best-effort detection of a JSON output mode before argument parsing completes."""
    argv = argv or []
    return "--json" in argv or any(a == "-j" for a in argv)


def build_layout_filter(args) -> LayoutFilter:
    return LayoutFilter(
        include_sections=args.include_sections,
        exclude_sections=args.exclude_sections,
        include_structures=args.include_structures,
        exclude_structures=args.exclude_structures,
        include_tags=args.include_tags,
        exclude_tags=args.exclude_tags,
        interesting=args.interesting,
        queries=args.queries,
        max_strings=args.max_strings,
        tag_rules=floss.render.default.DEFAULT_TAG_RULES,
    )


def render_text(args, results: floss.results.ResultDocument, stream=None):
    """render results as text, honoring --summary, --plain, --columns, and the filters."""
    if args.summary:
        # --summary is its own output; it needs the layout tree intact
        return floss.render.summary.render_summary(results, args.color)
    return floss.render.default.render(
        results,
        args.verbose,
        args.quiet,
        args.color,
        columns=args.columns,
        layout_filter=build_layout_filter(args),
        plain=args.plain,
        stream=stream,
    )


def main(argv=None) -> int:
    """
    arguments:
      argv: the command line arguments
    """
    rich.traceback.install(show_locals=True)

    if argv is None:
        argv = sys.argv[1:]

    parser = make_parser()
    parser.json_mode = json_requested(argv)
    try:
        if not argv:
            # no arguments: print the full option list and exit with code 1
            parser.print_help()
            return 1
        args = parser.parse_args(args=argv)
        for flag, include, exclude in (
            ("--string-type", args.enabled_string_types, args.disabled_string_types),
            ("--section", args.include_sections, args.exclude_sections),
            ("--structure", args.include_structures, args.exclude_structures),
            ("--tag", args.include_tags, args.exclude_tags),
        ):
            if include and exclude:
                parser.error("%s and --no-%s arguments are not allowed together" % (flag, flag[2:]))
        for flag, values in (
            ("--string-type", args.enabled_string_types),
            ("--no-string-type", args.disabled_string_types),
        ):
            if len(values) > 1 and StringType.ALL.value in values:
                parser.error("%s: 'all' cannot be combined with other string types" % flag)
        if args.summary:
            if args.analyze_functions:
                parser.error(
                    "--summary only covers static strings, which --analyze-functions does not show; "
                    "these flags cannot be combined"
                )
            if args.enabled_string_types or args.disabled_string_types:
                # --summary is its own static-only view; reject any string-type
                # selection rather than accepting shadow args
                parser.error("--summary only covers static strings and does not take --string-type/--no-string-type")
        if args.max_strings is not None and args.max_strings <= 0:
            parser.error("--max-strings must be a positive integer")
        for pattern in args.queries:
            try:
                re.compile(pattern)
            except re.error as e:
                parser.error("invalid --query regular expression %r: %s" % (pattern, e))
    except ArgumentValueError as e:
        report_error(parser, str(e))
        return -1

    set_log_config(args.debug, args.quiet)

    # caching applies to the default analysis variant only: an explicit format,
    # language, or custom signatures change the analysis, so the content-
    # addressed cache could return a mismatched document. disable it for those.
    cache_dir = None
    if (
        not args.analyze_functions
        and args.format == "auto"
        and args.language == Language.AUTO.value
        and args.signatures == SIGNATURES_PATH_DEFAULT_STRING
    ):
        cache_dir = floss.cache.get_cache_dir()

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

    disabled_string_types = expand_string_types(list(args.disabled_string_types or []))
    enabled_string_types = expand_string_types(list(args.enabled_string_types or []))

    if args.summary and not disabled_string_types and not enabled_string_types:
        # the summary's layout-derived sections cover static strings only, so
        # don't spin up the slow deobfuscation for stack/tight/decoded
        logger.info("--summary is static-only; skipping stack/tight/decoded extraction")
        disabled_string_types.extend([StringType.STACK.value, StringType.TIGHT.value, StringType.DECODED.value])

    if args.analyze_functions:
        static_was_enabled = is_string_type_enabled(StringType.STATIC, disabled_string_types, enabled_string_types)
        try:
            if enabled_string_types and StringType.STATIC.value in enabled_string_types:
                # --string-type explicitly selected static, but --analyze-functions cannot show it:
                # drop it from the include list instead of forcing the exclude list.
                enabled_string_types.remove(StringType.STATIC.value)
                if not enabled_string_types:
                    parser.error(
                        "--string-type static cannot be combined with --analyze-functions, "
                        "which does not show static strings"
                    )
            elif not enabled_string_types and StringType.STATIC.value not in disabled_string_types:
                disabled_string_types.append(StringType.STATIC.value)
        except ArgumentValueError as e:
            report_error(parser, str(e))
            return -1
        if static_was_enabled:
            logger.warning("analyzing specified functions, not showing static strings")

    # layout/tags are always on: automatic and detected from the sample content
    analysis = Analysis(
        enable_static_strings=is_string_type_enabled(StringType.STATIC, disabled_string_types, enabled_string_types),
        enable_stack_strings=is_string_type_enabled(StringType.STACK, disabled_string_types, enabled_string_types),
        enable_tight_strings=is_string_type_enabled(StringType.TIGHT, disabled_string_types, enabled_string_types),
        enable_decoded_strings=is_string_type_enabled(StringType.DECODED, disabled_string_types, enabled_string_types),
        enable_language_strings=is_string_type_enabled(
            StringType.LANGUAGE, disabled_string_types, enabled_string_types
        ),
    )

    if detect_file_type(sample) is FileType.RESULTS:
        try:
            results = load(sample, analysis, args.analyze_functions, args.min_length)
        except floss.results.InvalidResultsFile as e:
            if args.json:
                emit_json_error(f"cannot load JSON results file: {e}")
            else:
                logger.error("cannot load JSON results file: %s", e)
            return -1
        except floss.results.InvalidLoadConfig as e:
            if args.json:
                emit_json_error(str(e))
            else:
                logger.error("%s", e)
            return -1

        if args.json:
            r = floss.render.json.render(results)
        else:
            r = render_text(args, results, stream=sys.stdout)

        if r is not None:
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
        analyze_functions=args.analyze_functions,
        signatures=args.signatures,
        large_file=args.large_file,
        quiet=args.quiet,
        verbose=args.verbose,
        cache_dir=cache_dir,
    )

    try:
        analysis_results = analyze(options)
    except PipelineError as e:
        if args.json:
            emit_json_error(str(e), code=e.exit_code if e.exit_code >= 0 else 1)
        elif e.exit_code in (1, 130):
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
        r = render_text(args, analysis_results, stream=sys.stdout)

    if r is not None:
        print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())

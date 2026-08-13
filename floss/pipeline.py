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

"""Full FLOSS analysis orchestration.

Unified pipeline: static/language strings, optional layout+tags,
then vivisect deobfuscation (stack/tight/decoded) when enabled.
"""

from __future__ import annotations

import os
import sys
import hashlib
from time import time
from typing import Set, List, Optional
from pathlib import Path
from dataclasses import dataclass

import halo
import viv_utils
import viv_utils.flirt
from vivisect import VivWorkspace

import floss.utils
import floss.results
import floss.logging_
import floss.language.utils
import floss.language.go.extract
import floss.language.rust.extract
from floss.cli import WorkspaceLoadError
from floss.const import (
    MAX_FILE_SIZE,
)
from floss.utils import (
    FileType,
    hex,
    get_imagebase,
    detect_file_type,
    get_runtime_diff,
    get_vivisect_meta_info,
)
from floss.enrich import (
    build_offset_index,
    is_structured_layout,
    enrich_static_strings,
    static_strings_from_layout,
)
from floss.layout import Layout
from floss.render import Verbosity
from floss.results import Runtime, Analysis, Metadata, ResultLayout, ResultDocument
from floss.strings import extract_ascii_unicode_strings
from floss.identify import (
    append_unique,
    get_function_fvas,
    get_top_functions,
    get_tight_function_fvas,
    get_functions_with_tightloops,
    find_decoding_function_features,
    get_functions_without_tightloops,
)
from floss.stackstrings import extract_stackstrings
from floss.tightstrings import extract_tightstrings
from floss.string_decoder import decode_strings
from floss.language.identify import Language, identify_language_and_version

logger = floss.logging_.getLogger("floss.pipeline")

EXTENSIONS_SHELLCODE_32 = ("sc32", "raw32")
EXTENSIONS_SHELLCODE_64 = ("sc64", "raw64")


class PipelineError(Exception):
    """Analysis failed; ``exit_code`` is for the CLI."""

    def __init__(self, message: str, exit_code: int = -1):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class Options:
    sample: Path
    min_length: int
    analysis: Analysis
    format: str = "auto"
    language: str = Language.UNKNOWN.value
    enabled_string_types: Optional[List[str]] = None
    disabled_string_types: Optional[List[str]] = None
    functions: Optional[List[int]] = None
    signatures: Optional[Path] = None
    large_file: bool = False
    quiet: bool = False
    disable_progress: bool = False
    verbose: int = Verbosity.DEFAULT
    # when True, prompt on TTY for deobfuscation on language binaries
    prompt_deobfuscation: bool = True


def select_functions(vw, asked_functions: Optional[List[int]]) -> Set[int]:
    """
    Given a workspace and an optional list of function addresses,
    collect the set of valid functions, or all valid function addresses.

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


def load_vw(
    sample_path: Path,
    format: str,
    sigpaths: List[Path],
    should_save_workspace: bool = False,
) -> VivWorkspace:
    file_type = detect_file_type(sample_path)
    if format not in ("sc32", "sc64"):
        if file_type in (FileType.UNSUPPORTED, FileType.RESULTS):
            raise WorkspaceLoadError(
                "FLOSS currently supports the following formats for string decoding and stackstrings: PE and ELF\n"
                "You can analyze shellcode using the --format sc32|sc64 switch. See the help (-h) for more information."
            )

    if format == "auto" and sample_path.suffix.lower() in EXTENSIONS_SHELLCODE_32:
        format = "sc32"
    elif format == "auto" and sample_path.suffix.lower() in EXTENSIONS_SHELLCODE_64:
        format = "sc64"

    if format == "sc32":
        vw = viv_utils.getShellcodeWorkspaceFromFile(str(sample_path), arch="i386", analyze=False)
    elif format == "sc64":
        vw = viv_utils.getShellcodeWorkspaceFromFile(str(sample_path), arch="amd64", analyze=False)
    else:
        vw = viv_utils.getWorkspace(str(sample_path), analyze=False, should_save=False)

    if file_type is FileType.PE:
        viv_utils.flirt.register_flirt_signature_analyzers(vw, list(map(str, sigpaths)))

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


def get_signatures(sigs_path: Path) -> List[Path]:
    if not sigs_path.exists():
        raise IOError("signatures path %s does not exist or cannot be accessed" % str(sigs_path))

    paths = []
    if sigs_path.is_file():
        paths.append(sigs_path)
    elif sigs_path.is_dir():
        logger.debug("reading signatures from directory %s", str(sigs_path.resolve().absolute()))
        for item in sigs_path.iterdir():
            if item.is_file():
                if item.suffix in [".pat", ".pat.gz", ".sig"]:
                    paths.append(item)

    # load signatures in deterministic order: the alphabetic sorting of filename.
    # this means that `0_sigs.pat` loads before `1_sigs.pat`.
    paths = [path.resolve().absolute() for path in paths]
    paths = sorted(paths, key=lambda p: p.name)

    for path in paths:
        logger.debug("found signature file: %s", str(path))

    return paths


def compute_layout(
    buf: bytes,
    min_length: int,
) -> Optional[Layout]:
    """
    Compute a structured layout and extract static strings.

    Returns the populated layout tree, or None to fall back to classic statics when
    the layout does not parse or any step fails. Default-on layout must not
    crash the whole run.
    """
    from floss.layout import compute_layout as layout_compute
    from floss.ranges import Slice

    try:
        file_slice = Slice.from_bytes(buf=buf)
        parsed_layout = layout_compute(file_slice)

        if not is_structured_layout(parsed_layout.name):
            logger.debug("no structured layout (got %r); using classic static strings", parsed_layout.name)
            return None

        parsed_layout.extract_strings(min_length)
        return parsed_layout
    except Exception as e:
        logger.warning("layout-aware static analysis failed; using classic statics: %s", e)
        return None


def tag_layout(
    layout: Layout,
    enable_tags: bool,
) -> None:
    """
    Tag the layout strings and drop false positives.
    """
    from floss.tags import load_databases, remove_false_positive_lib_strings

    # tag_strings always converts ExtractedString → TaggedString (needed for mark_structures)
    taggers = load_databases() if enable_tags else []
    layout.tag_strings(taggers)
    layout.mark_structures()
    if enable_tags:
        remove_false_positive_lib_strings(layout)


def try_layout_static(
    buf: bytes,
    min_length: int,
    enable_tags: bool,
    runtime: Runtime,
) -> Optional[ResultLayout]:
    """
    Layout-aware static extraction with timing.

    Runs the layout computation and the tag matching steps, and records
    the elapsed time of each phase separately: ``runtime.layout`` covers
    the layout computation only, ``runtime.tags`` covers the tag matching
    step only.

    Returns a serializable ResultLayout, or None to fall back to classic
    statics. Default-on layout must not crash the whole run.
    """
    try:
        with runtime.measure_and_set_time("layout"):
            layout = compute_layout(buf, min_length)
            if layout is None:
                return None

        with runtime.measure_and_set_time("tags"):
            tag_layout(layout, enable_tags)

        return ResultLayout.from_layout(layout)
    except Exception as e:
        logger.warning("layout-aware static analysis failed; using classic statics: %s", e)
        return None


def analyze(options: Options) -> Optional[ResultDocument]:
    """
    Run full analysis. Returns None when there are no static strings to start from
    (matches historical CLI early-exit with code 0).
    """
    sample = options.sample
    analysis = options.analysis

    results = ResultDocument(
        metadata=Metadata(file_path=str(sample), min_length=options.min_length),
        analysis=analysis,
    )

    sample_size = sample.stat().st_size
    if sample_size > sys.maxsize:
        logger.warning("file is very large, strings listings may be truncated")

    time0 = time()

    # one read for classic statics + layout (layout is default and needs a full buffer)
    # TODO: mmap-only classic path if layout is ever optional-only again
    sample_buf = sample.read_bytes()
    if not sample_buf:
        logger.warning("file is empty")
        return None

    results.metadata.md5 = hashlib.md5(sample_buf).hexdigest()
    results.metadata.sha1 = hashlib.sha1(sample_buf).hexdigest()
    results.metadata.sha256 = hashlib.sha256(sample_buf).hexdigest()

    static_strings = list(extract_ascii_unicode_strings(sample_buf, options.min_length))
    if not static_strings:
        return None

    static_runtime = get_runtime_diff(time0)

    # set language configurations
    selected_lang = Language(options.language)
    if selected_lang == Language.DISABLED:
        results.metadata.language = ""
        results.metadata.language_version = ""
        results.metadata.language_selected = ""
    else:
        lang_id, lang_version = identify_language_and_version(sample, static_strings)

        if selected_lang == Language.UNKNOWN:
            pass
        elif selected_lang != lang_id:
            logger.warning(
                "the selected language '%s' differs to the automatically identified language '%s (%s)' - extracted "
                "strings may be incomplete or inaccurate",
                selected_lang.value,
                lang_id.value,
                lang_version,
            )
            results.metadata.language_selected = selected_lang.value

        results.metadata.language = lang_id.value
        results.metadata.language_version = lang_version

    if results.metadata.language == Language.GO.value:
        if analysis.enable_tight_strings or analysis.enable_stack_strings or analysis.enable_decoded_strings:
            logger.warning(
                "FLOSS handles Go static strings, but string deobfuscation may be inaccurate and take a long time"
            )

    elif results.metadata.language == Language.RUST.value:
        if analysis.enable_tight_strings or analysis.enable_stack_strings or analysis.enable_decoded_strings:
            logger.warning(
                "FLOSS handles Rust static strings, but string deobfuscation may be inaccurate and take a long time"
            )

    elif results.metadata.language == Language.DOTNET.value:
        logger.warning(".NET language-specific string extraction is not supported yet")
        logger.warning("FLOSS does NOT attempt to deobfuscate any strings from .NET binaries")
        # enable .NET strings once we can extract them
        # results.metadata.language = Language.DOTNET.value
        # TODO for pure .NET binaries our deobfuscation algorithms do nothing, but for mixed-mode assemblies they may
        analysis.enable_stack_strings = False
        analysis.enable_tight_strings = False
        analysis.enable_decoded_strings = False

    enabled_string_types = options.enabled_string_types or []
    disabled_string_types = options.disabled_string_types or []
    if results.metadata.language not in ("", "unknown"):
        if not enabled_string_types and not disabled_string_types and options.prompt_deobfuscation:
            # when stdout is redirected, such as in 'floss foo.exe | less' use default prompt values
            if sys.stdout.isatty():
                try:
                    prompt = input("Do you want to enable string deobfuscation? (this could take a long time) [y/N] ")
                except KeyboardInterrupt:
                    raise PipelineError("aborted by user", exit_code=130)
                except EOFError:
                    raise PipelineError("aborted by user", exit_code=1)
            else:
                prompt = "n"

            if prompt.lower() == "y":
                logger.info("enabled string deobfuscation")
                analysis.enable_stack_strings = True
                analysis.enable_tight_strings = True
                analysis.enable_decoded_strings = True
            else:
                logger.info("disabled string deobfuscation")
                analysis.enable_stack_strings = False
                analysis.enable_tight_strings = False
                analysis.enable_decoded_strings = False

    # in order of expected run time, fast to slow
    # 1. static strings (done above for language ID; layout-aware replace below when enabled)
    #  a) includes language-specific strings, if applicable
    # 2. stack strings
    # 3. tight strings
    # 4. decoded strings

    if results.analysis.enable_static_strings:
        logger.info("extracting static strings")
        layout_doc: Optional[ResultLayout] = None
        if analysis.enable_layout:
            # only layout/tag work for static_strings runtime — not language ID or the TTY prompt above
            with results.metadata.runtime.measure_and_set_time("static_strings"):
                layout_doc = try_layout_static(
                    sample_buf, options.min_length, analysis.enable_tags, results.metadata.runtime
                )

        if layout_doc is not None:
            results.layout = layout_doc
            results.strings.static_strings = static_strings_from_layout(layout_doc)
            # add the classic extraction time (done above for language ID)
            results.metadata.runtime.static_strings += static_runtime
        else:
            results.strings.static_strings = static_strings
            # add the elapsed time of the failed/skipped layout attempt, which
            # measure_and_set_time("static_strings") already recorded above
            results.metadata.runtime.static_strings += static_runtime

        # one offset index for both language_strings and language_strings_missed
        layout_offset_index = None
        if layout_doc is not None and results.metadata.language in (Language.GO.value, Language.RUST.value):
            layout_offset_index = build_offset_index(layout_doc)

        if results.metadata.language == Language.GO.value:
            logger.info("extracting language-specific Go strings")
            with results.metadata.runtime.measure_and_set_time("language_strings"):
                results.strings.language_strings = floss.language.go.extract.extract_go_strings(
                    sample, options.min_length
                )

            # missed strings only includes non-identified strings in searched range
            # here currently only focus on strings in string blob range
            base_statics = results.strings.static_strings if layout_doc is not None else static_strings
            string_blob_strings = floss.language.go.extract.get_static_strings_from_blob_range(sample, base_statics)
            results.strings.language_strings_missed = floss.language.utils.get_missed_strings(
                string_blob_strings, results.strings.language_strings, options.min_length
            )
            if layout_offset_index is not None:
                results.strings.language_strings = enrich_static_strings(
                    results.strings.language_strings, offset_index=layout_offset_index
                )
                results.strings.language_strings_missed = enrich_static_strings(
                    results.strings.language_strings_missed, offset_index=layout_offset_index
                )

        elif results.metadata.language == Language.RUST.value:
            logger.info("extracting language-specific Rust strings")
            with results.metadata.runtime.measure_and_set_time("language_strings"):
                results.strings.language_strings = floss.language.rust.extract.extract_rust_strings(
                    sample, options.min_length
                )

            # currently Rust strings are only extracted from the .rdata section
            base_statics = results.strings.static_strings if layout_doc is not None else static_strings
            rdata_strings = floss.language.rust.extract.get_static_strings_from_rdata(sample, base_statics)
            results.strings.language_strings_missed = floss.language.utils.get_missed_strings(
                rdata_strings, results.strings.language_strings, options.min_length
            )
            if layout_offset_index is not None:
                results.strings.language_strings = enrich_static_strings(
                    results.strings.language_strings, offset_index=layout_offset_index
                )
                results.strings.language_strings_missed = enrich_static_strings(
                    results.strings.language_strings_missed, offset_index=layout_offset_index
                )

    if (
        results.analysis.enable_decoded_strings
        or results.analysis.enable_stack_strings
        or results.analysis.enable_tight_strings
    ):
        if sample_size > MAX_FILE_SIZE:
            if not options.large_file:
                raise PipelineError(
                    "cannot deobfuscate strings from files larger than 0x%x bytes" % MAX_FILE_SIZE,
                    exit_code=-1,
                )
            else:
                logger.warning(
                    "a large file was provided with a size of %i bytes, this may take much more time and system resource to process",
                    sample_size,
                )

        if options.signatures is None:
            raise PipelineError("signatures path required for deobfuscation", exit_code=-1)

        sigpaths = get_signatures(options.signatures)

        should_save_workspace = os.environ.get("FLOSS_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)
        try:
            with halo.Halo(
                text="analyzing program",
                spinner="simpleDots",
                stream=sys.stderr,
                enabled=not (options.quiet or options.disable_progress),
            ):
                with results.metadata.runtime.measure_and_set_time("vivisect"):
                    vw = load_vw(sample, options.format, sigpaths, should_save_workspace)
        except WorkspaceLoadError as e:
            raise PipelineError("failed to analyze sample: %s" % e, exit_code=-1)

        results.metadata.imagebase = get_imagebase(vw)

        with results.metadata.runtime.measure_and_set_time("find_features"):
            try:
                selected_functions = select_functions(vw, options.functions)
                results.analysis.functions.discovered = len(vw.getFunctions())
            except ValueError as e:
                # failed to find functions in workspace
                raise PipelineError(e.args[0], exit_code=-1)

            decoding_function_features, library_functions = find_decoding_function_features(
                vw, selected_functions, disable_progress=options.quiet or options.disable_progress
            )
            results.analysis.functions.library = len(library_functions)

        logger.trace("analysis summary:")
        for k, v in get_vivisect_meta_info(vw, selected_functions, decoding_function_features).items():
            logger.trace("  %s: %s", k, v or "N/A")

        if results.analysis.enable_stack_strings:
            with results.metadata.runtime.measure_and_set_time("stack_strings"):
                funcs = selected_functions
                if results.analysis.enable_tight_strings:
                    # don't run stack-string extraction on functions with tight loops as this will likely
                    # result in FPs and should be caught by the tightstrings extraction below
                    funcs = get_functions_without_tightloops(decoding_function_features)

                results.strings.stack_strings = extract_stackstrings(
                    vw,
                    funcs,
                    options.min_length,
                    verbosity=options.verbose,
                    disable_progress=options.quiet or options.disable_progress,
                )
                results.analysis.functions.analyzed_stack_strings = len(funcs)

        if results.analysis.enable_tight_strings:
            with results.metadata.runtime.measure_and_set_time("tight_strings"):
                tightloop_functions = get_functions_with_tightloops(decoding_function_features)
                results.strings.tight_strings = extract_tightstrings(
                    vw,
                    tightloop_functions,
                    min_length=options.min_length,
                    verbosity=options.verbose,
                    disable_progress=options.quiet or options.disable_progress,
                )
                results.analysis.functions.analyzed_tight_strings = len(tightloop_functions)

        if results.analysis.enable_decoded_strings:
            with results.metadata.runtime.measure_and_set_time("decoded_strings"):
                # TODO select more based on score rather than absolute count?!
                top_functions = get_top_functions(decoding_function_features, 20)

                fvas_to_emulate = get_function_fvas(top_functions)
                fvas_tight_functions = get_tight_function_fvas(decoding_function_features)
                fvas_to_emulate = append_unique(fvas_to_emulate, fvas_tight_functions)

                if len(fvas_to_emulate) == 0:
                    logger.info("no candidate decoding functions found.")
                else:
                    logger.debug("identified %d candidate decoding functions", len(fvas_to_emulate))
                    for fva in fvas_to_emulate:
                        score = decoding_function_features[fva]["score"]
                        xrefs_to = decoding_function_features[fva]["xrefs_to"]
                        results.analysis.functions.decoding_function_scores[fva] = {
                            "score": score,
                            "xrefs_to": xrefs_to,
                        }
                        logger.debug("  - 0x%x: score: %.3f, xrefs to: %d", fva, score, xrefs_to)

                # TODO filter out strings decoded in library function or function only called by library function(s)
                results.strings.decoded_strings = decode_strings(
                    vw,
                    fvas_to_emulate,
                    options.min_length,
                    verbosity=options.verbose,
                    disable_progress=options.quiet or options.disable_progress,
                )
                results.analysis.functions.analyzed_decoded_strings = len(fvas_to_emulate)

    results.metadata.runtime.total = get_runtime_diff(time0)
    logger.info("finished execution after %.2f seconds", results.metadata.runtime.total)

    return results

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

Unified pipeline: static/language strings, optional layout+tags (quantum-style),
then vivisect deobfuscation (stack/tight/decoded) when enabled.
"""

from __future__ import annotations

import os
import sys
import hashlib
from time import time
from typing import Set, List, Optional, Tuple
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
    UNSUPPORTED_FILE_MAGIC,
    SUPPORTED_FILE_MAGIC_PE,
    SUPPORTED_FILE_MAGIC_ELF,
)
from floss.utils import (
    hex,
    get_imagebase,
    get_runtime_diff,
    get_vivisect_meta_info,
)
from floss.enrich import (
    build_offset_index,
    is_structured_layout,
    enrich_static_strings,
    static_strings_from_layout,
)
from floss.render import Verbosity
from floss.results import Analysis, Metadata, ResultLayout, ResultDocument
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
    enabled_types: Optional[List[str]] = None
    disabled_types: Optional[List[str]] = None
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


def get_file_type(sample_file_path: Path) -> bytes:
    with sample_file_path.open("rb") as f:
        magic = f.read(4)

    if magic == SUPPORTED_FILE_MAGIC_ELF:
        return SUPPORTED_FILE_MAGIC_ELF
    elif magic[:2] == SUPPORTED_FILE_MAGIC_PE:
        return SUPPORTED_FILE_MAGIC_PE
    else:
        return UNSUPPORTED_FILE_MAGIC


def load_vw(
    sample_path: Path,
    format: str,
    sigpaths: List[Path],
    should_save_workspace: bool = False,
) -> VivWorkspace:
    file_type = get_file_type(sample_path)
    if format not in ("sc32", "sc64"):
        if file_type is UNSUPPORTED_FILE_MAGIC:
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

    if file_type == SUPPORTED_FILE_MAGIC_PE:
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


def _try_layout_static(
    buf: bytes,
    min_length: int,
    enable_tags: bool,
) -> Tuple[Optional[ResultLayout], float]:
    """
    Quantum-style layout extract when PE/ELF/Mach-O parse succeeds.
    Returns serializable ResultLayout (or None to fall back to classic statics)
    along with the elapsed seconds spent in the tag database matching step.

    Any failure after a structured layout is detected (extract/tag/structures/DB)
    also returns None so default-on layout cannot crash the whole run.
    """
    from floss.tags import load_databases, remove_false_positive_lib_strings
    from floss.layout import compute_layout
    from floss.ranges import Slice
    from floss.layout.extract import extract_layout_strings

    tags_elapsed = 0.0
    try:
        file_slice = Slice.from_bytes(buf=buf)
        live = compute_layout(file_slice)

        if not is_structured_layout(live.name):
            logger.debug("no structured layout (got %r); using classic static strings", live.name)
            return None, tags_elapsed

        extract_layout_strings(live, min_length)
        # tag_strings always converts ExtractedString → TaggedString (needed for mark_structures)
        taggers = load_databases() if enable_tags else []
        tags_t0 = time()
        live.tag_strings(taggers)
        tags_elapsed = get_runtime_diff(tags_t0)
        live.mark_structures()
        if enable_tags:
            remove_false_positive_lib_strings(live)

        return ResultLayout.from_layout(live), tags_elapsed
    except Exception as e:
        logger.warning("layout-aware static analysis failed; using classic statics: %s", e)
        return None, tags_elapsed


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
    interim = time0

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

    static_runtime = get_runtime_diff(interim)

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

    enabled = options.enabled_types or []
    disabled = options.disabled_types or []
    if results.metadata.language not in ("", "unknown"):
        if not enabled and not disabled and options.prompt_deobfuscation:
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
        layout_tags_elapsed = 0.0
        # only layout/tag work for static_strings runtime — not language ID or the TTY prompt above
        layout_t0 = time()
        if analysis.enable_layout:
            layout_doc, layout_tags_elapsed = _try_layout_static(sample_buf, options.min_length, analysis.enable_tags)
            results.metadata.runtime.layout = get_runtime_diff(layout_t0)
            results.metadata.runtime.tags = layout_tags_elapsed

        if layout_doc is not None:
            results.layout = layout_doc
            results.strings.static_strings = static_strings_from_layout(layout_doc)
            # classic extraction + layout/tag work (excludes language ID / deobfuscation prompt)
            results.metadata.runtime.static_strings = static_runtime + get_runtime_diff(layout_t0)
        else:
            results.strings.static_strings = static_strings
            results.metadata.runtime.static_strings = static_runtime

        # one offset index for both language_strings and language_strings_missed
        layout_offset_index = None
        if layout_doc is not None and results.metadata.language in (Language.GO.value, Language.RUST.value):
            layout_offset_index = build_offset_index(layout_doc)

        if results.metadata.language == Language.GO.value:
            logger.info("extracting language-specific Go strings")
            interim = time()
            results.strings.language_strings = floss.language.go.extract.extract_go_strings(sample, options.min_length)
            results.metadata.runtime.language_strings = get_runtime_diff(interim)

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
            interim = time()
            results.strings.language_strings = floss.language.rust.extract.extract_rust_strings(
                sample, options.min_length
            )
            results.metadata.runtime.language_strings = get_runtime_diff(interim)

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
                interim = time()
                vw = load_vw(sample, options.format, sigpaths, should_save_workspace)
                results.metadata.runtime.vivisect = get_runtime_diff(interim)
                interim = time()
        except WorkspaceLoadError as e:
            raise PipelineError("failed to analyze sample: %s" % e, exit_code=-1)

        results.metadata.imagebase = get_imagebase(vw)

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
        results.metadata.runtime.find_features = get_runtime_diff(interim)
        interim = time()

        logger.trace("analysis summary:")
        for k, v in get_vivisect_meta_info(vw, selected_functions, decoding_function_features).items():
            logger.trace("  %s: %s", k, v or "N/A")

        if results.analysis.enable_stack_strings:
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
            results.metadata.runtime.stack_strings = get_runtime_diff(interim)
            interim = time()

        if results.analysis.enable_tight_strings:
            tightloop_functions = get_functions_with_tightloops(decoding_function_features)
            results.strings.tight_strings = extract_tightstrings(
                vw,
                tightloop_functions,
                min_length=options.min_length,
                verbosity=options.verbose,
                disable_progress=options.quiet or options.disable_progress,
            )
            results.analysis.functions.analyzed_tight_strings = len(tightloop_functions)
            results.metadata.runtime.tight_strings = get_runtime_diff(interim)
            interim = time()

        if results.analysis.enable_decoded_strings:
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
                    results.analysis.functions.decoding_function_scores[fva] = {"score": score, "xrefs_to": xrefs_to}
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
            results.metadata.runtime.decoded_strings = get_runtime_diff(interim)

    results.metadata.runtime.total = get_runtime_diff(time0)
    logger.info("finished execution after %.2f seconds", results.metadata.runtime.total)

    return results

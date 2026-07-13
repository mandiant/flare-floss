#!/usr/bin/env python3
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

"""
Build OSS string databases from vcpkg static libraries.

This script automates the "vcpkg & jh" technique described in readme.md:

  1. install static libraries via vcpkg
  2. extract string features (and function names) via jh
  3. convert to JSONL and compress with gzip

It is intentionally modular so the underlying extractor (jh today) can be
swapped for a more minimal tool later without rewriting the orchestration.

Strings are NOT deduped across libraries: a string observed in both zlib
and curl (e.g. when zlib is vendored into curl) stays in both databases.
The query tagger already emits one ``#<library>`` tag per matching
database, so the consumer can see the overlap directly. Within a single
library, the same string still collapses to one entry (when
``--no-deduplicate`` is not passed).
"""

from __future__ import annotations

import os
import re
import sys
import time
import gzip
import json
import shutil
import logging
import pathlib
import argparse
import subprocess
from typing import Callable, Set, Dict, List, Tuple, Optional
from dataclasses import dataclass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("build_oss_db")


class BuildError(Exception):
    """Raised when a single library cannot be built; the caller decides whether to abort or continue."""


class UnsupportedPlatformError(BuildError):
    """Raised when a library does not support the target triplet/platform."""


@dataclass(frozen=True)
class BuildConfig:
    triplet: str
    compiler: str
    profile: str
    libraries: List[str]
    output_dir: pathlib.Path
    vcpkg_root: Optional[pathlib.Path]
    jh_path: Optional[pathlib.Path]
    lancelot_dir: Optional[pathlib.Path]
    emit_function_names: bool = True
    deduplicate: bool = True
    continue_on_error: bool = False


def make_db_entry(
    string: str,
    library_name: str,
    library_version: str,
    file_path: Optional[str],
    function_name: Optional[str],
    line_number: Optional[int] = None,
) -> dict:
    """Construct a database entry using the standard OSS schema."""
    return {
        "string": string,
        "library_name": library_name,
        "library_version": library_version,
        "file_path": file_path,
        "function_name": function_name,
        "line_number": line_number,
    }


@dataclass
class ParseResult:
    """Result of parsing jh JSONL output for a single library."""

    entries: List[dict]
    num_objects: int
    num_functions: int


@dataclass
class LibraryMetrics:
    library: str
    version: str
    triplet: str
    num_objects: int = 0
    num_functions: int = 0
    num_string_entries: int = 0
    num_function_name_entries: int = 0
    num_raw_entries: int = 0
    total_entries: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "library": self.library,
            "version": self.version,
            "triplet": self.triplet,
            "num_objects": self.num_objects,
            "num_functions": self.num_functions,
            "num_string_entries": self.num_string_entries,
            "num_function_name_entries": self.num_function_name_entries,
            "num_raw_entries": self.num_raw_entries,
            "total_entries": self.total_entries,
            "duration_seconds": round(self.duration_seconds, 2),
            "error": self.error,
        }


def run(
    cmd: List[str],
    cwd: Optional[pathlib.Path] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a subprocess and return its output."""
    logger.debug("running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            cmd,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


class Vcpkg:
    """Thin wrapper around a vcpkg installation."""

    def __init__(self, vcpkg_root: Optional[pathlib.Path] = None):
        self.exe = self._find_executable(vcpkg_root)
        self.root = self._resolve_root(vcpkg_root)
        self.installed_dir = self.root / "installed"
        self.info_dir = self.installed_dir / "vcpkg" / "info"

    def _find_executable(self, vcpkg_root: Optional[pathlib.Path]) -> pathlib.Path:
        # 1. Executable bundled inside the provided root.
        if vcpkg_root:
            for name in ("vcpkg.exe", "vcpkg"):
                candidate = vcpkg_root / name
                if candidate.exists():
                    return candidate.resolve()

        # 2. Executable on PATH.
        exe = shutil.which("vcpkg")
        if exe:
            return pathlib.Path(exe).resolve()

        # 3. Executable inside VCPKG_ROOT.
        env_root = os.environ.get("VCPKG_ROOT")
        if env_root:
            for name in ("vcpkg.exe", "vcpkg"):
                candidate = pathlib.Path(env_root) / name
                if candidate.exists():
                    return candidate.resolve()

        raise FileNotFoundError("vcpkg not found. Set VCPKG_ROOT or pass --vcpkg-root.")

    def _resolve_root(self, vcpkg_root: Optional[pathlib.Path]) -> pathlib.Path:
        if vcpkg_root:
            return vcpkg_root.resolve()

        env_root = os.environ.get("VCPKG_ROOT")
        if env_root:
            return pathlib.Path(env_root).resolve()

        # The executable normally lives at <vcpkg-root>/vcpkg.
        return self.exe.parent.resolve()

    def install(self, library: str, triplet: str) -> None:
        """Install a library for the given triplet."""
        spec = f"{library}:{triplet}"
        logger.info("vcpkg install %s", spec)
        try:
            run([str(self.exe), "install", spec])
        except subprocess.CalledProcessError as exc:
            output = (exc.stdout or "") + (exc.stderr or "")
            if "is only supported on" in output:
                raise UnsupportedPlatformError(f"{spec} is not supported on this platform") from exc
            raise

    def get_installed_version(self, library: str, triplet: str) -> str:
        """Return the installed version string (e.g. '3.0.7#1')."""
        result = run([str(self.exe), "list", f"{library}:{triplet}"])
        expected_prefix = f"{library}:{triplet}"

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("The following packages are"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            if parts[0] == expected_prefix:
                return parts[1]

        raise BuildError(f"could not determine installed version for {library}:{triplet}")

    def find_package_libs(self, library: str, triplet: str) -> List[pathlib.Path]:
        """Return static-library files (.lib/.a) owned by the given package."""
        # vcpkg records installed files in <root>/installed/vcpkg/info/<package>_<version>_<triplet>.list
        pattern = re.compile(re.escape(library) + r"_.*?_" + re.escape(triplet) + r"\.list$")
        list_files = []
        if self.info_dir.exists():
            list_files = [p for p in self.info_dir.iterdir() if pattern.match(p.name)]

        if not list_files:
            # The .list file is the only authoritative way to know which static
            # libraries belong to this package. vcpkg installs every package's
            # libs into the same shared <triplet>/lib/ directory, so a blind
            # scan of that directory would attribute other packages'
            # strings/functions to this library. Refuse to extract instead of
            # silently polluting the database, and surface the files we would
            # have wrongly included for diagnostics.
            candidate_files = self._find_all_static_libs(triplet)
            logger.error(
                "could not find vcpkg info .list for %s:%s; "
                "refusing to extract to avoid misattributing %d other-package "
                "library file(s): %s",
                library,
                triplet,
                len(candidate_files),
                ", ".join(p.name for p in candidate_files),
            )
            return []

        lib_paths: List[pathlib.Path] = []
        for list_file in list_files:
            for line in list_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith(triplet + "/lib/"):
                    candidate = self.installed_dir / line
                    if candidate.suffix in (".lib", ".a"):
                        lib_paths.append(candidate)

        return sorted(set(lib_paths))

    def _find_all_static_libs(self, triplet: str) -> List[pathlib.Path]:
        lib_dir = self.installed_dir / triplet / "lib"
        if not lib_dir.exists():
            return []
        return sorted(p for p in lib_dir.iterdir() if p.suffix in (".lib", ".a"))


class JHExtractor:
    """Wrapper around the jh binary. Builds it from source if needed."""

    def __init__(
        self,
        jh_path: Optional[pathlib.Path] = None,
        lancelot_dir: Optional[pathlib.Path] = None,
    ):
        self.jh_path = self._resolve(jh_path, lancelot_dir)

    def _resolve(
        self,
        jh_path: Optional[pathlib.Path],
        lancelot_dir: Optional[pathlib.Path],
    ) -> pathlib.Path:
        if jh_path:
            path = pathlib.Path(jh_path).resolve()
            if not path.exists():
                raise FileNotFoundError(f"jh binary not found: {path}")
            return path

        env_path = os.environ.get("JH_PATH")
        if env_path:
            path = pathlib.Path(env_path).resolve()
            if path.exists():
                return path

        if lancelot_dir:
            return self._build(lancelot_dir)

        env_lancelot = os.environ.get("LANCELOT_DIR")
        if env_lancelot:
            return self._build(pathlib.Path(env_lancelot))

        exe = shutil.which("jh")
        if exe:
            return pathlib.Path(exe).resolve()

        raise FileNotFoundError("jh not found. Provide --jh-path, --lancelot-dir, or set JH_PATH.")

    def _build(self, lancelot_dir: pathlib.Path) -> pathlib.Path:
        logger.info("building jh from %s", lancelot_dir)
        run(
            ["cargo", "build", "--release", "-p", "lancelot-bin"],
            cwd=lancelot_dir,
        )
        exe = lancelot_dir / "target" / "release" / "jh"
        if sys.platform == "win32":
            exe = exe.with_suffix(".exe")
        if not exe.exists():
            raise FileNotFoundError(f"jh binary not found after build: {exe}")
        return exe.resolve()

    def extract(
        self,
        lib_path: pathlib.Path,
        library: str,
        version: str,
        triplet: str,
        compiler: str,
        profile: str,
    ) -> str:
        """Run jh on a single static library and return its JSONL output."""
        cmd = [
            str(self.jh_path),
            triplet,
            compiler,
            library,
            version,
            profile,
            str(lib_path),
        ]
        try:
            result = run(cmd)
        except subprocess.CalledProcessError as exc:
            logger.error(
                "jh failed for %s (%s): stdout=%r stderr=%r",
                library,
                lib_path.name,
                exc.stdout,
                exc.stderr,
            )
            raise
        return result.stdout


class Converter:
    """Convert jh JSONL output into a gzip-compressed JSONL database."""

    def __init__(self, emit_function_names: bool = True, deduplicate: bool = True):
        self.emit_function_names = emit_function_names
        self.deduplicate = deduplicate

    def parse(
        self,
        jh_text: str,
        library: str,
        version: str,
    ) -> ParseResult:
        """Parse jh JSONL into entries and tally object/function counts in one pass.

        Within-library dedup is applied to entries if enabled. Object and
        function counts reflect the raw (pre-dedup) input, matching the
        behavior of the previous standalone counter.
        """
        entries: List[dict] = []
        objects: Set[str] = set()
        function_names: Set[str] = set()
        explicit_function_names: Set[str] = set()

        for line in jh_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("skipping malformed JSONL line: %s (%s)", line, exc)
                continue

            file_path = row.get("path")
            function_name = row.get("function")
            feat_type = row.get("type")
            value = row.get("value")

            if not function_name:
                continue

            objects.add(file_path)
            function_names.add(function_name)

            if feat_type == "string":
                entries.append(make_db_entry(value, library, version, file_path, function_name))
            elif feat_type == "function_name":
                # Future-proof: a minimal extractor may emit function names explicitly.
                entries.append(make_db_entry(value, library, version, file_path, value))
                explicit_function_names.add(value)

        # Stock jh does not emit function_name rows, so derive them from the
        # function column. Functions without any string/number/api features
        # will be missed unless the extractor is patched to emit them.
        if self.emit_function_names:
            for fn in function_names - explicit_function_names:
                entries.append(make_db_entry(fn, library, version, None, fn))

        if self.deduplicate:
            # Match loader semantics: one metadata object per unique string.
            seen: dict = {}
            for entry in entries:
                key = entry["string"]
                if key not in seen:
                    seen[key] = entry
            entries = list(seen.values())

        return ParseResult(
            entries=entries,
            num_objects=len(objects),
            num_functions=len(function_names),
        )

    def write(
        self,
        entries: List[dict],
        output_path: pathlib.Path,
    ) -> dict:
        """Write entries to a gzip-compressed JSONL file. Returns counts."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(output_path, "wt", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        num_string_entries = sum(
            1 for e in entries if e["function_name"] is not None and e["function_name"] != e["string"]
        )
        num_function_name_entries = sum(
            1 for e in entries if e["function_name"] is not None and e["function_name"] == e["string"]
        )

        return {
            "num_string_entries": num_string_entries,
            "num_function_name_entries": num_function_name_entries,
            "total_entries": len(entries),
        }


def build_library(
    library: str,
    config: BuildConfig,
    vcpkg: Vcpkg,
    jh: JHExtractor,
    converter: Converter,
) -> Tuple[LibraryMetrics, List[dict]]:
    """Parse a single library's strings. Returns metrics and the deduped entries.

    The returned entries are not yet written to disk; the caller is responsible
    for cross-library deduplication and final file emission.
    """
    start = time.time()
    metrics = LibraryMetrics(
        library=library,
        version="unknown",
        triplet=config.triplet,
    )
    entries: List[dict] = []

    try:
        vcpkg.install(library, config.triplet)
        version = vcpkg.get_installed_version(library, config.triplet)
        metrics.version = version

        lib_paths = vcpkg.find_package_libs(library, config.triplet)
        if not lib_paths:
            logger.info(
                "%s: no static libraries found for %s:%s (likely header-only); skipping extraction",
                library,
                library,
                config.triplet,
            )
        else:
            logger.info(
                "%s: found %d static library file(s): %s",
                library,
                len(lib_paths),
                ", ".join(str(p.name) for p in lib_paths),
            )

        all_jh_parts: List[str] = []
        for lib_path in lib_paths:
            logger.info("%s: extracting strings from %s", library, lib_path.name)
            jh_text = jh.extract(
                lib_path,
                library,
                version,
                config.triplet,
                config.compiler,
                config.profile,
            )
            all_jh_parts.append(jh_text)

        combined_jh_text = "\n".join(all_jh_parts)
        result = converter.parse(combined_jh_text, library, version)
        metrics.num_objects = result.num_objects
        metrics.num_functions = result.num_functions
        entries = result.entries
        metrics.num_raw_entries = len(entries)
    except UnsupportedPlatformError as exc:
        logger.warning("%s: skipping unsupported library (%s)", library, exc)
    except Exception as exc:
        logger.exception("%s: build failed", library)
        metrics.error = f"{type(exc).__name__}: {exc}"
    finally:
        metrics.duration_seconds = time.time() - start

    return metrics, entries


def load_existing_entries(path: pathlib.Path) -> List[dict]:
    """Load entries from an existing OSS database .jsonl.gz.

    Returns an empty list if the file is missing, empty, unreadable, or does
    not contain entries in the expected schema. New keys are silently dropped;
    missing keys are filled with None so the entries can be merged uniformly.
    """
    if not path.exists():
        return []
    try:
        raw = gzip.decompress(path.read_bytes())
    except (OSError, gzip.BadGzipFile, EOFError) as exc:
        logger.warning("could not read existing database %s: %s", path, exc)
        return []

    entries: List[dict] = []
    for line in raw.split(b"\n"):
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("skipping malformed line in %s: %s", path, exc)
            continue
        if not isinstance(row, dict) or "string" not in row:
            continue
        entries.append(
            make_db_entry(
                row.get("string"),
                row.get("library_name"),
                row.get("library_version"),
                row.get("file_path"),
                row.get("function_name"),
                row.get("line_number"),
            )
        )
    return entries


def merge_entries(
    new_entries: List[dict],
    existing_entries: List[dict],
    deduplicate: bool,
) -> List[dict]:
    """Combine new and existing entries, with new taking precedence on conflict.

    When ``deduplicate`` is true the result contains at most one entry per
    unique string value; otherwise the lists are concatenated as-is.
    """
    if not new_entries:
        return list(existing_entries)
    if not existing_entries:
        return list(new_entries)
    if not deduplicate:
        return list(existing_entries) + list(new_entries)

    seen: Dict[str, dict] = {}
    # Iterate new first so that freshly-built entries win on string collisions,
    # which is the right behavior when the underlying library version changes.
    for entry in list(new_entries) + list(existing_entries):
        key = entry["string"]
        if key not in seen:
            seen[key] = entry
    return list(seen.values())


# Max +/-/~ lines per library in the CI log summary (build_diff.txt).
DIFF_MAX_LINES_PER_LIBRARY = 100
# Shorter per-library cap for the PR description body.
DIFF_PR_MAX_LINES_PER_LIBRARY = 20
# Cap individual string values so one long entry does not dominate the diff.
DIFF_STRING_MAX_LEN = 120
# GitHub rejects PR bodies over 65536 codepoints ("Body is too long"). Leave
# headroom for the workflow's static header and a truncation footer.
DIFF_PR_MAX_CHARS = 60_000
# Fields compared when deciding whether an existing string's metadata changed.
_DIFF_META_FIELDS = ("library_version", "file_path", "function_name", "line_number")


def _escape_diff_string(value: Optional[str]) -> str:
    """Make a string safe/readable for a single-line text diff.

    Backticks are separated so string values cannot close markdown code fences.
    """
    if value is None:
        return ""
    backtick = chr(96)  # ASCII backtick character.
    text = (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace(backtick * 3, f"{backtick} {backtick} {backtick}")
    )
    if len(text) > DIFF_STRING_MAX_LEN:
        return text[: DIFF_STRING_MAX_LEN - 3] + "..."
    return text


def _format_meta_value(value: object) -> str:
    if value is None:
        return ""
    return _escape_diff_string(str(value))


def _format_meta_delta(old: dict, new: dict) -> str:
    """Return a short 'field: old -> new' summary for changed metadata fields."""
    parts: List[str] = []
    for field in _DIFF_META_FIELDS:
        old_val, new_val = old.get(field), new.get(field)
        if old_val != new_val:
            parts.append(f"{field}: {_format_meta_value(old_val)} -> {_format_meta_value(new_val)}")
    return "; ".join(parts)


@dataclass
class LibraryDiff:
    """Text-diff summary for one library's database rewrite."""

    library: str
    old_count: int
    new_count: int
    added: List[dict]
    removed: List[dict]
    changed: List[Tuple[dict, dict]]  # (old_entry, new_entry)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def header_line(self) -> str:
        return (
            f"## {self.library}  "
            f"(entries: {self.old_count} -> {self.new_count}; "
            f"+{len(self.added)} -{len(self.removed)} ~{len(self.changed)})"
        )

    def body_lines(self) -> List[str]:
        lines: List[str] = []
        # Sort for stable, reviewable output.
        for entry in sorted(self.added, key=lambda e: e.get("string") or ""):
            lines.append(f"+ {_escape_diff_string(entry.get('string'))}")
        for entry in sorted(self.removed, key=lambda e: e.get("string") or ""):
            lines.append(f"- {_escape_diff_string(entry.get('string'))}")
        for old, new in sorted(self.changed, key=lambda pair: pair[0].get("string") or ""):
            delta = _format_meta_delta(old, new)
            lines.append(f"~ {_escape_diff_string(old.get('string'))}  ({delta})")
        return lines


def diff_library_entries(library: str, old_entries: List[dict], new_entries: List[dict]) -> LibraryDiff:
    """Compare two entry lists for one library and return a structured diff.

    Entries are keyed by their ``string`` value (matching merge/dedup
    semantics). Added/removed strings get ``+``/``-`` lines; same string with
    different metadata gets a ``~`` line.
    """
    old_by_string: Dict[str, dict] = {}
    for entry in old_entries:
        key = entry.get("string")
        if key is not None and key not in old_by_string:
            old_by_string[key] = entry

    new_by_string: Dict[str, dict] = {}
    for entry in new_entries:
        key = entry.get("string")
        if key is not None and key not in new_by_string:
            new_by_string[key] = entry

    old_keys = set(old_by_string)
    new_keys = set(new_by_string)

    added = [new_by_string[k] for k in new_keys - old_keys]
    removed = [old_by_string[k] for k in old_keys - new_keys]
    changed: List[Tuple[dict, dict]] = []
    for key in old_keys & new_keys:
        old, new = old_by_string[key], new_by_string[key]
        if any(old.get(field) != new.get(field) for field in _DIFF_META_FIELDS):
            changed.append((old, new))

    return LibraryDiff(
        library=library,
        old_count=len(old_entries),
        new_count=len(new_entries),
        added=added,
        removed=removed,
        changed=changed,
    )


def _truncated_body_lines(body: List[str], max_lines: int, library: str) -> List[str]:
    """Keep at most ``max_lines`` change lines; append a truncation note if needed."""
    if len(body) <= max_lines:
        return body
    omitted = len(body) - max_lines
    return body[:max_lines] + [f"... truncated ({omitted} more line(s) omitted for {library})"]


def format_build_diff(
    library_diffs: List[LibraryDiff],
    max_lines_per_library: int = DIFF_MAX_LINES_PER_LIBRARY,
) -> str:
    """Render library diffs as a plain-text report, truncated per library.

    Each library section keeps its header plus at most ``max_lines_per_library``
    change lines (``+``/``-``/``~``). A trailing note is added when a library's
    body is cut off. Intended for the capped CI log summary (``build_diff.txt``).
    """
    if max_lines_per_library < 1:
        return ""

    if not library_diffs:
        return "No libraries were rebuilt.\n"

    changed = [d for d in library_diffs if d.has_changes]
    if not changed:
        return "No entry-level changes detected.\n"

    lines: List[str] = [
        "OSS string database entry-level diff",
        f"(libraries with changes: {len(changed)}/{len(library_diffs)})",
        "",
    ]
    for diff in changed:
        lines.append(diff.header_line())
        lines.extend(_truncated_body_lines(diff.body_lines(), max_lines_per_library, diff.library))
        lines.append("")

    # Drop trailing blank line.
    while lines and lines[-1] == "":
        lines.pop()

    return "\n".join(lines) + "\n"


def _omission_footer(omitted: List[str]) -> str:
    """Short note listing libraries dropped to stay under the PR body size cap."""
    if not omitted:
        return ""
    if len(omitted) <= 10:
        names = ", ".join(omitted)
    else:
        names = ", ".join(omitted[:8]) + f", ... (+{len(omitted) - 8} more)"
    return (
        f"\n... omitted {len(omitted)} more libraries with changes ({names}).\n"
        "See `build_diff.txt` in the workflow logs for the capped CI summary.\n"
    )


def _clip_to_max_chars(text: str, max_chars: int) -> str:
    """Hard-cap ``text`` at ``max_chars``, appending a short notice if clipped."""
    if max_chars < 1:
        return ""
    if len(text) <= max_chars:
        return text
    notice = "\n... truncated to stay under GitHub's PR body length limit.\n"
    if len(notice) >= max_chars:
        return notice[:max_chars]

    limit = max_chars - len(notice)
    truncated = text[:limit]
    fence = chr(96) * 3  # Markdown fenced code-block delimiter.
    if truncated.count(fence) % 2:
        closing_fence = "\n" + fence
        if limit >= len(closing_fence):
            truncated = text[: limit - len(closing_fence)].rstrip() + closing_fence
        else:
            # A closing fence does not fit; omit the unmatched opening fence.
            truncated = truncated[: truncated.rfind(fence)]
    return truncated.rstrip() + notice


def format_build_diff_markdown(
    library_diffs: List[LibraryDiff],
    max_lines_per_library: int = DIFF_PR_MAX_LINES_PER_LIBRARY,
    max_chars: int = DIFF_PR_MAX_CHARS,
) -> str:
    """Render library diffs as markdown for a GitHub PR description.

    Each library gets a ``##`` heading outside its own fenced diff code block
    that contains only the ``+``/``-``/``~`` change lines (truncated per library).

    The whole report is also capped at ``max_chars`` so the PR body stays under
    GitHub's 65536-character limit (with headroom for the workflow header).
    Libraries that do not fit are summarized in a trailing note; the capped CI
    log summary remains in ``build_diff.txt`` / workflow logs.
    """
    if max_lines_per_library < 1 or max_chars < 1:
        return ""

    if not library_diffs:
        return "No libraries were rebuilt.\n"

    changed = [d for d in library_diffs if d.has_changes]
    if not changed:
        return "No entry-level changes detected.\n"

    sections: List[str] = []
    omitted: List[str] = []

    for i, diff in enumerate(changed):
        body = _truncated_body_lines(diff.body_lines(), max_lines_per_library, diff.library)
        # Heading outside the fence; only +/-/~ (and optional truncation note) inside.
        section = "\n".join(
            [
                f"## {diff.library}",
                "",
                f"entries: {diff.old_count} -> {diff.new_count}; "
                f"+{len(diff.added)} -{len(diff.removed)} ~{len(diff.changed)}",
                "",
                "```diff",
                *body,
                "```",
                "",
            ]
        )
        remaining = [d.library for d in changed[i + 1 :]]
        footer = _omission_footer(remaining)
        candidate_text = "\n".join([*sections, section]).rstrip() + "\n" + footer
        if len(candidate_text) > max_chars:
            if sections:
                omitted = [d.library for d in changed[i:]]
                break
            # First section alone may still exceed the cap; hard-cut it.
            section_budget = max_chars - len(footer) if footer else max_chars
            cut = _clip_to_max_chars(section, max(1, section_budget))
            sections.append(cut if cut.endswith("\n") else cut + "\n")
            omitted = [d.library for d in remaining]
            break
        sections.append(section)

    text = "\n".join(sections).rstrip() + "\n"
    if omitted:
        text += _omission_footer(omitted)
    return _clip_to_max_chars(text, max_chars)


def write_library_database(
    metrics: LibraryMetrics,
    entries: List[dict],
    output_dir: pathlib.Path,
    converter: Converter,
) -> LibraryMetrics:
    """Write the per-library JSONL.gz and update metrics. Returns metrics."""
    output_path = output_dir / f"{metrics.library}.jsonl.gz"

    if not entries:
        if output_path.exists():
            output_path.unlink()
        logger.info("%s: removed empty database %s", metrics.library, output_path)
        metrics.num_string_entries = 0
        metrics.num_function_name_entries = 0
        metrics.total_entries = 0
        return metrics

    counts = converter.write(entries, output_path)
    metrics.num_string_entries = counts["num_string_entries"]
    metrics.num_function_name_entries = counts["num_function_name_entries"]
    metrics.total_entries = counts["total_entries"]
    logger.info(
        "%s: wrote %s (%d entries)",
        metrics.library,
        output_path,
        metrics.total_entries,
    )
    return metrics


def run_build(
    config: BuildConfig,
    vcpkg: Vcpkg,
    jh: JHExtractor,
    converter: Converter,
    build_library_fn: Callable[
        [str, BuildConfig, Vcpkg, JHExtractor, Converter], Tuple[LibraryMetrics, List[dict]]
    ] = build_library,
) -> int:
    """Build and write databases for the configured libraries.

    This is split out from `main()` so tests can inject fakes directly without
    monkeypatching module globals.
    """
    config.output_dir.mkdir(parents=True, exist_ok=True)

    metrics: List[LibraryMetrics] = []
    per_library_new: Dict[str, List[dict]] = {}
    failed = False
    for library in config.libraries:
        metric, entries = build_library_fn(library, config, vcpkg, jh, converter)
        metrics.append(metric)
        # Even on error, preserve any partial entries so they aren't lost.
        per_library_new[library] = entries
        if metric.error:
            failed = True
            if not config.continue_on_error:
                break

    # Discover all existing .jsonl.gz databases in the output directory. These
    # include libraries we are rebuilding (whose fresh entries will be merged
    # in) and libraries we are leaving alone. Strings are NOT deduped across
    # libraries: a string that appears in both zlib and curl (e.g. when zlib
    # is vendored into curl) stays in both databases. The query tagger already
    # emits one #library tag per matching database, so the consumer can see
    # the overlap directly.
    existing_files = sorted(config.output_dir.glob("*.jsonl.gz"))

    def _lib_name_from_path(p: pathlib.Path) -> str:
        # p.name looks like "<lib>.jsonl.gz"; Path.stem would only strip ".gz".
        suffix = ".jsonl.gz"
        if p.name.endswith(suffix):
            return p.name[: -len(suffix)]
        return p.stem

    # Snapshot pre-merge contents for rebuilt libraries so we can emit a
    # human-readable text diff after writing (gzipped JSONL is opaque in PRs).
    existing_by_lib: Dict[str, List[dict]] = {}
    merged: Dict[str, List[dict]] = {}
    for path in existing_files:
        lib = _lib_name_from_path(path)
        existing = load_existing_entries(path)
        existing_by_lib[lib] = existing
        if lib in per_library_new:
            merged[lib] = merge_entries(per_library_new[lib], existing, config.deduplicate)
        elif existing:
            merged[lib] = existing

    # Libraries being built for the first time (no pre-existing file).
    for lib, new_entries in per_library_new.items():
        if lib not in merged:
            merged[lib] = list(new_entries)

    # Write rebuilt libraries, update their metrics, and collect entry diffs.
    library_diffs: List[LibraryDiff] = []
    for metric in metrics:
        if metric.error:
            logger.warning("%s: skipping database write due to build error", metric.library)
            continue
        entries = merged.get(metric.library, [])
        old_entries = existing_by_lib.get(metric.library, [])
        library_diffs.append(diff_library_entries(metric.library, old_entries, entries))
        write_library_database(metric, entries, config.output_dir, converter)

    summary = {
        "triplet": config.triplet,
        "compiler": config.compiler,
        "profile": config.profile,
        "libraries": [m.as_dict() for m in metrics],
        "successful": sum(1 for m in metrics if not m.error),
        "failed": sum(1 for m in metrics if m.error),
    }

    metrics_path = config.output_dir / "build_metrics.json"
    metrics_path.write_text(json.dumps(summary, indent=2))
    logger.info("wrote metrics to %s", metrics_path)

    # Capped CI log summary (up to 100 change lines per library).
    diff_text = format_build_diff(library_diffs, max_lines_per_library=DIFF_MAX_LINES_PER_LIBRARY)
    diff_path = config.output_dir / "build_diff.txt"
    diff_path.write_text(diff_text, encoding="utf-8")
    logger.info("wrote entry-level diff to %s", diff_path)

    # Markdown report for the GitHub PR description: ## heading per library,
    # each with its own ```diff fence (20 change lines per library).
    pr_diff_text = format_build_diff_markdown(library_diffs, max_lines_per_library=DIFF_PR_MAX_LINES_PER_LIBRARY)
    pr_diff_path = config.output_dir / "build_diff_pr.txt"
    pr_diff_path.write_text(pr_diff_text, encoding="utf-8")
    logger.info("wrote PR entry-level diff to %s", pr_diff_path)

    # Log a short preview so local/CI logs also surface the change.
    for line in pr_diff_text.splitlines()[:30]:
        logger.info("diff: %s", line)
    if pr_diff_text.count("\n") > 30:
        logger.info("diff: ... (see %s / %s for full reports)", diff_path, pr_diff_path)

    if failed:
        successful = sum(1 for m in metrics if not m.error)
        if config.continue_on_error and successful > 0:
            # Partial success: --continue-on-error let us build some libraries.
            # The CI will pick up the updated databases and a follow-up run can
            # retry the failed ones.
            logger.warning(
                "%d/%d libraries failed; exiting 0 because --continue-on-error is set",
                failed,
                len(metrics),
            )
            return 0
        # Either --continue-on-error was not set, or every library failed. In
        # the latter case we cannot let the workflow step go green: nothing was
        # produced, so a missing build (broken vcpkg, wrong jh path, etc.)
        # would be silent.
        logger.error(
            "one or more libraries failed to build (failed=%d, total=%d)",
            failed,
            len(metrics),
        )
        return 1
    return 0


def load_config(path: pathlib.Path) -> dict:
    """Load build configuration from a JSON file."""
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"config file {path} must contain a JSON object")
    return data


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    # First pass: figure out if a config file was provided.
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", type=pathlib.Path, default=None)
    pre_args, _ = pre_parser.parse_known_args(argv)

    config: dict = {}
    if pre_args.config:
        config = load_config(pre_args.config)
    elif "CONFIG" in os.environ:
        config = load_config(pathlib.Path(os.environ["CONFIG"]))

    # Defaults are taken from (lowest to highest precedence):
    #   built-in constants < config file < environment variables < CLI args
    defaults = {
        "triplet": config.get("triplet"),
        "compiler": config.get("compiler"),
        "profile": config.get("profile"),
        "libraries": config.get("libraries"),
    }

    parser = argparse.ArgumentParser(
        description="Build OSS string databases from vcpkg libraries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[pre_parser],
    )
    parser.set_defaults(**defaults)
    parser.add_argument(
        "--triplet",
        help="vcpkg triplet",
    )
    parser.add_argument(
        "--compiler",
        help="compiler label passed to jh",
    )
    parser.add_argument(
        "--profile",
        help="build profile label passed to jh",
    )
    parser.add_argument(
        "--libraries",
        nargs="+",
        help="libraries to build",
    )
    parser.add_argument(
        "--output-dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).parent,
        help="directory for generated .jsonl.gz files and metrics",
    )
    parser.add_argument(
        "--vcpkg-root",
        type=pathlib.Path,
        default=os.environ.get("VCPKG_ROOT", None),
        help="vcpkg installation root",
    )
    parser.add_argument(
        "--jh-path",
        type=pathlib.Path,
        default=os.environ.get("JH_PATH", None),
        help="path to an existing jh binary",
    )
    parser.add_argument(
        "--lancelot-dir",
        type=pathlib.Path,
        default=os.environ.get("LANCELOT_DIR", None),
        help="directory containing lancelot source; jh will be built if --jh-path is not given",
    )
    parser.add_argument(
        "--no-function-names",
        action="store_true",
        help="do not emit function-name-as-string entries",
    )
    parser.add_argument(
        "--no-deduplicate",
        action="store_true",
        help="emit one JSON object per JSONL row instead of one per unique string",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="continue building remaining libraries if one fails and exit successfully",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging level",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.getLogger().setLevel(args.log_level.upper())

    config = BuildConfig(
        triplet=args.triplet,
        compiler=args.compiler,
        profile=args.profile,
        libraries=[lib.strip() for lib in args.libraries if lib.strip()],
        output_dir=args.output_dir.resolve(),
        vcpkg_root=args.vcpkg_root.resolve() if args.vcpkg_root else None,
        jh_path=args.jh_path.resolve() if args.jh_path else None,
        lancelot_dir=args.lancelot_dir.resolve() if args.lancelot_dir else None,
        emit_function_names=not args.no_function_names,
        deduplicate=not args.no_deduplicate,
        continue_on_error=args.continue_on_error,
    )

    logger.info("configuration: %s", config)

    vcpkg = Vcpkg(config.vcpkg_root)
    jh = JHExtractor(config.jh_path, config.lancelot_dir)
    converter = Converter(
        emit_function_names=config.emit_function_names,
        deduplicate=config.deduplicate,
    )

    return run_build(config, vcpkg, jh, converter)


if __name__ == "__main__":
    sys.exit(main())

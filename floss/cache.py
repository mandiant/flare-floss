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

"""Result-document caching for repeated FLOSS analyses.

The full ResultDocument is cached on first execution and reused on later runs,
so repeated analyses of the same sample are fast. The cache is keyed by the
SHA-256 of the sample bytes plus the FLOSS version, and stores the same JSON
schema emitted by ``--json``.

Caching applies to binary sample analysis only: loading a user-supplied JSON
document never writes to the cache.

The cache directory defaults to the platform cache directory and can be
overridden with ``FLOSS_CACHE_DIR``. Caching can be disabled entirely by
setting ``FLOSS_CACHE_ENABLE=0``, and a single run can be forced to
re-analyze and overwrite its entry with ``FLOSS_CACHE_REFRESH=1``.
"""

from __future__ import annotations

import os
import sys
import tempfile
from typing import Optional
from pathlib import Path

from platformdirs import user_cache_dir

import floss.logging_
import floss.render.json
from floss.results import (
    STRING_TYPE_FIELDS,
    Analysis,
    ResultLayout,
    ResultDocument,
    filter_string_len,
    check_set_string_types,
)

logger = floss.logging_.getLogger(__name__)

ENV_CACHE_DIR = "FLOSS_CACHE_DIR"
ENV_CACHE_ENABLE = "FLOSS_CACHE_ENABLE"
ENV_CACHE_REFRESH = "FLOSS_CACHE_REFRESH"

# values that disable caching, so FLOSS_CACHE_ENABLE=0 behaves as documented
_DISABLED_VALUES = ("0", "false", "no", "n", "")
# values that force a re-analysis, so FLOSS_CACHE_REFRESH=1 behaves as documented
_ENABLED_VALUES = ("1", "true", "yes", "y")


def cache_enabled() -> bool:
    """Whether result caching is enabled.

    ``FLOSS_CACHE_ENABLE`` disables caching when set to 0 (or false/no/n);
    caching is enabled by default.
    """
    return os.environ.get(ENV_CACHE_ENABLE, "1") not in _DISABLED_VALUES


def cache_refresh() -> bool:
    """Whether the current run should bypass the cache and overwrite its entry.

    ``FLOSS_CACHE_REFRESH=1`` (or true/yes/y) forces a re-analysis: the cached
    document is ignored and the fresh result is stored on top of it. Unset by
    default.
    """
    return os.environ.get(ENV_CACHE_REFRESH, "") in _ENABLED_VALUES


def get_cache_dir() -> Path:
    """Resolve the analysis cache directory.

    ``FLOSS_CACHE_DIR`` overrides the platform default cache directory:
      - Linux:   ``$XDG_CACHE_HOME/floss`` (or ``~/.cache/floss``)
      - macOS:   ``~/Library/Caches/floss``
      - Windows: ``%LOCALAPPDATA%\\floss\\Cache``
    """
    override = os.environ.get(ENV_CACHE_DIR)
    if override:
        return Path(override)
    return Path(user_cache_dir("floss"))


def compute_key(sha256: str, version: str) -> str:
    """The cache key: content-addressed sample hash + FLOSS version."""
    return f"{sha256}-{version}"


def cache_file_path(cache_dir: Path, key: str) -> Path:
    """The on-disk location of a cache entry: ``{cache_dir}/{key}.json``."""
    return cache_dir / f"{key}.json"


def load(cache_dir: Path, key: str, sha256: str, version: str) -> Optional[ResultDocument]:
    """Load and validate a cached document, or None on a miss.

    On a parse failure or a checksum or version mismatch the entry is dropped
    so the caller re-analyzes and stores a fresh document.
    """
    path = cache_file_path(cache_dir, key)
    if not path.is_file():
        return None

    try:
        doc = ResultDocument.parse_file(path)
    except (OSError, UnicodeDecodeError, ValueError) as e:
        logger.warning("dropping invalid cache entry %s: %s", path.name, e)
        _drop_cache_entry(path)
        return None

    if doc.metadata.sha256 != sha256 or doc.metadata.version != version:
        logger.warning("dropping stale cache entry %s (checksum/version mismatch)", path.name)
        _drop_cache_entry(path)
        return None

    return doc


def _drop_cache_entry(path: Path) -> None:
    """Best-effort removal of a stale cache entry; never raises.

    The entry may be held open by another reader or an antivirus scanner (e.g.
    on Windows), so removal can fail with a PermissionError. Leave it and let
    the caller continue.
    """
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        logger.warning("could not remove cache entry %s: %s", path.name, e)


def store(cache_dir: Path, key: str, doc: ResultDocument) -> bool:
    """Atomically write a result document to the cache.

    The write is guarded by a lock file so concurrent first runs cannot corrupt
    the entry. When the lock cannot be acquired, caching is skipped and False is
    returned (the caller decides how to warn).
    """
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("could not create cache directory %s: %s; skipping cache write", cache_dir, e)
        return False

    lock_path = cache_dir / f"{key}.lock"
    lock_fd = _acquire_lock(lock_path)
    if lock_fd is None:
        logger.warning("could not acquire cache lock %s; skipping cache write", lock_path)
        return False

    try:
        return _write_atomic(cache_dir, key, floss.render.json.render(doc))
    finally:
        _release_lock(lock_fd, lock_path)


def _write_atomic(cache_dir: Path, key: str, payload: str) -> bool:
    """Atomically write ``{key}.json`` into the cache, or False on any OS failure.

    The payload is written to a temporary file in the cache directory and then
    renamed into place. Cache writes are best-effort: a failure (disk full, an
    unwritable cache directory, the destination held open by an antivirus
    scanner or another reader, etc.) must not crash the analysis, so it is
    logged and caching is skipped.
    """
    try:
        fd, tmp_name = tempfile.mkstemp(dir=str(cache_dir), prefix=f"{key}.", suffix=".tmp")
    except OSError as e:
        logger.warning("could not create temporary cache file in %s: %s; skipping cache write", cache_dir, e)
        return False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp_name, cache_file_path(cache_dir, key))
        return True
    except OSError as e:
        logger.warning("could not store cache entry %s: %s; skipping cache write", key, e)
        return False
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def covers(cached: ResultDocument, wanted: Analysis, min_length: int) -> bool:
    """Whether a cached document satisfies the requested analysis.

    Every string type the user wants enabled must be present in the cached
    document, and the requested ``--minimum-length`` must not be below what the
    document was built with (shorter strings were dropped at extraction time
    and cannot be recovered). Layout and tags are not part of the match: a
    cached layout/tags document can satisfy a request without them because
    `materialize()` drops the layout and redacts the tags when they are not
    wanted. The reverse (requesting layout/tags the cache was not built with) is
    a miss.
    """
    for field in STRING_TYPE_FIELDS:
        if getattr(wanted, field) and not getattr(cached.analysis, field):
            return False

    if wanted.enable_layout and not cached.analysis.enable_layout:
        return False
    if wanted.enable_tags and not cached.analysis.enable_tags:
        return False

    if min_length < cached.metadata.min_length:
        return False

    return True


def materialize(doc: ResultDocument, sample: Path, analysis: Analysis, min_length: int) -> ResultDocument:
    """Apply the same post-load filtering as loading a user-supplied JSON document.

    Rendering flags (--query, --columns, --max-strings, and the tag and section
    filters) apply at render time, so they work unchanged on cached results.
    """
    doc.metadata.file_path = str(sample)
    check_set_string_types(doc, analysis)
    doc.analysis.enable_layout = analysis.enable_layout
    doc.analysis.enable_tags = analysis.enable_tags
    # mirror a fresh run: a disabled string type is absent from the document,
    # not merely flagged. a cache hit must not emit data the user excluded.
    if not analysis.enable_static_strings:
        doc.strings.static_strings = []
        doc.layout = None
    if not analysis.enable_stack_strings:
        doc.strings.stack_strings = []
    if not analysis.enable_tight_strings:
        doc.strings.tight_strings = []
    if not analysis.enable_decoded_strings:
        doc.strings.decoded_strings = []
    if not analysis.enable_language_strings:
        doc.strings.language_strings = []
        doc.strings.language_strings_missed = []
    if not analysis.enable_layout:
        doc.layout = None
    if not analysis.enable_tags:
        _clear_tags(doc)
    filter_string_len(doc, min_length)
    # mirror a fresh run: the requested -n is what the document reports, so
    # --json does not advertise a looser extraction threshold than it holds
    doc.metadata.min_length = min_length
    return doc


def _clear_tags(doc: ResultDocument) -> None:
    """Redact tag classifications from a document (tags-off requests)."""
    for s in doc.strings.static_strings:
        s.tags.clear()
    for s in doc.strings.language_strings:
        s.tags.clear()
    for s in doc.strings.language_strings_missed:
        s.tags.clear()
    _clear_layout_tags(doc.layout)


def _clear_layout_tags(layout: Optional[ResultLayout]) -> None:
    if layout is None:
        return
    for s in layout.strings:
        s.tags.clear()
    for child in layout.children:
        _clear_layout_tags(child)


def _acquire_lock(lock_path: Path) -> Optional[int]:
    """Acquire an exclusive lock on the given lock file, non-blocking.

    Returns the open file descriptor when the lock is held, or None when
    another process holds it.
    """
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        return None

    try:
        if sys.platform == "win32":
            import msvcrt

            # msvcrt.locking cannot lock a byte range past EOF, so ensure the
            # lock file has at least one byte before taking the lock.
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None

    return fd


def _release_lock(fd: int, lock_path: Path) -> None:
    """Release a lock previously acquired by `_acquire_lock()`."""
    if sys.platform == "win32":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    os.close(fd)
    # the lock is never contended: acquire is non-blocking and skips on failure,
    # so no other process can be waiting on the file we just released. unlink it
    # to keep the cache directory clean.
    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass

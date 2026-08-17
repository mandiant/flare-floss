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
setting ``FLOSS_CACHE_ENABLE=0``.
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
    ResultDocument,
    filter_string_len,
    check_set_string_types,
)

logger = floss.logging_.getLogger(__name__)

ENV_CACHE_DIR = "FLOSS_CACHE_DIR"
ENV_CACHE_ENABLE = "FLOSS_CACHE_ENABLE"

# values that disable caching, so FLOSS_CACHE_ENABLE=0 behaves as documented
_DISABLED_VALUES = ("0", "false", "no", "n", "")


def cache_enabled() -> bool:
    """Whether result caching is enabled.

    ``FLOSS_CACHE_ENABLE`` disables caching when set to 0 (or false/no/n);
    caching is enabled by default.
    """
    return os.environ.get(ENV_CACHE_ENABLE, "1") not in _DISABLED_VALUES


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
        path.unlink(missing_ok=True)
        return None

    if doc.metadata.sha256 != sha256 or doc.metadata.version != version:
        logger.warning("dropping stale cache entry %s (checksum/version mismatch)", path.name)
        path.unlink(missing_ok=True)
        return None

    return doc


def store(cache_dir: Path, key: str, doc: ResultDocument) -> bool:
    """Atomically write a result document to the cache.

    The write is guarded by a lock file so concurrent first runs cannot corrupt
    the entry. When the lock cannot be acquired, caching is skipped and False is
    returned (the caller decides how to warn).
    """
    cache_dir.mkdir(parents=True, exist_ok=True)

    lock_path = cache_dir / f"{key}.lock"
    lock_fd = _acquire_lock(lock_path)
    if lock_fd is None:
        logger.warning("could not acquire cache lock %s; skipping cache write", lock_path)
        return False

    try:
        payload = floss.render.json.render(doc)
        fd, tmp_name = tempfile.mkstemp(dir=str(cache_dir), prefix=f"{key}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp_name, cache_file_path(cache_dir, key))
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
    finally:
        _release_lock(lock_fd, lock_path)

    return True


def covers(cached: ResultDocument, wanted: Analysis, min_length: int) -> bool:
    """Whether a cached document satisfies the requested analysis.

    Every string type the user wants enabled must be present in the cached
    document, the layout/tags preference must match, and the requested
    ``--minimum-length`` must not be below what the document was built with
    (shorter strings were dropped at extraction time and cannot be recovered).
    """
    for field in STRING_TYPE_FIELDS:
        if getattr(wanted, field) and not getattr(cached.analysis, field):
            return False

    if wanted.enable_layout and not cached.analysis.enable_layout:
        return False
    if not wanted.enable_layout and cached.layout is not None:
        return False
    if wanted.enable_tags and not cached.analysis.enable_tags:
        return False
    if not wanted.enable_tags and cached.analysis.enable_tags:
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
    filter_string_len(doc, min_length)
    return doc


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
    """Release a lock previously acquired by :func:`_acquire_lock`."""
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

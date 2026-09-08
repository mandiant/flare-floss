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

"""String tagging: tag sources, layout-derived checks, and visibility filters.

Modules like ``expert``, ``gp``, ``oss``, and ``winapi`` are *tag sources* — they
load on-disk classification databases and expose query interfaces. ``engine`` wires
those into ``Tagger`` callables, including layout-derived tags (#code, etc.).
"""

from __future__ import annotations

import pathlib


def data_root() -> pathlib.Path:
    """Shipped tag databases under floss/tags/data."""
    return pathlib.Path(__file__).resolve().parent / "data"


# the first line of a Git LFS pointer file; used to detect unpulled databases
LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/"


def ensure_not_lfs_pointer(path: pathlib.Path) -> None:
    """Raise a clear error when a tag database file is an unpulled Git LFS pointer.

    Without ``git lfs pull`` the LFS-tracked database files are tiny text
    pointers, which the loaders otherwise fail on with confusing gzip/msgspec
    errors.
    """
    try:
        with path.open("rb") as f:
            head = f.read(len(LFS_POINTER_PREFIX))
    except OSError:
        return
    if head == LFS_POINTER_PREFIX:
        raise ValueError(f"Git LFS pointer detected in {path.name}; please run `git lfs pull`")


from floss.tags.engine import (
    Tagger,
    load_databases,
    query_code_string_database,
    query_winapi_name_database,
    query_expert_string_database,
    query_library_string_database,
    query_global_prevalence_database,
    query_global_prevalence_hash_database,
)
from floss.tags.filter import (
    TagRules,
    should_hide_string,
    hide_strings_by_rules,
    remove_false_positive_lib_strings,
)

load_taggers = load_databases


def tag_classic_strings(strings, taggers) -> None:
    from floss.tags.filter import DEFAULT_FILENAMES

    for s in strings:
        tags = set(s.tags)
        for tagger in taggers:
            # Taggers check s.string or string.string (if they use ExtractedString typing),
            # but they just access the object's string property at runtime.
            tags.update(tagger(s))
        s.tags[:] = list(tags)

    # remove false positive lib strings
    for filename in DEFAULT_FILENAMES:
        libname = filename.partition(".")[0]
        tagname = f"#{libname}"

        count = sum(1 for string in strings if tagname in string.tags)

        if 0 < count < 5:
            for string in strings:
                if tagname in string.tags:
                    string.tags.remove(tagname)

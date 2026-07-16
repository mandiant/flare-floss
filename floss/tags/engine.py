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

"""Tagger callables and database loading."""

from __future__ import annotations

import pathlib
import functools
from typing import TYPE_CHECKING, Set, Dict, List, Tuple, Callable, Iterable, Optional, Sequence

import floss.tags.gp
import floss.tags.oss
import floss.tags.expert
import floss.tags.winapi
from floss.ranges import OffsetRanges
from floss.tags.gp import StringHashDatabase, StringGlobalPrevalenceDatabase
from floss.tags.oss import OpenSourceStringDatabase
from floss.tags.expert import ExpertStringDatabase
from floss.tags.winapi import WindowsApiStringDatabase

if TYPE_CHECKING:
    from floss.layout.types import ExtractedString

Tag = str
Tagger = Callable[["ExtractedString"], Sequence[Tag]]


def check_is_xor(xor_key: int | None) -> Sequence[Tag]:
    if isinstance(xor_key, int):
        return ("#decoded",)
    return ()


def check_is_reloc(reloc_offsets: OffsetRanges, string: ExtractedString) -> Sequence[Tag]:
    if reloc_offsets.overlaps(string.slice.range.offset, string.slice.range.end - 1):
        return ("#reloc",)
    return ()


def check_is_code(code_offsets: OffsetRanges, string: ExtractedString) -> Sequence[Tag]:
    if code_offsets.overlaps(string.slice.range.offset, string.slice.range.end - 1):
        return ("#code",)
    return ()


def query_code_string_database(db: StringGlobalPrevalenceDatabase, string: str):
    if db.query(string):
        return ("#code-junk",)

    return ()


def query_global_prevalence_database(db: StringGlobalPrevalenceDatabase, string: str):
    if db.query(string):
        return ("#common",)

    return ()


def query_global_prevalence_hash_database(db: StringHashDatabase, string: str):
    if string in db:
        return ("#common",)

    return ()


def query_library_string_database(db: OpenSourceStringDatabase, string: str) -> Sequence[Tag]:
    meta = db.metadata_by_string.get(string)
    if not meta:
        return ()

    return (f"#{meta.library_name}",)


def query_expert_string_database(db: ExpertStringDatabase, string: str) -> Sequence[Tag]:
    return tuple(db.query(string))


def query_winapi_name_database(db: WindowsApiStringDatabase, string: str) -> Sequence[Tag]:
    if string.lower() in db.dll_names:
        return ("#winapi",)

    if string in db.api_names:
        return ("#winapi",)

    return ()


def load_databases() -> Sequence[Tagger]:
    ret = []

    def query_database(db, queryfn, string: ExtractedString):
        return queryfn(db, string.string)

    def make_tagger(db, queryfn) -> Tagger:
        return functools.partial(query_database, db, queryfn)

    for db in floss.tags.winapi.get_default_databases():
        ret.append(make_tagger(db, query_winapi_name_database))

    for db_expert in floss.tags.expert.get_default_databases():
        ret.append(make_tagger(db_expert, query_expert_string_database))

    for db_oss in floss.tags.oss.get_default_databases():
        ret.append(make_tagger(db_oss, query_library_string_database))

    for db_gp in floss.tags.gp.get_default_databases():
        if isinstance(db_gp, StringGlobalPrevalenceDatabase):
            ret.append(make_tagger(db_gp, query_global_prevalence_database))
        elif isinstance(db_gp, StringHashDatabase):
            ret.append(make_tagger(db_gp, query_global_prevalence_hash_database))
        else:
            raise ValueError(f"unexpected database type: {type(db_gp)}")

    # supplement code analysis with a database of junk code strings
    junk_db = StringGlobalPrevalenceDatabase.from_file(
        pathlib.Path(__file__).resolve().parents[1] / "qs" / "db" / "data" / "gp" / "junk-code.jsonl.gz"
    )
    ret.append(make_tagger(junk_db, query_code_string_database))

    return ret

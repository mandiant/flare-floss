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

import json
import dataclasses

import floss.tags.gp
from floss.tags import data_root
from scripts.tags.generate_gp_db import generate_gp_db
from scripts.tags.extract_strings import PeStrings, FileString


def test_load_db():
    path = data_root() / "gp" / "gp.jsonl.gz"
    db = floss.tags.gp.StringGlobalPrevalenceDatabase.from_file(path)

    assert len(db) > 0  # 21 entries at time of writing


def test_query_db():
    path = data_root() / "gp" / "gp.jsonl.gz"
    db = floss.tags.gp.StringGlobalPrevalenceDatabase.from_file(path)
    res = db.metadata_by_string["!This program cannot be run in DOS mode."]

    assert len(res) == 1
    s = res[0]

    assert s is not None
    assert s.string == "!This program cannot be run in DOS mode."
    assert s.encoding == "ascii"
    assert s.global_count == 424466
    assert s.location == None


def test_load_hash_db():
    path = data_root() / "gp" / "xaa-hashes.bin"
    db = floss.tags.gp.StringHashDatabase.from_file(path)

    assert len(db) > 0


def test_query_hash_db():
    path = data_root() / "gp" / "xaa-hashes.bin"
    db = floss.tags.gp.StringHashDatabase.from_file(path)

    assert "!This program cannot be run in DOS mode." in db
    assert "Willi rules" not in db


def test_pestrings_roundtrip():
    original = PeStrings(
        path="/tmp/sample.exe",
        sha256="a" * 64,
        timestamp="2026-01-01T00:00:00",
        dotnet=False,
        strings=[
            FileString(
                offset=64, string="!This program cannot be run in DOS mode.", encoding="ascii", location="header"
            ),
            FileString(offset=1024, string="kernel32.dll", encoding="utf-16le", location=".rdata"),
        ],
    )
    serialized = json.loads(json.dumps(dataclasses.asdict(original)))
    restored = PeStrings.from_dict(serialized)
    assert restored == original
    assert all(isinstance(s, FileString) for s in restored.strings)


def test_generate_gp_db_deduplicates_sha256_and_filters_type(tmp_path):
    pe1 = PeStrings(
        path="/tmp/a.exe",
        sha256="1" * 64,
        timestamp="2026-01-01T00:00:00",
        dotnet=False,
        strings=[FileString(offset=64, string="common_str", encoding="ascii", location=".rdata")],
    )
    pe1_dup = PeStrings(
        path="/tmp/a_copy.exe",
        sha256="1" * 64,
        timestamp="2026-01-01T00:00:00",
        dotnet=False,
        strings=[FileString(offset=64, string="common_str", encoding="ascii", location=".rdata")],
    )
    pe2 = PeStrings(
        path="/tmp/b.exe",
        sha256="2" * 64,
        timestamp="2026-01-01T00:00:00",
        dotnet=True,
        strings=[FileString(offset=64, string="common_str", encoding="ascii", location=".rdata")],
    )

    (tmp_path / "a.json").write_text(json.dumps(dataclasses.asdict(pe1)), encoding="utf-8")
    (tmp_path / "a_copy.json").write_text(json.dumps(dataclasses.asdict(pe1_dup)), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(dataclasses.asdict(pe2)), encoding="utf-8")

    db_native = generate_gp_db(str(tmp_path), min_count=1, type_="native")
    entries_native = db_native.query("common_str")
    assert len(entries_native) == 1
    assert entries_native[0].global_count == 1

    db_all = generate_gp_db(str(tmp_path), min_count=1, type_="all")
    entries_all = db_all.query("common_str")
    assert len(entries_all) == 1
    assert entries_all[0].global_count == 2

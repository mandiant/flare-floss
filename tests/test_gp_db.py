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

import pathlib

import floss.tags.gp

CD = pathlib.Path(__file__).parent


def test_load_db():
    path = pathlib.Path(floss.tags.gp.__file__).resolve().parents[1] / "qs" / "db" / "data" / "gp" / "gp.jsonl.gz"
    db = floss.tags.gp.StringGlobalPrevalenceDatabase.from_file(path)

    assert len(db) > 0  # 21 entries at time of writing


def test_query_db():
    path = pathlib.Path(floss.tags.gp.__file__).resolve().parents[1] / "qs" / "db" / "data" / "gp" / "gp.jsonl.gz"
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
    path = pathlib.Path(floss.tags.gp.__file__).resolve().parents[1] / "qs" / "db" / "data" / "gp" / "xaa-hashes.bin"
    db = floss.tags.gp.StringHashDatabase.from_file(path)

    assert len(db) > 0


def test_query_hash_db():
    path = pathlib.Path(floss.tags.gp.__file__).resolve().parents[1] / "qs" / "db" / "data" / "gp" / "xaa-hashes.bin"
    db = floss.tags.gp.StringHashDatabase.from_file(path)

    assert "!This program cannot be run in DOS mode." in db
    assert "Willi rules" not in db

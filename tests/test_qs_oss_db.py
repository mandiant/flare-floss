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

import floss.tags.oss


def test_load_db():
    path = pathlib.Path(floss.tags.oss.__file__).resolve().parents[1] / "qs" / "db" / "data" / "oss" / "zlib.jsonl.gz"
    db = floss.tags.oss.OpenSourceStringDatabase.from_file(path)
    assert len(db) > 0  # 21 entries at time of writing


def test_query_db():
    path = pathlib.Path(floss.tags.oss.__file__).resolve().parents[1] / "qs" / "db" / "data" / "oss" / "zlib.jsonl.gz"
    db = floss.tags.oss.OpenSourceStringDatabase.from_file(path)

    s = db.metadata_by_string["invalid distance code"]

    assert s is not None
    assert s.string == "invalid distance code"
    assert s.library_name == "zlib"
    assert s.library_version == "1.2.13"
    assert s.file_path == "CMakeFiles/zlib.dir/inffast.obj"
    assert s.function_name == "inflate_fast"
    assert s.line_number is None

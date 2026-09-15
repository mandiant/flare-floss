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

import floss.tags.winapi
from floss.tags import data_root


def test_load_db():
    path = data_root() / "winapi"
    db = floss.tags.winapi.WindowsApiStringDatabase.from_dir(path)
    assert len(db) > 0


def test_query_db():
    path = data_root() / "winapi"
    db = floss.tags.winapi.WindowsApiStringDatabase.from_dir(path)

    assert "kernel32.dll" in db.dll_names
    assert "kernel33.dll" not in db.dll_names

    assert "CreateFileA" in db.api_names
    assert "CreateFileB" not in db.api_names

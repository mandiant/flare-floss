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

"""JSON round-trip for the unified ResultDocument schema (enrichment fields)."""

import json
import tempfile
from pathlib import Path

import floss.render.json
from floss.results import (
    Strings,
    Analysis,
    Metadata,
    ResultLayout,
    ResultString,
    StaticString,
    ResultDocument,
    StringEncoding,
)


def test_enriched_static_json_roundtrip():
    layout = ResultLayout(
        name="pe",
        offset=0,
        length=0x1000,
        strings=[
            ResultString(
                string="kernel32.dll",
                offset=0x100,
                size=12,
                encoding="ascii",
                tags=["#winapi", "#common"],
                structure="import table",
            )
        ],
        children=[],
    )
    doc = ResultDocument(
        metadata=Metadata(
            file_path="sample.exe",
            min_length=4,
            md5="d" * 32,
            sha1="a" * 40,
            sha256="b" * 64,
        ),
        analysis=Analysis(
            enable_static_strings=True,
            enable_stack_strings=False,
            enable_tight_strings=False,
            enable_decoded_strings=False,
            enable_layout=True,
            enable_tags=True,
        ),
        strings=Strings(
            static_strings=[
                StaticString(
                    string="kernel32.dll",
                    offset=0x100,
                    encoding=StringEncoding.ASCII,
                    tags=["#common", "#winapi"],
                    section="pe",
                    structure="import table",
                )
            ]
        ),
        layout=layout,
    )

    raw = floss.render.json.render(doc)
    data = json.loads(raw)
    assert data["metadata"]["md5"] == "d" * 32
    assert data["metadata"]["sha1"] == "a" * 40
    assert data["metadata"]["sha256"] == "b" * 64
    assert data["layout"]["name"] == "pe"
    assert data["strings"]["static_strings"][0]["tags"] == ["#common", "#winapi"]
    assert data["strings"]["static_strings"][0]["section"] == "pe"
    assert data["strings"]["static_strings"][0]["structure"] == "import table"
    assert data["analysis"]["enable_layout"] is True

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(raw)
        path = Path(f.name)
    try:
        loaded = ResultDocument.parse_file(path)
    finally:
        path.unlink()

    assert loaded.layout is not None
    assert loaded.layout.name == "pe"
    assert loaded.metadata.md5 == "d" * 32
    assert loaded.metadata.sha256 == "b" * 64
    assert loaded.strings.static_strings[0].tags == ["#common", "#winapi"]
    assert loaded.strings.static_strings[0].structure == "import table"


def test_layout_none_roundtrip():
    doc = ResultDocument(
        metadata=Metadata(file_path="blob.bin", min_length=4),
        analysis=Analysis(enable_layout=False, enable_tags=False),
        strings=Strings(
            static_strings=[
                StaticString(string="hello", offset=0, encoding=StringEncoding.ASCII),
            ]
        ),
        layout=None,
    )
    raw = floss.render.json.render(doc)
    data = json.loads(raw)
    assert data["layout"] is None
    assert data["strings"]["static_strings"][0]["tags"] == []

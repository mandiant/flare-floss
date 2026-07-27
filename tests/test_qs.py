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

import copy
import tempfile
from pathlib import Path

import pytest

import floss.render.json
from floss.tags import load_databases
from floss.enrich import static_strings_from_layout
from floss.layout import compute_layout
from floss.ranges import Slice
from floss.results import Strings, Analysis, Metadata, ResultLayout, ResultDocument
from floss.layout.extract import collect_strings, extract_layout_strings

CD = Path(__file__).resolve().parent
MIN_STR_LEN = 6


@pytest.fixture
def pma_binary_path():
    return CD / "data" / "pma" / "Practical Malware Analysis Lab 03-03.exe_"


@pytest.fixture
def analyzed_layout(pma_binary_path):
    slice_buf = pma_binary_path.read_bytes()
    file_slice = Slice.from_bytes(slice_buf)
    layout = compute_layout(file_slice)
    extract_layout_strings(layout, 6)
    taggers = load_databases()
    layout.tag_strings(taggers)
    layout.mark_structures()
    return layout


def test_round_trip(analyzed_layout, pma_binary_path):
    layout_doc = ResultLayout.from_layout(analyzed_layout)
    statics = static_strings_from_layout(layout_doc)
    one = ResultDocument(
        metadata=Metadata(file_path=str(pma_binary_path.resolve()), min_length=MIN_STR_LEN),
        analysis=Analysis(
            enable_static_strings=True,
            enable_stack_strings=False,
            enable_tight_strings=False,
            enable_decoded_strings=False,
            enable_layout=True,
            enable_tags=True,
        ),
        strings=Strings(static_strings=statics),
        layout=layout_doc,
    )

    doc = floss.render.json.render(one)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(doc)
        path = Path(f.name)
    try:
        two = ResultDocument.parse_file(path)
    finally:
        path.unlink()

    # show the round trip works
    assert one.metadata.file_path == two.metadata.file_path
    assert one.layout is not None and two.layout is not None
    assert one.layout.name == two.layout.name
    assert len(one.strings.static_strings) == len(two.strings.static_strings)
    assert one.strings.static_strings[0].tags == two.strings.static_strings[0].tags

    # now show that two different versions are not equal.
    three = copy.deepcopy(two)
    three.metadata.version = "0"
    assert one.metadata.version != three.metadata.version


def test_string_extraction(analyzed_layout):
    strings = collect_strings(analyzed_layout)
    # Check if a known string is extracted
    assert any(s.string.string == "user32.dll" for s in strings)


def test_tagging(analyzed_layout):
    strings = collect_strings(analyzed_layout)
    # Check if a known string is tagged correctly
    user32_string = next(s for s in strings if s.string.string == "user32.dll")
    assert "#winapi" in user32_string.tags


def test_structure_marking(analyzed_layout):
    strings = collect_strings(analyzed_layout)
    # Check if a string is correctly associated with a structure
    data_string = next(s for s in strings if s.string.string == "@.data")
    assert data_string.structure == "section header"

    close_string = next(s for s in strings if s.string.string == "CloseHandle")
    assert close_string.structure == "import table"

import json
from pathlib import Path

import pytest

from floss.qs.main import (
    Slice,
    Layout,
    TaggedString,
    compute_layout,
    load_databases,
    collect_strings,
    distribute_strings,
    extract_layout_strings,
)


@pytest.fixture
def pma_binary_path():
    # Path to the test binary provided by the user
    return Path("pma0303.exe_")


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


def test_serialization_deserialization(analyzed_layout):
    # Serialize the layout and strings
    layout_dict = analyzed_layout.to_dict()
    strings_list = [s.to_dict() for s in collect_strings(analyzed_layout)]

    # Deserialize the layout and strings
    deserialized_layout = Layout.from_dict(layout_dict)
    deserialized_strings = [TaggedString.from_dict(d) for d in strings_list]
    distribute_strings(deserialized_layout, deserialized_strings)

    # Assert that the deserialized layout is the same as the original
    assert deserialized_layout.name == analyzed_layout.name
    assert len(deserialized_layout.children) == len(analyzed_layout.children)


def test_string_extraction(analyzed_layout):
    strings = collect_strings(analyzed_layout)
    # Check if a known string is extracted
    assert any(s.string.string.lower() == "user32.dll" for s in strings)


def test_tagging(analyzed_layout):
    strings = collect_strings(analyzed_layout)
    # Check if a known string is tagged correctly
    user32_string = next(s for s in strings if s.string.string.lower() == "user32.dll")
    assert "#winapi" in user32_string.tags


def test_structure_marking(analyzed_layout):
    strings = collect_strings(analyzed_layout)
    # Check if a string is correctly associated with a structure
    data_string = next(s for s in strings if s.string.string.lower() == "@.data")
    assert data_string.structure == "section header"

    # strings = collect_strings(analyzed_layout)
    # close_string = next(s for s in strings if s.string.string.lower() == "CloseHandle")
    # assert close_string.structure == "import table"


def test_analysis_pipeline(pma_binary_path):
    # Run the analysis pipeline
    slice_buf = pma_binary_path.read_bytes()
    file_slice = Slice.from_bytes(slice_buf)
    layout = compute_layout(file_slice)
    extract_layout_strings(layout, 6)

    # Check that the layout has been computed correctly
    assert layout.name == "pe"

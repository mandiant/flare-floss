import copy
from pathlib import Path

import pytest

from floss.qs.main import (
    ResultLayout,
    Slice,
    compute_layout,
    load_databases,
    collect_strings,
    extract_layout_strings,
    to_result_layout,
)


@pytest.fixture
def pma_binary_path():
    return Path("tests") / Path("data") / Path("pma") / Path("pma0303.exe_")


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


def assert_round_trip(layout):
    layout = to_result_layout(analyzed_layout)
    one = layout

    doc = one.model_dump_json(exclude_none=True)
    two = ResultLayout.model_validate_json(doc)

    # show the round trip works
    # first by comparing the objects directly,
    # which works thanks to pydantic model equality.
    assert one == two
    # second by showing their json representations are the same.
    assert one.model_dump_json(exclude_none=True) == two.model_dump_json(exclude_none=True)

    # now show that two different versions are not equal.
    three = copy.deepcopy(two)
    three.meta.__dict__.update({"version": "0.0.0"})
    assert one.meta.version != three.meta.version
    assert one != three
    assert one.model_dump_json(exclude_none=True) != three.model_dump_json(exclude_none=True)


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


def test_analysis_pipeline(pma_binary_path):
    # Run the analysis pipeline
    slice_buf = pma_binary_path.read_bytes()
    file_slice = Slice.from_bytes(slice_buf)
    layout = compute_layout(file_slice)
    extract_layout_strings(layout, 6)

    # Check that the layout has been computed correctly
    assert layout.name == "pe"

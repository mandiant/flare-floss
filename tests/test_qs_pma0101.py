from pathlib import Path

import pytest

from floss.qs.main import (
    Slice,
    compute_layout,
    load_databases,
    collect_strings,
    extract_layout_strings,
)


@pytest.fixture(scope="module")
def pma0101_layout():
    """
    Provides the analyzed layout.
    The analysis pipeline (string extraction, tagging, structure marking)
    is run once for all tests in this module.
    """
    binary_path = Path("tests") / Path("data") / Path("pma") / Path("Practical Malware Analysis Lab 01-01.dll_")
    slice_buf = binary_path.read_bytes()
    file_slice = Slice.from_bytes(slice_buf)
    layout = compute_layout(file_slice)
    extract_layout_strings(layout, 6)
    taggers = load_databases()
    layout.tag_strings(taggers)
    layout.mark_structures()
    return layout


def find_string(layout, text):
    """Helper to find a specific string in the layout."""
    all_strings = collect_strings(layout)
    found = [s for s in all_strings if s.string.string == text]
    return found[0] if found else None


def test_pe_layout(pma0101_layout):
    assert pma0101_layout.name == "pe"


def test_header_strings(pma0101_layout):
    dos_mode_str = find_string(pma0101_layout, "!This program cannot be run in DOS mode.")
    assert dos_mode_str is not None
    assert "#common" in dos_mode_str.tags

    rdata_str = find_string(pma0101_layout, "@.data")
    assert rdata_str is not None
    assert "#common" in rdata_str.tags
    assert rdata_str.structure == "section header"

    reloc_str = find_string(pma0101_layout, ".reloc")
    assert reloc_str is not None
    assert "#common" in reloc_str.tags
    assert reloc_str.structure == "section header"


def test_rdata_strings(pma0101_layout):
    kernel32_str = find_string(pma0101_layout, "KERNEL32.dll")
    assert kernel32_str is not None
    assert "#winapi" in kernel32_str.tags
    assert kernel32_str.structure == "import table"

    msvcrt_str = find_string(pma0101_layout, "MSVCRT.dll")
    assert msvcrt_str is not None
    assert "#winapi" in msvcrt_str.tags
    assert msvcrt_str.structure == "import table"

    initterm_str = find_string(pma0101_layout, "_initterm")
    assert initterm_str is not None
    assert "#winapi" in initterm_str.tags
    assert "#code-junk" in initterm_str.tags
    assert initterm_str.structure == "import table"


def test_data_strings(pma0101_layout):
    ip_str = find_string(pma0101_layout, "127.26.152.13")
    assert ip_str is not None

    garbage_str = find_string(pma0101_layout, "SADFHUHF")
    assert garbage_str is not None


def test_strings(pma0101_layout):
    all_strings = collect_strings(pma0101_layout)

    assert len(all_strings) == 21

    # assert count of expected strings not tagged as #code or #reloc
    filtered_strings = [s for s in all_strings if not s.tags.intersection({"#code", "#reloc"})]
    assert len(filtered_strings) == 17

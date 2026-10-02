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

import pefile
import pytest

import floss.render.json
from floss.tags import load_databases
from floss.enrich import static_strings_from_layout
from floss.layout import compute_layout
from floss.ranges import Slice
from floss.results import Strings, Analysis, Metadata, ResultLayout, ResultDocument
from floss.layout.extract import collect_strings

CD = Path(__file__).resolve().parent
MIN_STR_LEN = 6


@pytest.fixture
def pma_binary_path():
    return CD / "data" / "pma" / "Practical Malware Analysis Lab 03-03.exe_"


@pytest.fixture
def analyzed_layout(pma_binary_path):
    slice_buf = pma_binary_path.read_bytes()
    file_slice = Slice.from_bytes(slice_buf)
    parsed = compute_layout(file_slice)
    parsed.extract_strings(6)
    taggers = load_databases()
    parsed.tag_strings(taggers)
    parsed.mark_structures()
    return parsed


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
    assert one == two
    assert floss.render.json.render(one) == floss.render.json.render(two)

    # now show that two different versions are not equal.
    three = copy.deepcopy(two)
    three.metadata.version = "0"
    assert two.metadata.version != three.metadata.version
    assert floss.render.json.render(two) != floss.render.json.render(three)


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
    parsed = compute_layout(file_slice)
    parsed.extract_strings(6)

    # Check that the layout has been computed correctly
    assert parsed.name == "pe"


def test_is_structured_layout():
    import floss.enrich

    assert floss.enrich.is_structured_layout("pe")
    assert floss.enrich.is_structured_layout("elf")
    assert floss.enrich.is_structured_layout("macho")
    assert floss.enrich.is_structured_layout("macho (fat)")
    # XOR-obfuscated PE/ELF headers append the XOR note to the name
    assert floss.enrich.is_structured_layout("pe (XOR decoded with key: 0x41)")
    assert floss.enrich.is_structured_layout("elf (XOR decoded with key: 0x42)")
    assert not floss.enrich.is_structured_layout("binary")


def _make_root_layout(cls, name, **extra):
    from floss.ranges import Range, Slice, OffsetRanges
    from floss.layout.base import Structure
    from floss.layout.types import TaggedString, ExtractedString

    buf = b"\x00" * 32
    sl = Slice(buf=buf, range=Range(offset=0, length=len(buf)), base_offset=0)
    layout = cls(
        name=name,
        slice=sl,
        structures_by_address={0: Structure(slice=sl, name="pe/elf header")},
        reloc_offsets=OffsetRanges(ranges=[]),
        code_offsets=OffsetRanges(ranges=[]),
        **extra,
    )
    layout.strings = [TaggedString(string=ExtractedString(string="rootstr", slice=sl, encoding="ascii"), tags=set())]
    return layout


def test_pe_root_strings_get_structure_annotations():
    from floss.layout.base import PELayout

    layout = _make_root_layout(PELayout, "pe", xor_key=None)
    layout.mark_structures()
    assert layout.strings[0].structure == "pe/elf header"


def test_elf_root_strings_get_structure_annotations():
    from floss.ranges import OffsetRanges
    from floss.layout.base import ELFLayout

    layout = _make_root_layout(ELFLayout, "elf", xor_key=None, relocation_offsets=OffsetRanges(ranges=[]))
    layout.mark_structures()
    assert layout.strings[0].structure == "pe/elf header"


DOTNET_HELLO = CD / "data" / "language" / "dotnet" / "dotnet-hello" / "bin" / "dotnet-hello.exe"


@pytest.mark.parametrize("prefix", [0, 0x1000])
def test_pe_layout_fills_all_section_gaps(prefix):
    pe = pefile.PE(data=DOTNET_HELLO.read_bytes())
    for section in pe.sections[:2]:
        section.SizeOfRawData = 0x200
    buf = pe.write()

    layout = compute_layout(Slice.from_bytes(b"\x00" * prefix + buf).slice(prefix, len(buf)))

    children = layout.children
    assert [c.name for c in children] == ["header", ".text", "gap", ".rsrc", "gap", ".reloc"]
    assert children[0].offset == prefix
    assert children[-1].end == prefix + len(buf)
    for prior, current in zip(children, children[1:]):
        assert prior.end == current.offset, f"hole between {prior.name} and {current.name}"


def test_pe_layout_overlapping_sections_do_not_create_gaps():
    pe = pefile.PE(data=DOTNET_HELLO.read_bytes())
    pe.sections[1].PointerToRawData = pe.sections[0].PointerToRawData

    layout = compute_layout(Slice.from_bytes(pe.write()))

    assert [(c.name, c.offset, c.end) for c in layout.children] == [
        ("header", 0x0, 0x200),
        (".text", 0x200, 0x600),
        (".rsrc", 0x200, 0x800),
        ("gap", 0x800, 0xC00),
        (".reloc", 0xC00, 0xE00),
    ]

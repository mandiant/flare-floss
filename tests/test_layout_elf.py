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

from pathlib import Path

from floss.layout import compute_layout
from floss.ranges import Slice
from floss.layout.base import ELFLayout, SectionLayout, SegmentLayout

CD = Path(__file__).resolve().parent
ELF_DIR = CD / "data" / "elf"

# x86-64 Position Independent Executable (PIE), dynamically linked, not stripped
X86_64_PIE = "055da8e6ccfe5a9380231ea04b850e18.elf"
# ARM64 shared object, dynamically linked, stripped, Android linker
ARM64_SO = "687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf"
# ARM64 PIE, dynamically linked, stripped
ARM64_LS = "ls"


def _load_layout(name: str):
    path = ELF_DIR / name
    data = path.read_bytes()
    return compute_layout(Slice.from_bytes(data))


def test_elf_layout():
    layout = _load_layout(X86_64_PIE)
    assert isinstance(layout, ELFLayout)
    assert layout.name == "elf"
    assert layout.children
    text_sections = [c for c in layout.children if c.name == ".text"]
    assert len(text_sections) == 1
    assert text_sections[0].offset == 0x10A0
    assert text_sections[0].slice.range.length == 0x1C5


def test_elf_section_names():
    # x86-64, not stripped: executable code section, dynamic string table, and symbol table all present
    layout = _load_layout(X86_64_PIE)
    names = {child.name for child in layout.children}
    assert ".text" in names
    assert ".dynstr" in names
    assert ".symtab" in names


def test_elf_structures_present():
    layout = _load_layout(X86_64_PIE)
    assert layout.structures_by_address[0x0].name == "elf header"
    assert layout.structures_by_address[0x40].name == "program header"
    assert layout.structures_by_address[0x39D0].name == "section header"
    assert layout.structures_by_address[0x3C8].name == "symbol table"  # .dynsym
    assert layout.structures_by_address[0x4A0].name == "string table"  # .dynstr


def test_elf_code_and_reloc_offsets():
    layout = _load_layout(X86_64_PIE)
    # .text (offset 0x10a0, size 0x1c5) is fully covered by code ranges;
    # it merges with adjacent exec sections (.plt etc.) so we check coverage, not exact range
    assert layout.code_offsets.overlaps(0x10A0, 0x10A0 + 0x1C5 - 1)
    assert (0x568, 0x66F) in layout.relocation_offsets.ranges  # .rela.dyn + .rela.plt merged


def test_arm64_so_android_note_section():
    # Android shared object has an Android-specific note section absent from standard Linux ELFs
    layout = _load_layout(ARM64_SO)
    names = {child.name for child in layout.children}
    assert ".note.android.ident" in names


def test_arm64_ls_stripped():
    # stripped binary has no symbol table
    layout = _load_layout(ARM64_LS)
    names = {child.name for child in layout.children}
    assert ".symtab" not in names


def test_elf_segment_fallback():
    # Test fallback to segments when section headers are missing/corrupted
    path = ELF_DIR / X86_64_PIE
    data = bytearray(path.read_bytes())

    # Verify ELFCLASS64
    assert data[4] == 2
    # Corrupt e_shoff (set 8 bytes at offset 40 to 0)
    data[40:48] = b"\x00" * 8
    # Corrupt e_shnum (set 2 bytes at offset 60 to 0)
    data[60:62] = b"\x00\x00"

    layout = compute_layout(Slice.from_bytes(bytes(data)))
    assert isinstance(layout, ELFLayout)
    assert layout.children
    for child in layout.children:
        assert isinstance(child, SegmentLayout)
        assert child.name.startswith("segment_")


def test_elf_truncated_shstrtab_header_segment_fallback():
    path = ELF_DIR / X86_64_PIE
    data = bytearray(path.read_bytes())

    # Truncate right inside the .shstrtab section header entry so ELFFile._get_section_header_stringtable fails
    e_shoff = int.from_bytes(data[40:48], "little")
    e_shentsize = int.from_bytes(data[58:60], "little")
    e_shstrndx = int.from_bytes(data[62:64], "little")
    shstr_hdr_offset = e_shoff + e_shstrndx * e_shentsize
    truncated = bytes(data[: shstr_hdr_offset + 16])

    layout = compute_layout(Slice.from_bytes(truncated))
    assert isinstance(layout, ELFLayout)
    assert layout.children
    for child in layout.children:
        assert isinstance(child, SegmentLayout)
        assert child.name.startswith("segment_")
        assert child.name.endswith("_PT_LOAD")


def test_elf_invalid_shstrndx_and_symtab_sh_link():
    path = ELF_DIR / X86_64_PIE
    data = bytearray(path.read_bytes())

    e_shoff = int.from_bytes(data[40:48], "little")
    e_shentsize = int.from_bytes(data[58:60], "little")
    e_shnum = int.from_bytes(data[60:62], "little")
    e_shstrndx = int.from_bytes(data[62:64], "little")

    # Change .shstrtab sh_type (4 bytes at +4 in Elf64_Shdr) to SHT_NOBITS (8)
    shstr_hdr_offset = e_shoff + e_shstrndx * e_shentsize
    data[shstr_hdr_offset + 4 : shstr_hdr_offset + 8] = (8).to_bytes(4, "little")

    # Set sh_link (4 bytes at +40 in Elf64_Shdr) on SHT_SYMTAB (2) and SHT_DYNSYM (11) to out-of-range index
    for i in range(e_shnum):
        hdr_off = e_shoff + i * e_shentsize
        sh_type = int.from_bytes(data[hdr_off + 4 : hdr_off + 8], "little")
        if sh_type in (2, 11):
            data[hdr_off + 40 : hdr_off + 44] = (0xFFFF).to_bytes(4, "little")

    layout = compute_layout(Slice.from_bytes(bytes(data)))
    assert isinstance(layout, ELFLayout)
    assert layout.children
    for child in layout.children:
        assert isinstance(child, SectionLayout)
        assert child.name.startswith("unnamed_section_")

    assert layout.structures_by_address[0x3C8].name == "symbol table"
    assert layout.code_offsets.overlaps(0x10A0, 0x10A0 + 0x1C5 - 1)
    assert (0x568, 0x66F) in layout.relocation_offsets.ranges


def test_elf_code_offsets_inclusive_end():
    layout = _load_layout(X86_64_PIE)
    # The last executable section (.fini) ends at 0x1275, so the last executable byte is 0x1274
    assert 0x1274 in layout.code_offsets
    assert 0x1275 not in layout.code_offsets


def test_elf_code_offsets_nested_slice():
    data = (ELF_DIR / X86_64_PIE).read_bytes()
    standalone = compute_layout(Slice.from_bytes(data))
    assert isinstance(standalone, ELFLayout)

    k = 0x400
    outer = b"\x00" * k + data + b"\x00" * 0x100
    nested = compute_layout(Slice.from_bytes(outer).slice(k, len(data)))
    assert isinstance(nested, ELFLayout)

    expected = [(start + k, end + k) for start, end in standalone.code_offsets.ranges]
    assert nested.code_offsets.ranges == expected
    assert nested.relocation_offsets.ranges == [(s + k, e + k) for s, e in standalone.relocation_offsets.ranges]

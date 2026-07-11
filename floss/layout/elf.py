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

"""ELF layout construction."""

from __future__ import annotations

import io
import logging
from typing import Any, Dict, List, Tuple, Iterable, Optional, Sequence

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.relocation import RelocationSection
from elftools.common.exceptions import ELFError

from floss.ranges import Range, Slice, OffsetRanges
from floss.layout.base import Layout, ELFLayout, Structure, SectionLayout, SegmentLayout
from floss.layout.util import _merge_overlapping_ranges
from floss.layout.types import Tag, ExtractedString

logger = logging.getLogger("floss.layout.elf")


def elf_has_valid_sections(elf: ELFFile, limit: int) -> bool:
    shoff = elf.header.get("e_shoff", 0)
    shnum = elf.header.get("e_shnum", 0)
    shentsize = elf.header.get("e_shentsize", 0)
    if shoff == 0 or shnum == 0 or shentsize == 0:
        return False

    try:
        expected_shentsize = elf.structs.Elf_Shdr.sizeof()
    except Exception:
        return False

    if shentsize < expected_shentsize:
        return False

    sh_end = shoff + shnum * shentsize
    return sh_end <= limit


def elf_has_valid_segments(elf: ELFFile, limit: int) -> bool:
    phoff = elf.header.get("e_phoff", 0)
    phnum = elf.header.get("e_phnum", 0)
    phentsize = elf.header.get("e_phentsize", 0)
    if phnum == 0 or phnum >= 0xFFFF:
        return False
    if phoff == 0 or phentsize == 0:
        return False

    try:
        expected_phentsize = elf.structs.Elf_Phdr.sizeof()
    except Exception:
        return False

    if phentsize < expected_phentsize:
        return False

    ph_end = phoff + phnum * phentsize
    return ph_end <= limit


def iter_sections_robust(elf: ELFFile) -> Iterable[Any]:
    try:
        num_sections = elf.num_sections()
    except Exception as e:
        logger.warning("failed to get number of sections: %s", e)
        return

    for i in range(num_sections):
        try:
            yield elf.get_section(i)
        except Exception as e:
            logger.warning("failed to parse section %d: %s", i, e)
            continue


def get_relocations_elf(slice_: Slice, elf: ELFFile) -> List[Tuple[int, int]]:
    if not elf_has_valid_sections(elf, slice_.range.length):
        return []

    ranges: List[Tuple[int, int]] = []

    for section in iter_sections_robust(elf):
        if isinstance(section, RelocationSection):
            offset = section["sh_offset"]
            size = section["sh_size"]

            if not slice_.contains_range(offset, size):
                logger.warning("relocation directory points to an invalid location, skipping")
                continue

            ranges.append((slice_.offset + offset, slice_.offset + offset + size - 1))
    return _merge_overlapping_ranges(ranges)


def collect_elf_structures(slice_: Slice, elf: ELFFile) -> Sequence[Structure]:
    structures: List[Structure] = []

    # ELF file header: 52 bytes (32-bit) or 64 bytes (64-bit)
    header_size = 52 if elf.elfclass == 32 else 64
    if slice_.contains_range(0, header_size):
        structures.append(Structure(slice=slice_.slice(0, header_size), name="elf header"))

    # Program header table
    phoff = elf.header["e_phoff"]
    phentsize = elf.header["e_phentsize"]
    phnum = elf.header["e_phnum"]
    if phnum > 0 and phentsize > 0:
        ph_total = phentsize * phnum
        if slice_.contains_range(phoff, ph_total):
            structures.append(Structure(slice=slice_.slice(phoff, ph_total), name="program header"))

    # Section header table
    shoff = elf.header["e_shoff"]
    shentsize = elf.header["e_shentsize"]
    shnum = elf.header["e_shnum"]
    if shnum > 0 and shentsize > 0:
        sh_total = shentsize * shnum
        if slice_.contains_range(shoff, sh_total) and elf_has_valid_sections(elf, slice_.range.length):
            structures.append(Structure(slice=slice_.slice(shoff, sh_total), name="section header"))

    # String tables (.shstrtab, .strtab, .dynstr) and symbol tables (.symtab, .dynsym)
    if elf_has_valid_sections(elf, slice_.range.length):
        for section in iter_sections_robust(elf):
            if section["sh_size"] == 0:
                continue
            if section["sh_type"] == "SHT_NOBITS":
                continue

            offset = section["sh_offset"]
            size = section["sh_size"]

            if not slice_.contains_range(offset, size):
                continue

            if section["sh_type"] == "SHT_STRTAB":
                structures.append(Structure(slice=slice_.slice(offset, size), name="string table"))
            elif section["sh_type"] in {"SHT_SYMTAB", "SHT_DYNSYM"}:
                structures.append(Structure(slice=slice_.slice(offset, size), name="symbol table"))

    return structures


def compute_elf_layout(slice_: Slice, xor_key: int | None) -> Layout:
    data = slice_.data

    elf = ELFFile(io.BytesIO(data))

    structures = collect_elf_structures(slice_, elf)
    relocation_offsets = OffsetRanges.from_merged_ranges(get_relocations_elf(slice_, elf))

    structures_by_address: Dict[int, Structure] = {}
    for structure in structures:
        for offset in structure.slice.range:
            structures_by_address[offset] = structure

    # Collect valid file-backed sections/segments, sorted by offset, deduplicating overlaps.
    # For sections: SHT_NOBITS sections (.bss, .noptrbss) have no file content; skip them.
    # For segments: PT_LOAD segments are main focus.
    # Also track executable parts (SHF_EXECINSTR or PF_X) for #code tagging.
    layout_elements: List[Tuple[int, int, str, bool]] = []  # (offset, size, name, is_exec)

    use_sections = elf_has_valid_sections(elf, slice_.range.length)
    if use_sections:
        for idx, section in enumerate(iter_sections_robust(elf)):
            if section["sh_size"] == 0:
                continue
            if section["sh_type"] == "SHT_NOBITS":
                continue

            try:
                name = section.name
            except (ELFError, IndexError, UnicodeDecodeError) as e:
                name = f"unnamed_section_{idx}"
                logger.warning("failed to get section name for section %d: %s", idx, e)

            offset = section["sh_offset"]
            size = section["sh_size"]
            is_exec = bool(section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR)

            if offset >= slice_.range.length:
                logger.warning("section %s out of range", name)
                continue

            if offset + size > slice_.range.length:
                size_orig = size
                size = slice_.range.length - offset
                logger.warning(
                    "section size %s out of range, truncating from 0x%x to 0x%x bytes", name, size_orig, size
                )

            layout_elements.append((offset, size, name, is_exec))
    else:
        logger.debug("ELF section headers missing or invalid, using segments for layout")
        if not elf_has_valid_segments(elf, slice_.range.length):
            raise ELFError("ELF program headers missing or invalid")
        num_segments = elf.num_segments()

        for i in range(num_segments):
            try:
                segment_header = elf.get_segment(i).header

                if segment_header["p_type"] not in ("PT_LOAD", 1):
                    continue

                if segment_header["p_filesz"] == 0:
                    continue

                offset = segment_header["p_offset"]
                size = segment_header["p_filesz"]
                is_exec = bool(segment_header["p_flags"] & P_FLAGS.PF_X)
                name = f"segment_{i}_{segment_header['p_type']}"

                if offset >= slice_.range.length:
                    logger.warning("segment %s out of range", name)
                    continue

                if offset + size > slice_.range.length:
                    size_orig = size
                    size = slice_.range.length - offset
                    logger.warning(
                        "segment size %s out of range, truncating from 0x%x to 0x%x bytes", name, size_orig, size
                    )

                layout_elements.append((offset, size, name, is_exec))
            except Exception as e:
                logger.warning("failed to parse segment %d: %s", i, e)
                continue

    # Build code_offsets from executable parts before constructing the layout.
    layout_elements.sort(key=lambda t: t[0])
    exec_ranges: List[Tuple[int, int]] = [
        (offset, offset + size) for offset, size, _name, is_exec in layout_elements if is_exec
    ]
    code_offsets = OffsetRanges.from_merged_ranges(_merge_overlapping_ranges(exec_ranges))

    layout = ELFLayout(
        slice=slice_,
        name="elf",
        xor_key=xor_key,
        relocation_offsets=relocation_offsets,
        code_offsets=code_offsets,
        structures_by_address=structures_by_address,
    )

    if xor_key:
        layout.name += f" (XOR decoded with key: 0x{xor_key:x})"

    # Sort by offset, then skip any element that overlaps a previously added one.
    cursor = 0
    for offset, size, name, _is_exec in layout_elements:
        if offset < cursor:
            logger.debug("element %s overlaps previous element, skipping", name)
            continue
        if use_sections:
            layout.add_child(SectionLayout(slice=slice_.slice(offset, size), name=name))
        else:
            layout.add_child(SegmentLayout(slice=slice_.slice(offset, size), name=name))
        cursor = offset + size

    return layout

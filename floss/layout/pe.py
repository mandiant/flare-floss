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

"""PE layout construction."""

from __future__ import annotations

import struct
import logging
import functools
from typing import Any, Set, Dict, List, Tuple, Optional, Sequence

import pefile
import lancelot

from floss.ranges import Range, Slice, OffsetRanges, timing
from floss.layout.base import (
    Layout,
    PELayout,
    Structure,
    SectionLayout,
    SegmentLayout,
    ResourceLayout,
)
from floss.layout.util import _merge_overlapping_ranges
from floss.layout.types import Tag, ExtractedString

logger = logging.getLogger("floss.layout.pe")


PE_RESOURCE_TYPES = {
    1: "Cursors",
    2: "Bitmaps",
    3: "Icons",
    4: "Menus",
    5: "Dialogs",
    6: "String Tables",
    7: "Font Directories",
    8: "Fonts",
    9: "Accelerators",
    10: "RCData",
    11: "Message Tables",
    12: "Cursor Groups",
    14: "Icon Groups",
    16: "Version Info",
    17: "DLGInclude",
    19: "Plug and Play",
    20: "VXD",
    21: "Animated Cursors",
    22: "Animated Icons",
    23: "HTML",
    24: "Manifest",
    240: "DLGInit",  # MFC specific
    241: "Toolbars",  # MFC specific
}


def get_reloc_offsets(slice: Slice, pe: pefile.PE) -> Set[int]:
    ret: Set[int] = set()

    directory_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]

    if pe.OPTIONAL_HEADER is None or pe.OPTIONAL_HEADER.DATA_DIRECTORY is None:
        return ret

    try:
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    except IndexError:
        return ret

    rva = dir_entry.VirtualAddress
    try:
        offset = pe.get_offset_from_rva(rva)
    except pefile.PEFormatError as e:
        logger.warning("failed to get offset for relocation directory RVA 0x%x: %s", rva, e)
        return ret

    size = dir_entry.Size

    if not slice.contains_range(offset, size):
        logger.warning("relocation directory points to an invalid location, skipping")
        return ret

    for fo in slice.range.slice(offset, size):
        ret.add(fo)

    return ret


def _get_code_ranges(
    be2: "lancelot.BinExport2",
    idx: "lancelot.be2utils.BinExport2Index",
    base_address: int,
    pe: pefile.PE,
    slice_: Slice,
) -> List[Tuple[int, int]]:
    """
    Extract and return the raw, unmerged code ranges from a PE file.
    """

    # cache because getting the offset is slow
    @functools.lru_cache(maxsize=None)
    def get_offset_from_rva_cached(rva):
        try:
            return pe.get_offset_from_rva(rva)
        except pefile.PEFormatError as e:
            logger.warning("%s", str(e))
            return None

    code_ranges: List[Tuple[int, int]] = []
    for flow_graph in be2.flow_graph:
        for basic_block_index in flow_graph.basic_block_index:
            try:
                basic_block = be2.basic_block[basic_block_index]
            except IndexError:
                logger.warning("lancelot basic block index %d out of range, skipping", basic_block_index)
                continue

            current_range: Optional[Tuple[int, int]] = None
            for _instruction_index, instruction, instruction_address in idx.basic_block_instructions(basic_block):
                va = instruction_address
                rva = va - base_address
                offset = get_offset_from_rva_cached(rva)
                if offset is None:
                    if current_range is not None:
                        code_ranges.append(current_range)
                        current_range = None
                    continue

                size = len(instruction.raw_bytes)
                if size == 0:
                    continue

                if not slice_.contains_range(offset, size):
                    logger.warning("lancelot identified code at an invalid location, skipping instruction at 0x%x", rva)
                    if current_range is not None:
                        code_ranges.append(current_range)
                        current_range = None
                    continue

                start = slice_.offset + offset
                end = slice_.offset + offset + size - 1
                if current_range is None:
                    current_range = (start, end)
                elif start == current_range[1] + 1:
                    current_range = (current_range[0], end)
                else:
                    code_ranges.append(current_range)
                    current_range = (start, end)
            if current_range is not None:
                code_ranges.append(current_range)
    return code_ranges


def collect_pe_structures(slice_: Slice, pe: pefile.PE) -> Sequence[Structure]:
    structures = []

    for section in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        offset = section.get_file_offset()
        size = section.sizeof()

        structures.append(
            Structure(
                slice=slice_.slice(offset, size),
                name="section header",
            )
        )

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = dll.dll.decode("ascii")
            except UnicodeDecodeError:
                continue

            rva = dll.struct.Name
            size = len(dll_name)
            try:
                offset = pe.get_offset_from_rva(rva)
            except pefile.PEFormatError as e:
                logger.warning("failed to get offset for import DLL name RVA 0x%x: %s", rva, e)
                continue

            structures.append(
                Structure(
                    slice=slice_.slice(offset, size),
                    name="import table",
                )
            )

            for entry in dll.imports:
                if entry.name is None:
                    continue

                if entry.name_offset is None:
                    continue

                try:
                    symbol_name = entry.name.decode("ascii")
                except UnicodeDecodeError:
                    continue

                offset = entry.name_offset
                size = len(symbol_name)

                structures.append(
                    Structure(
                        slice=slice_.slice(offset, size),
                        name="import table",
                    )
                )

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exp = pe.DIRECTORY_ENTRY_EXPORT
        if hasattr(exp, "name") and exp.name:
            try:
                dll_name = exp.name.decode("ascii")
                rva = exp.struct.Name
                size = len(dll_name)
                offset = pe.get_offset_from_rva(rva)

                structures.append(
                    Structure(
                        slice=slice_.slice(offset, size),
                        name="export table",
                    )
                )
            except (UnicodeDecodeError, pefile.PEFormatError) as e:
                logger.warning("failed to parse export table DLL name: %s", e)

        if hasattr(exp, "symbols"):
            for entry in exp.symbols:
                if entry.name is None:
                    continue

                if entry.name_offset is None:
                    continue

                try:
                    symbol_name = entry.name.decode("ascii")
                except UnicodeDecodeError:
                    continue

                offset = entry.name_offset
                size = len(symbol_name)

                structures.append(
                    Structure(
                        slice=slice_.slice(offset, size),
                        name="export table",
                    )
                )

                if entry.forwarder:
                    try:
                        forwarder_name = entry.forwarder.decode("ascii")
                    except UnicodeDecodeError:
                        continue
                    offset = entry.forwarder_offset
                    size = len(forwarder_name)
                    structures.append(
                        Structure(
                            slice=slice_.slice(offset, size),
                            name="export table",
                        )
                    )

    if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
        key_bytes = pe.RICH_HEADER.key

        rich_sig_offset = pe.__data__.find(b"Rich", 0x40, pe.DOS_HEADER.e_lfanew)
        # The structure end is 'Rich' (4) + key (4) = 8 bytes
        rich_end = rich_sig_offset + 8

        # Find the start of rich header by looking for 'DanS' XORed with the key
        xor_dans = bytes(a ^ b for a, b in zip(b"DanS", key_bytes))
        rich_start = pe.__data__.rfind(xor_dans, 0x40, rich_sig_offset)

        if rich_sig_offset != -1 and rich_start != -1:
            structures.append(Structure(slice=slice_.slice(rich_start, rich_end - rich_start), name="rich header"))

    return structures


def compute_pe_layout(slice_: Slice, xor_key: int | None) -> Layout:
    data = slice_.data

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as e:
        raise ValueError("pefile failed to load workspace") from e

    structures = collect_pe_structures(slice_, pe)
    reloc_offsets = OffsetRanges.from_offsets(get_reloc_offsets(slice_, pe))

    structures_by_address = {}
    for structure in structures:
        for offset in structure.slice.range:
            structures_by_address[offset] = structure

    be2: Optional[lancelot.BinExport2] = None
    with timing("lancelot: load workspace"):
        try:
            be2 = lancelot.get_binexport2_from_bytes(data)
        except ValueError as e:
            logger.warning("lancelot failed to load workspace: %s", e)
        except BaseException as e:
            if isinstance(e, (KeyboardInterrupt, SystemExit)):
                raise
            logger.warning("lancelot failed critically (panic): %s", e)

    # contains the file offsets of bytes that are part of recognized instructions.
    code_offsets = OffsetRanges()
    if be2:
        with timing("lancelot: find code"):
            base_address = lancelot.be2utils.find_be2_base_address(be2)
            idx = lancelot.be2utils.BinExport2Index(be2)
            code_ranges = _get_code_ranges(be2, idx, base_address, pe, slice_)
            merged_code_ranges = _merge_overlapping_ranges(code_ranges)
            code_offsets = OffsetRanges.from_merged_ranges(merged_code_ranges)

    layout = PELayout(
        slice=slice_,
        name="pe",
        xor_key=xor_key,
        reloc_offsets=reloc_offsets,
        code_offsets=code_offsets,
        structures_by_address=structures_by_address,
    )

    if xor_key:
        layout.name += f" (XOR decoded with key: 0x{xor_key:x})"

    for section in pe.sections:
        if section.SizeOfRawData == 0:
            continue

        try:
            name = section.Name.partition(b"\x00")[0].decode("utf-8")
        except UnicodeDecodeError:
            name = "(invalid)"

        offset = section.get_PointerToRawData_adj()
        size = section.SizeOfRawData

        if offset > slice_.range.end:
            logger.warning("section %s out of range", name)
            continue

        if offset + size > slice_.range.length:
            size_orig = size
            size = slice_.range.length - offset
            assert size >= 0
            logger.warning("section size %s out of range, truncating from 0x%x to 0x%x bytes", name, size_orig, size)

        layout.add_child(SectionLayout(slice=slice_.slice(offset, size), name=name, section=section))

    # segment that contains all data until the first section
    offset = 0
    size = layout.children[0].offset - slice_.range.offset
    layout.add_child(
        SegmentLayout(
            slice=slice_.slice(offset, size),
            name="header",
        )
    )

    # segment that contains all data after the last section
    # aka. "overlay"
    last_section: Layout = layout.children[-1]
    if last_section.end < layout.end:
        offset = last_section.end - layout.offset
        size = layout.end - last_section.end
        layout.add_child(
            SegmentLayout(
                slice=slice_.slice(offset, size),
                name="overlay",
            )
        )

    # the "overlay" may contain Authenticode digital signatures
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    if security.VirtualAddress and security.Size - 1 > 0:
        overlay: Layout = layout.children[-1]
        if overlay.name != "overlay":
            logger.debug("expected overlay to be present")
            # tread with caution

        if overlay.end < (security.VirtualAddress + security.Size - 1):
            logger.debug("overlay ends before authenticode digital signature")
        else:
            overlay.add_child(
                SegmentLayout(
                    slice=slice_.slice(security.VirtualAddress, security.Size - 1),
                    name="Authenticode digital signature",
                )
            )

    # add segments for any gaps between sections.
    # note that we append new items to the end of the list and then resort,
    # to avoid mutating the list while we're iterating over it.
    for i in range(1, len(layout.children)):
        prior: Layout = layout.children[i - 1]
        current: Layout = layout.children[i]

        if prior.end != current.offset:
            offset = prior.end
            size = current.offset - prior.end
            layout.add_child(
                SegmentLayout(
                    slice=slice_.slice(offset, size),
                    name="gap",
                )
            )

    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):

        def collect_pe_resources(dir_data: pefile.ResourceDirData, path: Tuple[str, ...] = ()) -> Sequence[Layout]:
            resources: List[Layout] = []
            for entry in dir_data.entries:
                if entry.name:
                    name = str(entry.name)
                else:
                    name = str(entry.id)
                    if not path and entry.id in PE_RESOURCE_TYPES:
                        name = PE_RESOURCE_TYPES[entry.id]

                epath = path + (name,)

                if hasattr(entry, "directory"):
                    resources.extend(collect_pe_resources(entry.directory, epath))

                else:
                    rva = entry.data.struct.OffsetToData
                    try:
                        offset = pe.get_offset_from_rva(rva)
                    except pefile.PEFormatError as e:
                        logger.warning("failed to get offset for resource RVA 0x%x: %s", rva, e)
                        continue

                    size = entry.data.struct.Size

                    if not slice_.contains_range(offset, size):
                        logger.warning("resource '%s' points to an invalid location, skipping", "/".join(epath))
                        continue

                    logger.debug("resource: %s, size: 0x%x", "/".join(epath), size)

                    resources.append(
                        ResourceLayout(
                            slice=slice_.slice(offset, size),
                            name="rsrc: " + "/".join(epath),
                        )
                    )

            return resources

        resources = collect_pe_resources(pe.DIRECTORY_ENTRY_RESOURCE)

        for resource in resources:
            # parse content of resources, such as embedded PE files
            from floss.layout import compute_layout

            resource.add_child(compute_layout(resource.slice))

        for resource in resources:
            # place resources into their parent section, usually .rsrc
            container = next(
                filter(lambda candidate: candidate.offset <= resource.offset < candidate.end, layout.children)
            )
            container.add_child(resource)

    return layout

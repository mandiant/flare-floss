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

"""Mach-O (thin and fat) layout construction."""

from __future__ import annotations

import struct
import logging
from typing import Any, Dict, List, Tuple, Optional, Sequence

import machofile  # type: ignore[import-untyped]

from floss.ranges import Range, Slice
from floss.layout.base import Layout, Structure, MachOLayout, SegmentLayout, MachOFatLayout
from floss.layout.types import Tag

logger = logging.getLogger("floss.layout.macho")


MACHO_MAGIC = 0xFEEDFACE
MACHO_CIGAM = 0xCEFAEDFE
MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

MACHO_MAGICS = {MACHO_MAGIC, MACHO_CIGAM, MACHO_MAGIC_64, MACHO_CIGAM_64}
FAT_MAGICS = {FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64}

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

CPU_TYPE_X86 = 0x7
CPU_TYPE_X86_64 = 0x1000007
CPU_TYPE_ARM = 0xC
CPU_TYPE_ARM64 = 0x100000C
CPU_TYPE_PPC = 0x12
CPU_TYPE_PPC64 = 0x10000012

CPU_TYPE_MAP = {
    CPU_TYPE_X86: "x86",
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM: "arm",
    CPU_TYPE_ARM64: "arm64",
    CPU_TYPE_PPC: "ppc",
    CPU_TYPE_PPC64: "ppc64",
}

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01


def _get_u32_be(data: bytes, offset: int) -> Optional[int]:
    if offset + 4 > len(data):
        return None
    return struct.unpack(">I", data[offset : offset + 4])[0]


def _is_macho_magic(magic: Optional[int]) -> bool:
    if magic is None:
        return False
    return magic in MACHO_MAGICS or magic in FAT_MAGICS


def _format_macho_arch(cputype: int, cpusubtype: int) -> str:
    base = CPU_TYPE_MAP.get(cputype, f"cpu_{cputype}")
    clean_subtype = cpusubtype & 0x00FFFFFF
    if cputype == CPU_TYPE_ARM64:
        if clean_subtype == 0:
            return "arm64"
        if clean_subtype == 2:
            return "arm64e"
        return f"arm64_{clean_subtype}"
    return base


def _parse_fat_arches(data: bytes) -> List[Tuple[str, int, int]]:
    """
    Parse the Mach-O fat header to extract architecture information.
    Returns:
        List of (arch_name, offset, size) tuples:
            - arch_name (str): The name of the architecture (e.g., 'x86_64', 'arm64').
            - offset (int): The file offset to the architecture-specific binary.
            - size (int): The size of the architecture-specific binary in bytes.
    """
    arches: List[Tuple[str, int, int]] = []
    if len(data) < 8:
        return arches

    magic = _get_u32_be(data, 0)
    if magic not in FAT_MAGICS:
        return arches

    swap = magic in {FAT_CIGAM, FAT_CIGAM_64}
    endian = "<" if swap else ">"
    nfat_arch = struct.unpack(endian + "I", data[4:8])[0]

    is_64 = magic in {FAT_MAGIC_64, FAT_CIGAM_64}
    offset = 8

    for _ in range(nfat_arch):
        if is_64:
            if offset + 32 > len(data):
                break
            cputype, cpusubtype, arch_offset, size, align, _reserved = struct.unpack(
                endian + "IIQQII", data[offset : offset + 32]
            )
            offset += 32
        else:
            if offset + 20 > len(data):
                break
            cputype, cpusubtype, arch_offset, size, _align = struct.unpack(endian + "IIIII", data[offset : offset + 20])
            offset += 20

        arch_name = _format_macho_arch(cputype, cpusubtype)
        arches.append((arch_name, arch_offset, size))

    return arches


def _parse_macho_endian_and_cmds(data: bytes) -> Tuple[str, bool, int, int]:
    if len(data) < 4:
        raise ValueError("insufficient data for Mach-O header")

    magic = struct.unpack(">I", data[:4])[0]
    if magic not in MACHO_MAGICS:
        raise ValueError("not a Mach-O header")

    big_endian = magic in {MACHO_MAGIC, MACHO_MAGIC_64}
    endian = ">" if big_endian else "<"
    is_64 = magic in {MACHO_MAGIC_64, MACHO_CIGAM_64}

    header_size = 32 if is_64 else 28
    if len(data) < header_size:
        raise ValueError("insufficient data for Mach-O header")

    ncmds = struct.unpack(endian + "I", data[16:20])[0]
    sizeofcmds = struct.unpack(endian + "I", data[20:24])[0]
    return endian, is_64, ncmds, sizeofcmds


def _parse_macho_load_commands(
    slice_: Slice, endian: str, is_64: bool, ncmds: int
) -> Tuple[List[Structure], Sequence[Dict[str, int]], Optional[Tuple[int, int]]]:
    structures: List[Structure] = []
    segments: List[Dict[str, int]] = []
    code_sig: Optional[Tuple[int, int]] = None

    data = slice_.data
    header_size = 32 if is_64 else 28
    if slice_.range.length >= header_size:
        structures.append(Structure(slice=slice_.slice(0, header_size), name="macho header"))
    offset = header_size
    cmd_header_size = 8
    seg_fmt = "II16sQQQQIIII" if is_64 else "II16sIIIIIIII"
    seg_header_size = struct.calcsize(endian + seg_fmt)

    for _ in range(ncmds):
        if offset + cmd_header_size > slice_.range.length:
            break

        cmd, cmdsize = struct.unpack(endian + "II", data[offset : offset + cmd_header_size])
        if cmdsize < cmd_header_size:
            break

        cmd_offset = offset
        cmd_end = offset + cmdsize
        if cmd_end > slice_.range.length:
            break

        structures.append(Structure(slice=slice_.slice(cmd_offset, cmdsize), name="load command"))

        if cmd == LC_CODE_SIGNATURE:
            if cmdsize >= 16:
                dataoff = struct.unpack(endian + "I", data[cmd_offset + 8 : cmd_offset + 12])[0]
                datasize = struct.unpack(endian + "I", data[cmd_offset + 12 : cmd_offset + 16])[0]
                code_sig = (int(dataoff), int(datasize))

        if cmd in {LC_SEGMENT, LC_SEGMENT_64}:
            if cmdsize >= seg_header_size:
                seg_data = data[cmd_offset : cmd_offset + seg_header_size]
                seg_values = struct.unpack(endian + seg_fmt, seg_data)
                segname = seg_values[2].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                fileoff = seg_values[5]
                filesize = seg_values[6]
                nsects = seg_values[9]

                segments.append({"segname": segname, "offset": int(fileoff), "size": int(filesize)})

                structures.append(Structure(slice=slice_.slice(cmd_offset, seg_header_size), name="segment header"))

                section_offset = cmd_offset + seg_header_size
                section_size = 80 if is_64 else 68
                for _section_index in range(nsects):
                    if section_offset + section_size > cmd_end:
                        break
                    structures.append(
                        Structure(slice=slice_.slice(section_offset, section_size), name="section header")
                    )
                    section_offset += section_size

        offset += cmdsize

    return structures, segments, code_sig


def _add_macho_segments(parent: Layout, slice_: Slice, segments: Sequence[Dict[str, int]]):
    for segment in segments:
        offset = segment.get("offset", 0)
        size = segment.get("size", 0)
        raw_name = segment.get("segname", "segment")
        if isinstance(raw_name, bytes):
            name = raw_name.decode("utf-8", errors="replace")
        else:
            name = str(raw_name)
        name = name.replace("\x00", "").strip()
        if not name:
            name = f"segment@0x{offset:x}"

        if size <= 0:
            continue

        if not slice_.contains_range(offset, size):
            if offset >= slice_.range.length:
                logger.warning("Mach-O segment %s out of range", name)
                continue
            size = slice_.range.length - offset
            if size <= 0:
                continue
            logger.warning("Mach-O segment %s size out of range, truncating", name)

        parent.add_child(SegmentLayout(slice=slice_.slice(offset, size), name=name))


def _attach_nested_layout(parent: Layout, child: Layout):
    container = next(
        (candidate for candidate in parent.children if candidate.offset <= child.offset < candidate.end),
        None,
    )
    if container and child.end <= container.end:
        container.add_child(child)
    else:
        parent.add_child(child)


def _parse_superblob_blobs(slice_: Slice, cs_offset: int, cs_size: int) -> Sequence[Tuple[int, int, int]]:
    blobs: List[Tuple[int, int, int]] = []
    if cs_size <= 0:
        return blobs

    if not slice_.contains_range(cs_offset, cs_size):
        return blobs

    cs_data = slice_.data[cs_offset : cs_offset + cs_size]
    if len(cs_data) < 12:
        return blobs

    magic, length, count = struct.unpack(">III", cs_data[:12])
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return blobs

    if length > cs_size:
        length = cs_size

    index_offset = 12
    for _ in range(count):
        if index_offset + 8 > length:
            break
        _blob_type, blob_offset = struct.unpack(">II", cs_data[index_offset : index_offset + 8])
        index_offset += 8

        if blob_offset + 8 > length:
            continue

        blob_magic, blob_length = struct.unpack(">II", cs_data[blob_offset : blob_offset + 8])
        if blob_length < 8:
            continue

        if blob_offset + blob_length > length:
            blob_length = length - blob_offset
            if blob_length < 8:
                continue

        blobs.append((blob_magic, cs_offset + blob_offset, blob_length))

    return blobs


def _scan_entitlements_plist(slice_: Slice, cs_offset: int, cs_size: int) -> Sequence[Tuple[int, int]]:
    entitlements: List[Tuple[int, int]] = []
    if cs_size <= 0:
        return entitlements

    if not slice_.contains_range(cs_offset, cs_size):
        return entitlements

    cs_data = slice_.data[cs_offset : cs_offset + cs_size]

    xml_marker = b"<?xml"
    plist_end = b"</plist>"
    start = 0
    while True:
        index = cs_data.find(xml_marker, start)
        if index == -1:
            break
        end_index = cs_data.find(plist_end, index)
        if end_index != -1:
            end_index += len(plist_end)
            entitlements.append((cs_offset + index, end_index - index))
            start = end_index
        else:
            break

    bplist_marker = b"bplist00"
    index = cs_data.find(bplist_marker)
    if index != -1:
        bplist_len = _find_bplist_length(cs_data, index)
        if bplist_len:
            entitlements.append((cs_offset + index, bplist_len))

    return entitlements


def _find_bplist_length(data: bytes, start: int) -> Optional[int]:
    bplist_marker = b"bplist00"
    if start < 0 or start + 8 > len(data):
        return None

    trailer_size = 32
    min_len = 8 + trailer_size
    max_len = len(data) - start
    if max_len < min_len:
        return None

    for end in range(start + max_len, start + min_len - 1, -1):
        trailer_offset = end - trailer_size
        trailer = data[trailer_offset:end]

        offset_size = trailer[6]
        object_ref_size = trailer[7]
        num_objects = int.from_bytes(trailer[8:16], "big")
        top_object = int.from_bytes(trailer[16:24], "big")
        offset_table_offset = int.from_bytes(trailer[24:32], "big")

        if offset_size == 0 or offset_size > 8:
            continue
        if object_ref_size == 0 or object_ref_size > 8:
            continue
        if num_objects == 0:
            continue
        if top_object >= num_objects:
            continue

        length = end - start
        if offset_table_offset < 8 or offset_table_offset >= length:
            continue

        offset_table_size = num_objects * offset_size
        if offset_table_offset + offset_table_size > length - trailer_size:
            continue

        if data[start : start + 8] == bplist_marker:
            return length

    return None


def _populate_thin_macho_layout(layout: MachOLayout, slice_: Slice):
    try:
        endian, is_64, ncmds, _sizeofcmds = _parse_macho_endian_and_cmds(slice_.data)
        structures, segments, code_sig = _parse_macho_load_commands(slice_, endian, is_64, ncmds)
    except ValueError:
        structures = []
        segments = []
        code_sig = None

    if segments:
        _add_macho_segments(layout, slice_, segments)

    if code_sig:
        cs_offset, cs_size = code_sig
        if slice_.contains_range(cs_offset, cs_size):
            cs_layout = SegmentLayout(slice=slice_.slice(cs_offset, cs_size), name="code signature")
            blobs = _parse_superblob_blobs(slice_, cs_offset, cs_size)
            entitlements: List[Tuple[int, int]] = []
            for blob_magic, blob_offset, blob_length in blobs:
                if not slice_.contains_range(blob_offset, blob_length):
                    continue
                if blob_magic in {CSMAGIC_EMBEDDED_ENTITLEMENTS, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS}:
                    entitlements.append((blob_offset, blob_length))
                elif blob_magic == CSMAGIC_BLOBWRAPPER:
                    cs_layout.add_child(
                        SegmentLayout(
                            slice=slice_.slice(blob_offset, blob_length),
                            name="certificates",
                        )
                    )

            if not entitlements:
                entitlements = list(_scan_entitlements_plist(slice_, cs_offset, cs_size))

            for ent_offset, ent_size in entitlements:
                if slice_.contains_range(ent_offset, ent_size):
                    plist_layout = SegmentLayout(
                        slice=slice_.slice(ent_offset, ent_size),
                        name="plist: entitlements",
                    )
                    _attach_nested_layout(cs_layout, plist_layout)
            _attach_nested_layout(layout, cs_layout)

    if structures:
        for structure in structures:
            for offset_value in structure.slice.range:
                layout.structures_by_address[offset_value] = structure


def compute_macho_layout(slice_: Slice) -> Layout:
    data = slice_.data
    magic = _get_u32_be(data, 0)

    if magic in FAT_MAGICS:
        layout = MachOFatLayout(slice=slice_, name="macho (fat)")
        arches = _parse_fat_arches(data)
        for arch_name, offset, size in arches:
            if not slice_.contains_range(offset, size):
                logger.warning("fat arch %s out of range, skipping", arch_name)
                continue

            arch_slice = slice_.slice(offset, size)
            arch_layout = MachOLayout(slice=arch_slice, name=f"macho: {arch_name}", arch=arch_name)

            _populate_thin_macho_layout(arch_layout, arch_slice)

            layout.add_child(arch_layout)

        return layout

    arch_name = "macho"
    try:
        macho = machofile.UniversalMachO(data=data)
        macho.parse()
        header = macho.get_macho_header()
        if isinstance(header, dict):
            cputype = header.get("cputype")
            cpusubtype = header.get("cpusubtype")
            if isinstance(cputype, int) and isinstance(cpusubtype, int):
                arch_name = _format_macho_arch(cputype, cpusubtype)
    except Exception as e:
        logger.debug("failed to parse Mach-O header via machofile: %s", e)

    thin_layout = MachOLayout(slice=slice_, name=f"macho: {arch_name}", arch=arch_name)

    _populate_thin_macho_layout(thin_layout, slice_)

    return thin_layout

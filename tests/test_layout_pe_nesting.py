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

import struct

import pytest

import floss.pipeline
from floss.layout import MAX_NESTING_DEPTH, LayoutNestingError, compute_layout
from floss.ranges import Slice


def build_pe_with_resource(data_rva: int, data_size: int, total: int = 0x1000) -> bytes:
    """
    A single-section PE32 whose .rsrc section (RVA 0x1000, file offset 0x200) holds one
    resource directory tree with a single data entry pointing at (data_rva, data_size).
    """
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<I", opt, 28, 0x400000)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<I", opt, 56, 0x4000)
    struct.pack_into("<I", opt, 60, 0x200)
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 8 * 2, 0x1000, 0x200)

    hdr = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40))
    hdr += b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(opt), 0x102)
    hdr += opt
    hdr += struct.pack("<8sIIIIIIHHI", b".rsrc", 0x1000, 0x1000, 0xE00, 0x200, 0, 0, 0, 0, 0x40000040)
    hdr += b"\x00" * (0x200 - len(hdr))

    rsrc = bytearray(0x200)
    struct.pack_into("<HH", rsrc, 12, 0, 1)
    struct.pack_into("<II", rsrc, 16, 10, 0x80000000 | 0x18)
    struct.pack_into("<HH", rsrc, 0x18 + 12, 0, 1)
    struct.pack_into("<II", rsrc, 0x18 + 16, 1, 0x80000000 | 0x30)
    struct.pack_into("<HH", rsrc, 0x30 + 12, 0, 1)
    struct.pack_into("<II", rsrc, 0x30 + 16, 0x409, 0x48)
    struct.pack_into("<IIII", rsrc, 0x48, data_rva, data_size, 0, 0)

    body = bytearray(hdr + rsrc)
    while len(body) < total:
        body += b"section-string-%04x\x00" % len(body)
    return bytes(body[:total])


def test_resource_covering_whole_file_is_rejected():
    data = build_pe_with_resource(data_rva=0, data_size=0x1000)
    with pytest.raises(LayoutNestingError):
        compute_layout(Slice.from_bytes(data))


def test_resource_covering_whole_file_falls_back_to_binary():
    data = build_pe_with_resource(data_rva=0, data_size=0x1000)
    layout = floss.pipeline.compute_layout(data, 4)
    assert layout is not None
    assert layout.name == "binary"
    assert layout.children == []


def test_ordinary_resource_still_nests():
    data = build_pe_with_resource(data_rva=0x1100, data_size=0x100)
    layout = compute_layout(Slice.from_bytes(data))
    rsrc = next(child for child in layout.children if child.name == ".rsrc")
    assert [child.name for child in rsrc.children] == ["rsrc: RCData/1/1033"]
    assert [child.name for child in rsrc.children[0].children] == ["binary"]


def test_nesting_depth_is_bounded():
    data = build_pe_with_resource(data_rva=0x1100, data_size=0x100)
    compute_layout(Slice.from_bytes(data), depth=MAX_NESTING_DEPTH - 1)
    with pytest.raises(LayoutNestingError):
        compute_layout(Slice.from_bytes(data), depth=MAX_NESTING_DEPTH)

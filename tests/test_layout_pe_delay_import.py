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

from floss.pipeline import tag_layout, compute_layout
from floss.layout.extract import collect_strings

IMAGE_BASE = 0x400000
ALIGNMENT = 0x200
HEADERS_SIZE = 0x200
RDATA_RVA = 0x1000
RDATA_SIZE = 0x200
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13

# offsets within .rdata
DESCRIPTOR = 0x00
INT = 0x40
IAT = 0x60
DLL_NAME = 0x100
HINT_NAME = 0x120
HMODULE = 0x180


def build_pe(rdata: bytes, directories: dict[int, tuple[int, int]]) -> bytes:
    """PE32 with a single .rdata section at RVA 0x1000, file offset 0x200."""
    file_header = struct.pack(
        "<HHIIIHH",
        0x14C,  # Machine: i386
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xE0,  # SizeOfOptionalHeader
        0x102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    fields = {
        "Magic": ("H", 0x10B),
        "MajorLinkerVersion": ("B", 0),
        "MinorLinkerVersion": ("B", 0),
        "SizeOfCode": ("I", 0),
        "SizeOfInitializedData": ("I", RDATA_SIZE),
        "SizeOfUninitializedData": ("I", 0),
        "AddressOfEntryPoint": ("I", RDATA_RVA),
        "BaseOfCode": ("I", RDATA_RVA),
        "BaseOfData": ("I", RDATA_RVA),
        "ImageBase": ("I", IMAGE_BASE),
        "SectionAlignment": ("I", 0x1000),
        "FileAlignment": ("I", ALIGNMENT),
        "MajorOperatingSystemVersion": ("H", 4),
        "MinorOperatingSystemVersion": ("H", 0),
        "MajorImageVersion": ("H", 0),
        "MinorImageVersion": ("H", 0),
        "MajorSubsystemVersion": ("H", 4),
        "MinorSubsystemVersion": ("H", 0),
        "Win32VersionValue": ("I", 0),
        "SizeOfImage": ("I", RDATA_RVA + 0x1000),
        "SizeOfHeaders": ("I", HEADERS_SIZE),
        "CheckSum": ("I", 0),
        "Subsystem": ("H", 2),  # WINDOWS_GUI
        "DllCharacteristics": ("H", 0),
        "SizeOfStackReserve": ("I", 0x100000),
        "SizeOfStackCommit": ("I", 0x1000),
        "SizeOfHeapReserve": ("I", 0x100000),
        "SizeOfHeapCommit": ("I", 0x1000),
        "LoaderFlags": ("I", 0),
        "NumberOfRvaAndSizes": ("I", 16),
    }
    optional_header = struct.pack(
        "<" + "".join(fmt for fmt, _ in fields.values()), *(value for _, value in fields.values())
    )
    optional_header += b"".join(struct.pack("<II", *directories.get(i, (0, 0))) for i in range(16))

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata",  # Name
        RDATA_SIZE,  # VirtualSize
        RDATA_RVA,  # VirtualAddress
        RDATA_SIZE,  # SizeOfRawData
        HEADERS_SIZE,  # PointerToRawData
        0,  # PointerToRelocations
        0,  # PointerToLinenumbers
        0,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        0x40000040,  # Characteristics: INITIALIZED_DATA | MEM_READ
    )

    e_lfanew = 0x40
    headers = b"MZ".ljust(0x3C, b"\x00") + struct.pack("<I", e_lfanew) + b"PE\x00\x00"
    headers += file_header + optional_header + section_header
    return headers.ljust(HEADERS_SIZE, b"\x00") + rdata.ljust(RDATA_SIZE, b"\x00")


def build_delay_import_pe(old_style: bool) -> bytes:
    """PE32 whose .rdata holds only a delay import of USER32.dll!MessageBoxA.

    old-style descriptors (grAttrs=0, pre-VC6) store VAs instead of RVAs.
    """
    base = IMAGE_BASE if old_style else 0

    def addr(offset: int) -> int:
        return base + RDATA_RVA + offset

    rdata = bytearray(RDATA_SIZE)
    descriptor = struct.pack(
        "<8I",
        0 if old_style else 1,  # grAttrs: dlattrRva
        addr(DLL_NAME),  # szName
        addr(HMODULE),  # phmod
        addr(IAT),  # pIAT
        addr(INT),  # pINT
        0,  # pBoundIAT
        0,  # pUnloadIAT
        0,  # dwTimeStamp
    )
    rdata[DESCRIPTOR : DESCRIPTOR + len(descriptor)] = descriptor
    rdata[INT : INT + 8] = struct.pack("<II", addr(HINT_NAME), 0)
    rdata[IAT : IAT + 8] = struct.pack("<II", addr(HINT_NAME), 0)
    rdata[DLL_NAME : DLL_NAME + 11] = b"USER32.dll\x00"
    rdata[HINT_NAME : HINT_NAME + 14] = b"\x00\x00MessageBoxA\x00"

    return build_pe(bytes(rdata), {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: (RDATA_RVA + DESCRIPTOR, 0x40)})


@pytest.mark.parametrize("old_style", [False, True])
def test_delay_import_names_are_marked_as_import_table(old_style):
    layout = compute_layout(build_delay_import_pe(old_style), 4)
    tag_layout(layout, enable_tags=False)
    structures = {s.string.string: s.structure for s in collect_strings(layout)}
    assert structures["USER32.dll"] == "import table"
    assert structures["MessageBoxA"] == "import table"

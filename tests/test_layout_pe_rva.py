from pathlib import Path

import pefile
import pytest

from floss.layout.pe import collect_pe_structures, get_physical_offset_from_rva
from floss.layout.base import Slice

CD = Path(__file__).resolve().parent
DOTNET_HELLO = CD / "data" / "language" / "dotnet" / "dotnet-hello" / "bin" / "dotnet-hello.exe"


@pytest.fixture(scope="module")
def pe():
    """dotnet-hello.exe with .text VirtualSize raised from 0x3b8 to 0x3000 (SizeOfRawData stays 0x400)."""
    pe = pefile.PE(data=DOTNET_HELLO.read_bytes())
    pe.sections[0].Misc_VirtualSize = 0x3000
    return pefile.PE(data=pe.write())


def test_backed_rva_maps_into_section(pe):
    assert get_physical_offset_from_rva(pe, 0x2100) == 0x300


def test_rva_in_virtual_padding_is_rejected(pe):
    assert pe.get_offset_from_rva(0x2500) == 0x700
    with pytest.raises(pefile.PEFormatError):
        get_physical_offset_from_rva(pe, 0x2500)


def test_header_rva_maps_to_itself(pe):
    assert get_physical_offset_from_rva(pe, 0x80) == 0x80


def test_rva_beyond_sections_is_rejected(pe):
    with pytest.raises(pefile.PEFormatError):
        get_physical_offset_from_rva(pe, 0x100000)


@pytest.fixture(scope="module")
def pe_import_padding():
    """dotnet-hello.exe with .text SizeOfRawData reduced to 0x390 so import names fall into virtual padding."""
    pe = pefile.PE(data=DOTNET_HELLO.read_bytes())
    pe.sections[0].Misc_VirtualSize = 0x3000
    pe.sections[0].SizeOfRawData = 0x390
    return pefile.PE(data=pe.write())


def test_import_name_rva_in_virtual_padding_is_rejected(pe_import_padding):
    slice_ = Slice.from_bytes(pe_import_padding.__data__)
    structs = collect_pe_structures(slice_, pe_import_padding)

    # The .text section physical end is its PointerToRawData + SizeOfRawData
    text_end = pe_import_padding.sections[0].PointerToRawData + pe_import_padding.sections[0].SizeOfRawData

    for struct in structs:
        if struct.name in ("import table", "export table"):
            assert (
                struct.slice.range.offset < text_end
            ), f"{struct.name} emitted in virtual padding/unrelated section: {hex(struct.slice.range.offset)}"

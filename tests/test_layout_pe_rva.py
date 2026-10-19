from pathlib import Path

import pefile
import pytest

from floss.layout import compute_layout
from floss.ranges import Slice
from floss.layout.pe import get_physical_offset_from_rva
from floss.layout.base import PELayout

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
def unaligned():
    """dotnet-hello.exe with .text PointerToRawData moved from 0x200 to 0x210 (FileAlignment 0x200)."""
    pe = pefile.PE(data=DOTNET_HELLO.read_bytes())
    pe.sections[0].PointerToRawData = 0x210
    return pe.write()


def test_unaligned_pointer_to_raw_data_is_not_rounded(unaligned):
    pe = pefile.PE(data=unaligned)
    assert pe.sections[0].get_PointerToRawData_adj() == 0x200
    assert pe.get_offset_from_rva(0x2000) == 0x200
    assert get_physical_offset_from_rva(pe, 0x2000) == 0x210
    assert get_physical_offset_from_rva(pe, 0x2100) == 0x310


def test_section_nodes_and_header_follow_raw_pointer(unaligned):
    layout = compute_layout(Slice.from_bytes(bytes(unaligned)))
    assert isinstance(layout, PELayout)
    header = next(child for child in layout.children if child.name == "header")
    text = next(child for child in layout.children if child.name == ".text")
    assert (header.offset, header.end) == (0, 0x210)
    assert (text.offset, text.end) == (0x210, 0x610)
    assert not any(child.name == "gap" for child in layout.children)

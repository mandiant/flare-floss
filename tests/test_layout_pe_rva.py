from pathlib import Path

import pefile
import pytest

from floss.layout.pe import get_physical_offset_from_rva

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

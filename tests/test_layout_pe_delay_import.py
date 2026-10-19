import struct

import pytest

from floss.pipeline import tag_layout, compute_layout
from floss.layout.extract import collect_strings

IMAGE_BASE = 0x400000


def build_delay_import_pe(old_style: bool) -> bytes:
    """PE32 with one .rdata section holding only a delay import of USER32.dll!MessageBoxA.

    old-style descriptors (grAttrs=0, pre-VC6) store VAs instead of RVAs.
    """
    base = IMAGE_BASE if old_style else 0

    file_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        0,
        0,
        0,
        0x200,
        0,
        0x1000,
        0x1000,
        0x1000,
        IMAGE_BASE,
        0x1000,
        0x200,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        0x2000,
        0x200,
        0,
        2,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    directories = [(0, 0)] * 16
    directories[13] = (0x1000, 0x40)
    optional_header += b"".join(struct.pack("<II", rva, size) for rva, size in directories)
    section_header = struct.pack("<8sIIIIIIHHI", b".rdata", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x40000040)

    headers = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00"
    headers += file_header + optional_header + section_header
    headers = headers.ljust(0x200, b"\x00")

    rdata = bytearray(0x200)
    descriptor = (0 if old_style else 1, base + 0x1100, base + 0x1180, base + 0x1060, base + 0x1040, 0, 0, 0)
    rdata[0x00:0x20] = struct.pack("<8I", *descriptor)
    rdata[0x40:0x48] = struct.pack("<II", base + 0x1120, 0)
    rdata[0x60:0x68] = struct.pack("<II", base + 0x1120, 0)
    rdata[0x100:0x10B] = b"USER32.dll\x00"
    rdata[0x120:0x12E] = b"\x00\x00MessageBoxA\x00"
    return headers + bytes(rdata)


@pytest.mark.parametrize("old_style", [False, True])
def test_delay_import_names_are_marked_as_import_table(old_style):
    layout = compute_layout(build_delay_import_pe(old_style), 4)
    tag_layout(layout, enable_tags=False)
    structures = {s.string.string: s.structure for s in collect_strings(layout)}
    assert structures["USER32.dll"] == "import table"
    assert structures["MessageBoxA"] == "import table"

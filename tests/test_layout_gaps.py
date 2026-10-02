import struct
from pathlib import Path

import pefile

from floss.layout import compute_layout
from floss.ranges import Slice


def test_pe_layout_fills_all_section_gaps():
    path = Path(__file__).parent / "data" / "language" / "dotnet" / "dotnet-hello" / "bin" / "dotnet-hello.exe"
    buf = bytearray(path.read_bytes())
    pe = pefile.PE(data=bytes(buf))

    for section in pe.sections[:2]:
        struct.pack_into("<I", buf, section.get_field_absolute_offset("SizeOfRawData"), 0x200)

    layout = compute_layout(Slice.from_bytes(bytes(buf)))

    children = layout.children
    assert children[0].offset == 0
    assert children[-1].end == len(buf)

    for prior, current in zip(children, children[1:]):
        assert prior.end == current.offset, f"hole between {prior.name} and {current.name}"

    assert [c.name for c in children] == [
        "header",
        ".text",
        "gap",
        ".rsrc",
        "gap",
        ".reloc",
    ]

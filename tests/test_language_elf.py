import pathlib

import pytest

from floss.language.elf import ELF, PF_R, Segment


@pytest.fixture(scope="module")
def elf_sample_path() -> pathlib.Path:
    return pathlib.Path(__file__).parent / "data" / "language" / "go" / "go-hello" / "bin" / "go-hello"


def test_iter_load_segments(elf_sample_path):
    elf = ELF(elf_sample_path)

    segments = list(elf.iter_load_segments())

    assert len(segments) == 3
    assert segments[0].vaddr_start == 0x400000
    assert segments[0].vaddr_end == 0x481387
    assert segments[0].file_off == 0x0
    assert segments[0].file_end == 0x81387


def test_va_mapping_and_read_known_text_bytes(elf_sample_path):
    elf = ELF(elf_sample_path)

    assert elf.va_to_file_offset(0x401000) == 0x1000

    expected = bytes.fromhex("49 3b 66 10 76 38 48 83 ec 18 48 89 6c 24 10 48")
    assert elf.read_va(0x401000, len(expected)) == expected


def test_ranges_and_mapping_helpers(elf_sample_path):
    elf = ELF(elf_sample_path)

    executable_segments = list(elf.iter_executable_segments())
    readonly_segments = list(elf.iter_readonly_segments())

    assert len(executable_segments) == 1
    assert executable_segments[0].vaddr_start == 0x400000

    assert readonly_segments
    assert all(not (segment.flags & 1) for segment in readonly_segments)

    low_va, high_va = elf.get_mapped_range()
    assert (low_va, high_va) == (0x400000, 0x55D830)

    assert elf.is_va_mapped(0x401000)
    assert not elf.is_va_mapped(0x390000)


def test_read_va_across_adjacent_file_backed_segments():
    elf = ELF.__new__(ELF)
    elf._data = b"ABCDEFGH"
    elf._segments = [
        Segment(vaddr_start=0x1000, vaddr_end=0x1004, file_off=0, file_end=4, flags=PF_R),
        Segment(vaddr_start=0x1004, vaddr_end=0x1008, file_off=4, file_end=8, flags=PF_R),
    ]

    assert elf.read_va(0x1002, 4) == b"CDEF"


def test_read_va_rejects_non_file_backed_gap():
    elf = ELF.__new__(ELF)
    elf._data = b"ABCDEFGH"
    elf._segments = [
        Segment(vaddr_start=0x1000, vaddr_end=0x1008, file_off=0, file_end=4, flags=PF_R),
        Segment(vaddr_start=0x1008, vaddr_end=0x100C, file_off=4, file_end=8, flags=PF_R),
    ]

    with pytest.raises(ValueError, match="not fully file-backed"):
        elf.read_va(0x1002, 6)

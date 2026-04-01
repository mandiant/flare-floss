import struct
from typing import List, Tuple, Union, Iterable, Optional
from pathlib import Path
from dataclasses import dataclass

# ELF program header constants
PT_LOAD = 1  # loadable segment

PF_X = 1  # executable
PF_W = 2  # writable
PF_R = 4  # readable

"""
This file is the ELF counterpart to PE section mapping
It ensures FLOSS can safely and accurately extract strings from ELF binaries, respecting the actual memory layout and permissions

---Comparison to PE implementation
PE uses sections (rdata, .text) and section flags (IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_EXECUT)
- PE parsing maps RVA (relative virtual address) to file offset using section headers
- String extraction scans .rdata for Go string headers because it’s a well-defined, contiguous region.
ELF uses segments (PT_LOAD) and segment flags (PF_R, PF_X, etc.)
- ELF parsing maps VA to file offset using program headers
- String extraction scans all read-only, non-executable PT_LOAD segments, since .rodata may not be contiguous or directly mappable
"""


@dataclass(frozen=True)
class Segment:
    """
    Models a single memory segment in an ELF binary
    Represents a PT_LOAD segment’s virtual address range, file offset range, and permission flags
    ELF binaries organize memory by segments, not sections
    String extraction, VA mapping, and blob carving require knowing which segment a VA belongs to and whether it’s readable/file-backe
    """

    vaddr_start: int
    vaddr_end: int
    file_off: int
    file_end: int
    flags: int

    def contains_va(self, va: int) -> bool:
        return self.vaddr_start <= va < self.vaddr_end

    def contains_file_backed_va(self, va: int) -> bool:
        size = self.file_end - self.file_off
        return self.vaddr_start <= va < self.vaddr_start + size


class ELF:
    """
    Minimal ELF(x86-64) helper for VA mapping and byte reading
    """

    def __init__(self, source: Union[Path, str, bytes]):
        if isinstance(source, bytes):
            self._data = source
        else:
            self._data = Path(source).read_bytes()

        self._segments = self._parse_load_segments(self._data)
        if not self._segments:
            raise ValueError("ELF has no PT_LOAD segments")

    @property
    def data(self) -> bytes:
        return self._data

    def iter_load_segments(self) -> Iterable[Segment]:
        return iter(self._segments)

    def iter_executable_segments(self) -> Iterable[Segment]:
        return (segment for segment in self._segments if segment.flags & PF_X)

    def iter_readable_segments(self) -> Iterable[Segment]:
        return (segment for segment in self._segments if segment.flags & PF_R)

    def iter_readonly_segments(self) -> Iterable[Segment]:
        return (segment for segment in self._segments if (segment.flags & PF_R) and not (segment.flags & PF_X))

    def get_mapped_range(self) -> Tuple[int, int]:
        low = min(segment.vaddr_start for segment in self._segments)
        high = max(segment.vaddr_end for segment in self._segments)
        return low, high

    def is_va_mapped(self, va: int) -> bool:
        return self._find_va_segment(va) is not None

    def va_to_file_offset(self, va: int) -> int:
        segment = self._find_file_backed_va_segment(va)
        if segment is None:
            raise ValueError(f"VA is not file-backed: 0x{va:x}")

        return segment.file_off + (va - segment.vaddr_start)

    def read_va(self, va: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        if size == 0:
            return b""

        buf = bytearray()
        current_va = va
        remaining = size

        while remaining > 0:
            segment = self._find_file_backed_va_segment(current_va)
            if segment is None:
                raise ValueError(f"VA range is not fully file-backed: 0x{current_va:x}")

            file_backed_end_va = segment.vaddr_start + (segment.file_end - segment.file_off)
            chunk_size = min(remaining, file_backed_end_va - current_va)
            if chunk_size <= 0:
                raise ValueError("invalid VA range")

            file_offset = segment.file_off + (current_va - segment.vaddr_start)
            buf.extend(self._data[file_offset : file_offset + chunk_size])

            current_va += chunk_size
            remaining -= chunk_size

        return bytes(buf)

    @staticmethod
    def _parse_load_segments(data: bytes) -> List[Segment]:
        if len(data) < 0x40:
            raise ValueError("file too small for ELF header")

        e_ident = data[:16]
        if e_ident[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")

        elf_class = e_ident[4]
        if elf_class != 2:
            raise ValueError("only ELF64 is supported")

        ei_data = e_ident[5]
        if ei_data != 1:
            raise ValueError("only little-endian ELF is supported")

        # ELF64 header (little-endian)
        # e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
        # e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
        (
            _,
            e_machine,
            _,
            _,
            e_phoff,
            _,
            _,
            _,
            e_phentsize,
            e_phnum,
            _,
            _,
            _,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

        # EM_X86_64
        if e_machine != 62:
            raise ValueError("only x86-64 ELF is supported")

        expected_phentsize = struct.calcsize("<IIQQQQQQ")
        if e_phentsize < expected_phentsize:
            raise ValueError("unsupported program header size")

        load_segments: List[Segment] = []
        for index in range(e_phnum):
            entry_offset = e_phoff + index * e_phentsize
            if entry_offset + expected_phentsize > len(data):
                raise ValueError("program header exceeds file size")

            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(
                "<IIQQQQQQ", data, entry_offset
            )

            if p_type != PT_LOAD:
                continue

            file_end = p_offset + p_filesz
            if file_end > len(data):
                raise ValueError("PT_LOAD file range exceeds file size")

            load_segments.append(
                Segment(
                    vaddr_start=p_vaddr,
                    vaddr_end=p_vaddr + p_memsz,
                    file_off=p_offset,
                    file_end=file_end,
                    flags=p_flags,
                )
            )

        return sorted(load_segments, key=lambda segment: segment.vaddr_start)

    def _find_va_segment(self, va: int) -> Optional[Segment]:
        for segment in self._segments:
            if segment.contains_va(va):
                return segment
        return None

    def _find_file_backed_va_segment(self, va: int) -> Optional[Segment]:
        for segment in self._segments:
            if segment.contains_file_backed_va(va):
                return segment
        return None

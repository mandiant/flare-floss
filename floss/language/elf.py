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


import io
from typing import List, Tuple, Union, Iterable, Optional
from pathlib import Path
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile

# ELF program header constants
PT_LOAD = 1  # loadable segment

PF_X = 1  # executable
PF_W = 2  # writable
PF_R = 4  # readable


@dataclass(frozen=True)
class Segment:
    """
    Models a single memory segment in an ELF binary
    ELF binaries organize memory by segments, not sections
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
        # if source as bytes passed
        if isinstance(source, bytes):
            self._data = source
        # if source as Path or str passed
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
        return (seg for seg in self._segments if seg.flags & PF_X)

    def iter_readable_segments(self) -> Iterable[Segment]:
        return (seg for seg in self._segments if seg.flags & PF_R)

    def iter_readonly_segments(self) -> Iterable[Segment]:
        return (seg for seg in self._segments if (seg.flags & PF_R) and not (seg.flags & PF_X))

    def get_mapped_range(self) -> Tuple[int, int]:
        low = min(seg.vaddr_start for seg in self._segments)
        high = max(seg.vaddr_end for seg in self._segments)
        return low, high

    def is_va_mapped(self, va: int) -> bool:
        return self._find_va_segment(va) is not None

    def va_to_file_offset(self, va: int) -> int:
        seg = self._find_file_backed_va_segment(va)
        if seg is None:
            raise ValueError(f"VA is not file backed: 0x{va:x}")

        return seg.file_off + (va - seg.vaddr_start)

    def read_va(self, va: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non negative")
        if size == 0:
            return b""

        out = bytearray()
        cur = va
        remaining = size

        while remaining > 0:
            segment = self._find_file_backed_va_segment(cur)
            if segment is None:
                raise ValueError(f"VA range is not fully file backed: 0x{cur:x}")

            file_backed_end_va = segment.vaddr_start + (segment.file_end - segment.file_off)
            chunk_size = min(remaining, file_backed_end_va - cur)
            if chunk_size <= 0:
                raise ValueError("invalid VA range")

            file_offset = segment.file_off + (cur - segment.vaddr_start)
            out.extend(self._data[file_offset : file_offset + chunk_size])

            cur += chunk_size
            remaining -= chunk_size

        return bytes(out)

    @staticmethod
    def _parse_load_segments(data: bytes) -> List[Segment]:
        stream = io.BytesIO(data)

        try:
            elf = ELFFile(stream)
        except Exception:
            raise ValueError("not a valid ELF file")

        # contraints for now, might update later
        if elf.elfclass != 64:
            raise ValueError("only ELF64 is supported")
        if not elf.little_endian:
            raise ValueError("only little endian is supported")
        if elf["e_machine"] != "EM_X86_64":
            raise ValueError("only x86-64 ELF is supported")

        size = len(data)
        segments: list[Segment] = []

        for ph in elf.iter_segments():
            if ph["p_type"] != "PT_LOAD":
                continue

            p_offset = int(ph["p_offset"])
            p_filesz = int(ph["p_filesz"])
            p_memsz = int(ph["p_memsz"])
            p_vaddr = int(ph["p_vaddr"])
            p_flags = int(ph["p_flags"])

            file_end = p_offset + p_filesz
            if file_end > size:
                raise ValueError("PT_LOAD file range exceeds file size")

            segments.append(
                Segment(
                    vaddr_start=p_vaddr,
                    vaddr_end=p_vaddr + p_memsz,
                    file_off=p_offset,
                    file_end=file_end,
                    flags=p_flags,
                )
            )

        return sorted(segments, key=lambda s: s.vaddr_start)

    def _find_va_segment(self, va: int) -> Optional[Segment]:
        for seg in self._segments:
            if seg.contains_va(va):
                return seg
        return None

    def _find_file_backed_va_segment(self, va: int) -> Optional[Segment]:
        for segment in self._segments:
            if segment.contains_file_backed_va(va):
                return segment
        return None

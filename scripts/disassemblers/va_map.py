#!/usr/bin/env python3
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


# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License
#  You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""
va_map.py

Shared helpers to map file offsets from a FLOSS result document to
virtual addresses within a PE image.

`static_strings` and `language_strings` carry a file offset (position of the
string in the input file), while disassemblers like IDA Pro and x64dbg work
with virtual addresses. These helpers translate file offsets to RVAs/VAs using
pefile, so that the render scripts can annotate static and language-specific
strings.

This is only possible when the original sample is available at the path
recorded in the result document metadata, and when it is a PE file.
Other inputs (e.g. shellcode, ELF, Mach-O) do not carry a mapping that the
renderers can use.
"""

import logging
import itertools
from typing import List, Tuple, Optional, NamedTuple
from pathlib import Path

import pefile

from floss.results import ResultDocument

logger = logging.getLogger("floss.va_map")


class ImageRegion(NamedTuple):
    """
    A file region that is mapped into a PE image.

    Attributes:
        raw_start: file offset of the first mapped byte (inclusive)
        raw_end: file offset one past the last mapped byte (exclusive)
        rva: relative virtual address of the first mapped byte
    """

    raw_start: int
    raw_end: int
    rva: int


class PeImage(NamedTuple):
    """
    A parsed PE image and the information needed to translate file offsets.

    Attributes:
        imagebase: preferred load address from the PE optional header
        regions: file regions that are mapped into the image
    """

    imagebase: int
    regions: List[ImageRegion]


class MappedString(NamedTuple):
    """
    A static or language string translated into the PE address space.

    Attributes:
        rva: relative virtual address of the string
        va: virtual address of the string
        string: the string contents
    """

    rva: int
    va: int
    string: str


def load_pe_image(path: str) -> Optional[PeImage]:
    """
    Parse a PE file and build its file-offset to RVA mapping.

    Returns None if the file is not a PE, does not exist, or cannot be parsed.
    """
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as e:
        logger.warning("not a PE file (or cannot be parsed): %s (%s)", path, e)
        return None
    except OSError as e:
        logger.warning("cannot open file for offset translation: %s (%s)", path, e)
        return None

    regions: List[ImageRegion] = []

    for section in sorted(pe.sections, key=lambda s: s.VirtualAddress):
        raw_start = section.PointerToRawData
        raw_size = section.SizeOfRawData
        if not raw_start or not raw_size:
            # virtual-only sections (e.g. .bss) do not contribute file offsets
            continue
        regions.append(ImageRegion(raw_start, raw_start + raw_size, section.VirtualAddress))

    # headers (DOS header, PE headers, section table) are mapped at the image base.
    # append last so that (where ranges overlap) the section-specific region wins.
    header_end = pe.OPTIONAL_HEADER.SizeOfHeaders
    if header_end > 0:
        regions.append(ImageRegion(0, header_end, 0))

    return PeImage(pe.OPTIONAL_HEADER.ImageBase, regions)


def file_offset_to_rva(regions: List[ImageRegion], offset: int) -> Optional[int]:
    """
    Translate a file offset to an RVA, or None if the offset is not mapped
    (e.g. debug directories between sections, padding, or overlay data).
    """
    for region in regions:
        if region.raw_start <= offset < region.raw_end:
            return region.rva + (offset - region.raw_start)
    return None


def resolve_static_strings(
    result_document: ResultDocument, pe_image: Optional[PeImage]
) -> Tuple[List[MappedString], int]:
    """
    Translate the document's static and language strings into PE addresses.

    Returns a list of mapped strings and the number of non-empty strings that
    could not be translated. When the sample is unavailable or is not a PE,
    every non-empty static/language string is reported as unmapped.

    The imagebase recorded in the result document is preferred, because that is
    the base used for decoded strings too. Static-only runs do not load the
    sample into a disassembler and therefore leave it at zero; in that case the
    PE's preferred imagebase is used.
    """
    if pe_image is not None:
        imagebase = result_document.metadata.imagebase or pe_image.imagebase
    else:
        imagebase = result_document.metadata.imagebase

    mapped: List[MappedString] = []
    unmapped = 0
    for static_string in itertools.chain(
        result_document.strings.static_strings, result_document.strings.language_strings
    ):
        if static_string.string == "":
            continue

        if pe_image is None:
            unmapped += 1
            continue

        rva = file_offset_to_rva(pe_image.regions, static_string.offset)
        if rva is None:
            unmapped += 1
            continue

        mapped.append(MappedString(rva, imagebase + rva, static_string.string))

    return mapped, unmapped


def load_sample_path(result_document: ResultDocument) -> Optional[str]:
    """
    Return the path of the analyzed sample when it is usable for offset
    translation (file exists), else None so callers can warn once.
    """
    path = result_document.metadata.file_path
    if path and Path(path).is_file():
        return path
    logger.warning(
        "sample file not found: %s (needed to translate string file offsets to virtual addresses)",
        path,
    )
    return None

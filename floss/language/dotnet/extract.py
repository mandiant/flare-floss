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

import logging
import pathlib
from typing import List, Tuple, Optional

import dnfile
import pefile

from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)


def _load_user_strings(sample: pathlib.Path) -> Optional[Tuple[dnfile.stream.UserStringHeap, int, int]]:
    """The #US heap and its [start, end) file offsets, or None when the sample has no usable heap."""
    try:
        # lazy: only the #US heap is needed; a full metadata table parse is ~20x slower on large assemblies
        dn = dnfile.dnPE(data=pathlib.Path(sample).read_bytes(), clr_lazy_load=True)
    except pefile.PEFormatError:
        return None
    if dn.net is None or dn.net.user_strings is None:
        return None

    us = dn.net.user_strings
    if us.file_offset is None:
        # the heap's RVA does not map into the file, so no offset we report could be trusted
        return None
    return us, us.file_offset, us.file_offset + us.sizeof()


def extract_dotnet_strings(sample: pathlib.Path, min_length: int) -> List[StaticString]:
    """
    Extract the string literals of a .NET assembly from its #US (user strings) heap.

    Each heap entry is a compressed length, UTF-16LE characters and a trailing flag byte
    (ECMA-335 II.24.2.4). Index 0 holds the empty string, so the walk starts at 1.
    """
    loaded = _load_user_strings(sample)
    if loaded is None:
        return []

    us, heap_start, _ = loaded
    strings: List[StaticString] = []
    index = 1
    while index < us.sizeof():
        try:
            item = us.get(index, encoding="utf-16-le")
        except IndexError:
            # dnfile 0.18 raises this for an entry whose length runs past the end of the heap
            item = None
        if item is None or item.raw_size == 0:
            # dnfile could not parse the entry; without its length the next one cannot be found
            logger.debug("stopping .NET user string walk at heap index 0x%x", index)
            break

        if item.value is not None and len(item.value) >= min_length:
            # the string's characters follow its compressed length prefix
            offset = heap_start + index + item.item_size.raw_size
            strings.append(StaticString(string=item.value, offset=offset, encoding=StringEncoding.UTF16LE))

        index += item.raw_size

    return strings


def get_static_strings_from_us_heap(sample: pathlib.Path, static_strings: List[StaticString]) -> List[StaticString]:
    """The static strings located inside the #US heap, i.e. the range the .NET extractor searched."""
    loaded = _load_user_strings(sample)
    if loaded is None:
        return []

    _, start, end = loaded
    return [s for s in static_strings if start <= s.offset < end]

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

"""Binary layout analysis (PE / ELF / Mach-O).

Public entrypoint: ``compute_layout``. Import types, extract helpers, and
format builders from the submodules that define them (``base``, ``extract``,
``types``, ``pe``, ``elf``, ``macho``).
"""

from __future__ import annotations

import logging

from elftools.common.exceptions import ELFError

from floss.ranges import Range, Slice
from floss.layout.pe import compute_pe_layout
from floss.layout.elf import compute_elf_layout
from floss.layout.base import Layout, SegmentLayout
from floss.layout.macho import _get_u32_be, _is_macho_magic, compute_macho_layout

logger = logging.getLogger("floss.layout")


def xor_static(data: bytes, i: int) -> bytes:
    return bytes(c ^ i for c in data)


def compute_layout(slice_: Slice) -> Layout:

    # TODO don't do this for text or other obvious non-xored data

    mz_xor = [
        (
            xor_static(b"MZ", key),
            key,
        )
        for key in range(1, 256)
    ]

    xor_key = None
    decoded_slice = slice_

    # Try to find the XOR key. Read only the first two bytes from buf; slice_.data
    # copies the entire underlying buffer on each call.
    rel_start = slice_.range.offset - slice_.base_offset
    start_bytes = slice_.buf[rel_start : rel_start + 2]
    for mz, key in mz_xor:
        if start_bytes == mz:
            xor_key = key
            break

    # If XOR key is found, apply XOR decoding
    if xor_key is not None:
        decoded_data = xor_static(slice_.data, xor_key)
        # Use base_offset to match the absolute offset,
        # so that Slice/Range logic based on absolute offsets still works
        # without requiring a large NULL-padded buffer.
        decoded_slice = Slice(
            buf=decoded_data,
            range=Range(offset=slice_.offset, length=len(decoded_data)),
            base_offset=slice_.offset,
        )

    # Try to parse as PE file
    if decoded_slice.data.startswith(b"MZ"):
        try:
            # lancelot may panic here, which we can't currently catch from Python
            return compute_pe_layout(decoded_slice, xor_key)
        except ValueError as e:
            logger.debug("failed to parse as PE file: %s", e)
    elif _is_macho_magic(_get_u32_be(slice_.data, 0)):
        try:
            return compute_macho_layout(slice_)
        except Exception as e:
            # TODO: narrow exception handling once machofile error types are clearer.
            logger.debug("failed to parse as Mach-O file: %s", e)
    elif decoded_slice.data.startswith(b"\x7fELF"):
        try:
            return compute_elf_layout(decoded_slice, xor_key)
        except ELFError as e:
            logger.debug("failed to parse as ELF file: %s", e)
    else:
        logger.debug("unrecognized file format, falling back to binary layout")

    return SegmentLayout(
        slice=slice_,
        name="binary",
    )

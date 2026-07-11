# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Binary layout analysis (PE / ELF / Mach-O)."""

from __future__ import annotations

import logging

from elftools.common.exceptions import ELFError

from floss.ranges import Range, Slice
from floss.layout.pe import compute_pe_layout
from floss.layout.elf import compute_elf_layout
from floss.layout.base import (
    Layout,
    PELayout,
    ELFLayout,
    Structure,
    MachOLayout,
    SectionLayout,
    SegmentLayout,
    MachOFatLayout,
)
from floss.layout.macho import _get_u32_be, _is_macho_magic, compute_macho_layout
from floss.layout.types import MIN_STR_LEN, Tag, TaggedString, ExtractedString, extract_strings
from floss.layout.extract import collect_strings, extract_layout_strings

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

    # Try to find the XOR key
    for mz, key in mz_xor:
        if slice_.data.startswith(mz):
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


__all__ = [
    "Layout",
    "SectionLayout",
    "SegmentLayout",
    "PELayout",
    "ELFLayout",
    "MachOLayout",
    "MachOFatLayout",
    "Structure",
    "ExtractedString",
    "TaggedString",
    "Tag",
    "MIN_STR_LEN",
    "extract_strings",
    "extract_layout_strings",
    "collect_strings",
    "compute_layout",
    "compute_pe_layout",
    "compute_elf_layout",
    "compute_macho_layout",
]

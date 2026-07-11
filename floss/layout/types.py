# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""String extraction types used while walking binary layouts."""

from __future__ import annotations

import re
import itertools
from typing import Set, List, Literal, Iterable, TypeAlias

from pydantic import BaseModel

from floss.ranges import Slice

Tag: TypeAlias = str


class ExtractedString(BaseModel):
    string: str
    slice: Slice
    encoding: Literal["ascii", "unicode"]


class TaggedString(BaseModel):
    string: ExtractedString
    tags: Set[Tag]
    structure: str = ""

    @property
    def offset(self) -> int:
        "convenience"
        return self.string.slice.range.offset


MIN_STR_LEN = 4
# we don't include \r and \n to make output easier to understand by humans and to simplify rendering
ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
ASCII_RE_MIN = re.compile(b"([%s]{%d,})" % (ASCII_BYTE, MIN_STR_LEN))
UNICODE_RE_MIN = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, MIN_STR_LEN))

MACHO_MAGIC = 0xFEEDFACE
MACHO_CIGAM = 0xCEFAEDFE
MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

MACHO_MAGICS = {MACHO_MAGIC, MACHO_CIGAM, MACHO_MAGIC_64, MACHO_CIGAM_64}
FAT_MAGICS = {FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64}

PE_RESOURCE_TYPES = {
    1: "Cursors",
    2: "Bitmaps",
    3: "Icons",
    4: "Menus",
    5: "Dialogs",
    6: "String Tables",
    7: "Font Directories",
    8: "Fonts",
    9: "Accelerators",
    10: "RCData",
    11: "Message Tables",
    12: "Cursor Groups",
    14: "Icon Groups",
    16: "Version Info",
    17: "DLGInclude",
    19: "Plug and Play",
    20: "VXD",
    21: "Animated Cursors",
    22: "Animated Icons",
    23: "HTML",
    24: "Manifest",
    240: "DLGInit",  # MFC specific
    241: "Toolbars",  # MFC specific
}

CPU_TYPE_X86 = 0x7
CPU_TYPE_X86_64 = 0x1000007
CPU_TYPE_ARM = 0xC
CPU_TYPE_ARM64 = 0x100000C
CPU_TYPE_PPC = 0x12
CPU_TYPE_PPC64 = 0x10000012

CPU_TYPE_MAP = {
    CPU_TYPE_X86: "x86",
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM: "arm",
    CPU_TYPE_ARM64: "arm64",
    CPU_TYPE_PPC: "ppc",
    CPU_TYPE_PPC64: "ppc64",
}

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01


def extract_ascii_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate ASCII strings in the given binary data"

    if not slice.range.length:
        return

    r: re.Pattern
    if n == MIN_STR_LEN:
        r = ASCII_RE_MIN
    else:
        reg = b"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)

    for match in r.finditer(slice.data):
        offset = match.start()
        length = match.end() - match.start()
        string = match.group().decode("ascii")
        yield ExtractedString(string=string, slice=slice.slice(offset, length), encoding="ascii")


def extract_unicode_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate naive UTF-16 strings in the given binary data"

    if not slice.range.length:
        return

    r: re.Pattern
    if n == MIN_STR_LEN:
        r = UNICODE_RE_MIN
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)

    for match in r.finditer(slice.data):
        offset = match.start()
        length = match.end() - match.start()

        try:
            string = match.group().decode("utf-16")
        except UnicodeDecodeError:
            continue

        yield ExtractedString(string=string, slice=slice.slice(offset, length), encoding="unicode")


def extract_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    "enumerate ASCII and naive UTF-16 strings in the given binary data"
    return list(
        sorted(
            itertools.chain(extract_ascii_strings(slice, n), extract_unicode_strings(slice, n)),
            key=lambda s: s.slice.range.offset,
        )
    )

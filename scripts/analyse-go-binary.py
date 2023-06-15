# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
import sys
import struct
import logging
import argparse
from typing import List, Iterable, Optional

import pefile
from tqdm import tqdm

from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)


final_size = 0

MIN_STR_LEN = 4


def find_longest_string(bindata):
    """
    Reference:- https://github.com/CarveSystems/gostringsr2/blob/master/gostringsr2/gostringsr2.py
    """
    off = 0
    this_off = 0
    longest_off = 0
    longest_size = 0

    binlength = len(bindata)
    while off < binlength:
        b = bindata[off : off + 2]
        # Basically, terminate a "string" if 2 null bytes are seen. Seems to work for the most part.
        if b == b"\x00\x00":
            this_size = off - this_off
            if this_size > 0:
                if this_size > longest_size:
                    longest_off = this_off
                    longest_size = this_size
            this_off = off + 2
        else:
            this_size = off - this_off
            if this_size > 0:
                if this_size > longest_size:
                    longest_off = this_off
                    longest_size = this_size
        off += 2

    if (off - this_off) > longest_size:
        longest_off = this_off
        longest_size = off - this_off

    if longest_size > 0:
        return (longest_off, longest_size)

    return (None, 0)


def extract_go_strings(
    sample: str,
    min_length,
) -> Iterable[StaticString]:
    """
    Get Go strings from a PE file.
    Reference: https://github.com/mandiant/flare-floss/issues/779
    """
    global final_size

    try:
        pe = pefile.PE(sample)
    except pefile.PEFormatError as err:
        return
        # logger.debug(f"invalid PE file: {err}")
        # raise ValueError("Invalid PE header")

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        """
        .data:0000000000770F20 3D 68 60 00 00 00+off_770F20      dq offset aString
        .data:0000000000770F28 15                                db  15h
        .data:0000000000770F29 00                                db    0
        """
        alignment = 0x10  # 16
        fmt = "<QQ"

        # See https://github.com/mandiant/flare-floss/issues/805#issuecomment-1590472813 for regex explanation
        combinedregex = re.compile(
            b"\x48\xba(........)|\x48\xb8(........)|\x81\x78\x08(....)|\x81\x79\x08(....)|\x66\x81\x78\x0c(..)|\x66\x81\x79\x0c(..)|\x80\x78\x0e(.)|\x80\x79\x0e(.)"
        )

    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        """
        .data:102A78D0 E3 9A 17 10                       dd offset aString
        .data:102A78D4 12                                db  12h
        """
        alignment = 0x8
        fmt = "<II"

        # See https://github.com/mandiant/flare-floss/issues/805#issuecomment-1590510957 for regex explanation
        combinedregex = re.compile(
            b"\x81\xf9(....)|\x81\x38(....)|\x81\x7d\x00(....)|\x81\x3B(....)|\x66\x81\xf9(..)|\x66\x81\x7b\x04(..)|\x66\x81\x78\x04(..)|\x66\x81\x7d\x04(..)|\x80\x7b\x06(.)|\x80\x7d\x06(.)|\x80\xf8(.)|\x80\x78\x06(.)"
        )
    else:
        raise ValueError("unhandled architecture")

    for section in pe.sections:
        try:
            section_name = section.Name.partition(b"\x00")[0].decode("utf-8")
        except UnicodeDecodeError:
            continue

        if section_name == ".rdata":
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            off, size = find_longest_string(section_data)
            # print(hex(pe.OPTIONAL_HEADER.ImageBase + off + section_va), hex(size))
            final_size = size

        if section_name == ".text":
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            strings = re.findall(combinedregex, section_data)

            for string_tuple in strings:
                for string in string_tuple:
                    if string != b"":
                        try:
                            decoded_string = string.decode("utf-8")
                            if decoded_string.isprintable() and len(string) >= min_length:
                                addr = 0
                                yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                        except UnicodeDecodeError:
                            pass

        if section_name in (".rdata", ".data"):
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)

            for i in tqdm(range(0, len(section_data) - alignment // 2, alignment // 2)):
                try:
                    curr = section_data[i : i + alignment]
                    s_off, s_size = struct.unpack(fmt, curr)

                    if not s_off and not (1 <= s_size < 128):
                        continue

                    s_rva = s_off - pe.OPTIONAL_HEADER.ImageBase

                    if not pe.get_section_by_rva(s_rva):
                        continue

                    addr = pe.OPTIONAL_HEADER.ImageBase + section_va + i

                    try:
                        string = pe.get_string_at_rva(s_rva, s_size).decode("ascii")
                    except UnicodeDecodeError:
                        continue

                    if len(string) >= min_length and len(string) == s_size:
                        yield StaticString(string=string, offset=addr, encoding=StringEncoding.ASCII)
                except Exception as e:
                    logger.error(f"Error: {e}")
                    raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Get Go strings")
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length",
    )
    args = parser.parse_args(args=argv)

    static_strings = extract_go_strings(args.path, min_length=args.min_length)

    final_length = 0

    for strings_obj in static_strings:
        string = strings_obj.string
        final_length += len(string)

    try:
        print(final_length * 100 / final_size)
    except:
        pass


if __name__ == "__main__":
    sys.exit(main())

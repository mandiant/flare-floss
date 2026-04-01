# Copyright 2023 Google LLC
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

import sys
import logging
import pathlib
import argparse
import itertools
from typing import List, Iterable

import pefile

from .utf8_strings import extract_utf8_strings
from floss.results import StaticString, StringEncoding
from floss.language.utils import (
    find_lea_xrefs,
    find_mov_xrefs,
    find_push_xrefs,
    get_rdata_section,
    get_struct_string_candidates,
)

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4


def split_strings(static_strings: List[StaticString], address: int, min_length: int) -> None:
    """
    if address is in between start and end of a string in ref data then split the string
    this modifies the elements of the static strings list directly
    """

    for string in static_strings:
        if string.offset < address < string.offset + len(string.string):
            rust_string = string.string[0 : address - string.offset]
            rest = string.string[address - string.offset :]

            if len(rust_string) >= min_length:
                static_strings.append(
                    StaticString(string=rust_string, offset=string.offset, encoding=StringEncoding.UTF8)
                )
            if len(rest) >= min_length:
                static_strings.append(StaticString(string=rest, offset=address, encoding=StringEncoding.UTF8))

            # remove string from static_strings
            for static_string in static_strings:
                if static_string == string:
                    static_strings.remove(static_string)
                    return

            return


def extract_rust_strings(sample: pathlib.Path, min_length: int) -> List[StaticString]:
    """
    Extract Rust strings from a sample
    """

    p = pathlib.Path(sample)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    rust_strings: List[StaticString] = list()
    rust_strings.extend(get_string_blob_strings(pe, min_length))

    return rust_strings


def get_static_strings_from_rdata(sample, static_strings) -> List[StaticString]:
    pe = pefile.PE(data=pathlib.Path(sample).read_bytes(), fast_load=True)

    try:
        rdata_section = get_rdata_section(pe)
    except ValueError:
        return []

    start_rdata = rdata_section.PointerToRawData
    end_rdata = start_rdata + rdata_section.SizeOfRawData

    return list(filter(lambda s: start_rdata <= s.offset < end_rdata, static_strings))


def get_string_blob_strings(pe: pefile.PE, min_length: int) -> Iterable[StaticString]:
    image_base = pe.OPTIONAL_HEADER.ImageBase

    try:
        rdata_section = get_rdata_section(pe)
    except ValueError as e:
        logger.error("cannot extract rust strings: %s", e)
        return []

    start_rdata = rdata_section.PointerToRawData
    end_rdata = start_rdata + rdata_section.SizeOfRawData
    virtual_address = rdata_section.VirtualAddress
    pointer_to_raw_data = rdata_section.PointerToRawData
    buffer_rdata = rdata_section.get_data()

    # Extract strictly valid UTF-8 strings using our custom regex implementation
    # This automatically prevents the b2s wide-string garbage extraction bug
    static_strings: List[StaticString] = []
    for offset, string_val in extract_utf8_strings(buffer_rdata, min_length=min_length):
        # our static algorithm does not extract new lines either
        clean_str = string_val.replace("\n", "")
        
        static_strings.append(
            StaticString(
                string=clean_str, 
                offset=offset + start_rdata, 
                encoding=StringEncoding.UTF8
            )
        )

    # TODO(mr-tz) - handle miss in rust-hello64.exe
    #  .rdata:00000001400C1270 0A                      aPanickedAfterP db 0Ah                  ; DATA XREF: .rdata:00000001400C12B8↓o
    #  .rdata:00000001400C1271 70 61 6E 69 63 6B 65 64…                db 'panicked after panic::always_abort(), aborting.',0Ah,0
    #  .rdata:00000001400C12A2 00 00 00 00 00 00                       align 8

    struct_string_addrs = map(lambda c: c.address, get_struct_string_candidates(pe))

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        xrefs_lea = find_lea_xrefs(pe)
        xrefs_push = find_push_xrefs(pe)
        xrefs_mov = find_mov_xrefs(pe)
        xrefs = itertools.chain(struct_string_addrs, xrefs_lea, xrefs_push, xrefs_mov)

    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        xrefs_lea = find_lea_xrefs(pe)
        xrefs = itertools.chain(struct_string_addrs, xrefs_lea)

        # TODO(mr-tz) - handle movdqa rust-hello64.exe
        #  .text:0000000140026046 66 0F 6F 05 02 71 09 00                 movdqa  xmm0, cs:xmmword_1400BD150
        #  .text:000000014002604E 66 0F 6F 0D 0A 71 09 00                 movdqa  xmm1, cs:xmmword_1400BD160
        #  .text:0000000140026056 66 0F 6F 15 12 71 09 00                 movdqa  xmm2, cs:xmmword_1400BD170

    else:
        logger.error("unsupported architecture: %s", pe.FILE_HEADER.Machine)
        return []

    for addr in xrefs:
        address = addr - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        split_strings(static_strings, address, min_length)

    return static_strings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Get Rust strings")
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

    logging.basicConfig(level=logging.DEBUG)

    rust_strings = sorted(extract_rust_strings(args.path, args.min_length), key=lambda s: s.offset)
    for string in rust_strings:
        print(f"{string.offset:#x}: {string.string}")


if __name__ == "__main__":
    sys.exit(main())
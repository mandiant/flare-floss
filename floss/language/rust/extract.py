# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
import sys
import array
import struct
import logging
import pathlib
import argparse
from typing import List, Tuple, Iterable, Optional
from pathlib import Path
from itertools import chain
from dataclasses import dataclass

import pefile
import binary2strings as b2s
from typing_extensions import TypeAlias

import floss.utils
from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4

VA: TypeAlias = int


def get_image_range(pe: pefile.PE) -> Tuple[VA, VA]:
    """return the range of the image in memory."""
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    return image_base, image_base + image_size


@dataclass(frozen=True)
class StructString:
    """
    a struct String instance.


    ```go
        // String is the runtime representation of a string.
        // It cannot be used safely or portably and its representation may
        // change in a later release.
        //
        // Unlike reflect.StringHeader, its Data field is sufficient to guarantee the
        // data it references will not be garbage collected.
        type String struct {
            Data unsafe.Pointer
            Len  int
        }
    ```

    https://github.com/golang/go/blob/36ea4f9680f8296f1c7d0cf7dbb1b3a9d572754a/src/internal/unsafeheader/unsafeheader.go#L28-L37
    """

    address: VA
    length: int


def get_max_section_size(pe: pefile.PE) -> int:
    """get the size of the largest section, as seen on disk."""
    return max(map(lambda s: s.SizeOfRawData, pe.sections))


def get_struct_string_candidates_with_pointer_size(pe: pefile.PE, buf: bytes, psize: int) -> Iterable[StructString]:
    """
    scan through the given bytes looking for pairs of machine words (address, length)
    that might potentially be struct String instances.

    we do some initial validation, like checking that the address is valid
    and the length is reasonable; however, we don't validate the encoded string data.
    """
    if psize == 32:
        format = "I"
    elif psize == 64:
        format = "Q"
    else:
        raise ValueError("unsupported pointer size")

    limit = get_max_section_size(pe)
    low, high = get_image_range(pe)

    # using array module as a high-performance way to access the data as fixed-sized words.
    words = iter(array.array(format, buf))

    # walk through the words pairwise, (address, length)
    last = next(words)
    for current in words:
        address = last
        length = current
        last = current

        if address == 0x0:
            continue

        if length == 0x0:
            continue

        if length > limit:
            continue

        if not (low <= address < high):
            continue

        yield StructString(address, length)


def get_amd64_struct_string_candidates(pe: pefile.PE, buf: bytes) -> Iterable[StructString]:
    yield from get_struct_string_candidates_with_pointer_size(pe, buf, 64)


def get_i386_struct_string_candidates(pe: pefile.PE, buf: bytes) -> Iterable[StructString]:
    yield from get_struct_string_candidates_with_pointer_size(pe, buf, 32)


def get_struct_string_candidates(pe: pefile.PE) -> Iterable[StructString]:
    """
    find candidate struct String instances in the given PE file.

    we do some initial validation, like checking that the address is valid
    and the length is reasonable; however, we don't validate the encoded string data.
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase
    low, high = get_image_range(pe)

    # cache the section data so that we can avoid pefile overhead
    section_datas: List[Tuple[VA, VA, bytes]] = []
    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_READ:
            continue

        section_datas.append(
            (
                image_base + section.VirtualAddress,
                image_base + section.VirtualAddress + section.SizeOfRawData,
                # use memoryview here so that we can slice it quickly later
                memoryview(section.get_data()),
            )
        )

    for section in pe.sections:
        if section.IMAGE_SCN_MEM_EXECUTE:
            continue

        if not section.IMAGE_SCN_MEM_READ:
            continue

        if not (section.Name.startswith(b".rdata\x00") or section.Name.startswith(b".data\x00")):
            # by convention, the struct String instances are stored in the .rdata or .data section.
            continue

        data = section.get_data()

        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            candidates = get_amd64_struct_string_candidates(pe, data)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            candidates = get_i386_struct_string_candidates(pe, data)
        else:
            raise ValueError("unhandled architecture")

        with floss.utils.timing("find struct string candidates (raw)"):
            candidates = list(candidates)

        for candidate in candidates:
            # this region has some inline performance comments,
            # showing the impact of the various checks against a huge
            # sample Go program (kubelet.exe) encountered during development.
            #
            # go ahead and remove these comments if the logic ever changes.
            #
            # base perf: 1.07s
            va = candidate.address
            rva = va - image_base

            # perf: 1.13s
            # delta: 0.06s
            if not (low <= va < high):
                continue

            # perf: 1.35s
            # delta: 0.22s
            target_section = pe.get_section_by_rva(rva)
            if not target_section:
                # string instance must be in a section
                continue

            # perf: negligible
            if target_section.IMAGE_SCN_MEM_EXECUTE:
                # string instances aren't found with the code
                continue

            # perf: negligible
            if not target_section.IMAGE_SCN_MEM_READ:
                # string instances must be readable, naturally
                continue

            # perf: 1.42s
            # delta: 0.07s
            try:
                section_start, _, section_data = next(filter(lambda s: s[0] <= candidate.address < s[1], section_datas))
            except StopIteration:
                continue

            # perf: 1.53s
            # delta: 0.11s
            instance_offset = candidate.address - section_start
            # remember: section_data is a memoryview, so this is a fast slice.
            # when not using memoryview, this takes a *long* time (dozens of seconds or longer).
            instance_data = section_data[instance_offset : instance_offset + candidate.length]

            # perf: 1.66s
            # delta: 0.13s
            if len(instance_data) != candidate.length:
                continue

            yield candidate

            # we would want to be able to validate that structure actually points
            # to valid UTF-8 data;
            # however, even copying the bytes here is very slow,
            # dozens of seconds or more (suspect many minutes).


def find_string_blob_range(pe: pefile.PE, struct_strings: List[StructString]) -> Tuple[VA, VA]:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if not section.Name.decode().rstrip("\x00") == ".rdata":
            continue

        start_address = section.VirtualAddress + image_base
        end_address = section.VirtualAddress + section.SizeOfRawData + image_base

    return start_address, end_address


def get_rdata_file_offset(pe: pefile.PE, addr) -> int:
    """
    get the file offset of the .rdata section.
    """
    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            image_base = pe.OPTIONAL_HEADER.ImageBase
            virtual_address = section.VirtualAddress
            pointer_to_raw_data = section.PointerToRawData
    return addr - (image_base + virtual_address - pointer_to_raw_data)


def get_string_blob_strings(pe: pefile.PE, min_length) -> Iterable[StaticString]:
    """
    for the given PE file compiled by Rust,
    find the string blob and then extract strings from it.

    we rely on code and memory scanning techniques to identify
    pointers into this table, which is then segmented into strings.

    we expect the string blob to generally contain UTF-8 strings;
    however, this isn't guaranteed:

    its still the best we can do, though.
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase

    with floss.utils.timing("find struct string candidates"):
        struct_strings = list(sorted(set(get_struct_string_candidates(pe)), key=lambda s: s.address))

    with floss.utils.timing("find string blob"):
        string_blob_start, string_blob_end = find_string_blob_range(pe, struct_strings)

    for instance in struct_strings:
        sbuf = pe.get_string_at_rva(instance.address - image_base)

        if not (string_blob_start <= instance.address < string_blob_end):
            continue

        try:
            string = StaticString.from_utf8(sbuf, instance.address, min_length)
            yield string
        except ValueError:
            pass


def extract_rust_strings(sample, min_length) -> List[StaticString]:
    """
    extract Rust strings from the given PE file
    """

    p = pathlib.Path(sample)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    rust_strings: List[StaticString] = list()
    rust_strings.extend(get_string_blob_strings(pe, min_length))

    return rust_strings


def extract_utf8_strings(sample, min_length) -> List[StaticString]:
    """
    extract UTF-8 strings from the given PE file using binary2strings
    """
    p = pathlib.Path(sample)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    image_base = pe.OPTIONAL_HEADER.ImageBase

    with floss.utils.timing("extract UTF-8 strings"):
        strings = list(b2s.extract_all_strings(buf, min_length))

    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            virtual_address = section.VirtualAddress
            pointer_to_raw_data = section.PointerToRawData
            section_size = section.SizeOfRawData
            break

    start_rdata = pointer_to_raw_data
    end_rdata = pointer_to_raw_data + section_size

    ref_data = []

    for string in strings:
        start = string[2][0]
        end = string[2][1]
        string_type = string[1]
        if not (start_rdata <= start < end_rdata):
            continue
        if not (start_rdata <= end < end_rdata):
            continue
        if string_type != "UTF8":
            continue

        ref_data.append((string[0], start, end))

    candidates = get_struct_string_candidates(pe)

    for can in candidates:
        address = can.address - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        # if address is in between start and end of a string in ref data then split the string
        for ref in ref_data:
            if ref[1] < address < ref[2]:
                # split the string and add it to ref_data
                ref_data.append((ref[0][0 : address - ref[1]], ref[1], address))
                ref_data.append((ref[0][address - ref[1] :], address, ref[2]))

                # remove the original string
                ref_data.remove(ref)

                break

    static_strings = []
    for ref in ref_data:
        try:
            string = StaticString.from_utf8(ref[0].encode("utf-8"), ref[1], min_length)
            static_strings.append(string)
        except ValueError:
            pass

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

    rust_strings = sorted(extract_utf8_strings(args.path, args.min_length), key=lambda s: s.offset)
    for string in rust_strings:
        print(f"{string.offset:#x}: {string.string}")

    # rust_strings = sorted(extract_rust_strings(args.path, args.min_length), key=lambda s: s.offset)
    # for string in rust_strings:
    #     print(f"{string.offset:#x}: {string.string}")


if __name__ == "__main__":
    sys.exit(main())

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
from typing_extensions import TypeAlias

import floss.utils
from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4


def find_stack_strings_with_regex(
    extract_stackstring_pattern, section_data, offset, min_length
) -> Iterable[StaticString]:
    """
    Find stack strings using a regex pattern.
    """
    for m in extract_stackstring_pattern.finditer(section_data):
        for i in range(1, 8):
            try:
                binary_string = m.group(i)
                if not binary_string:
                    continue

                addr = m.start()
                # need to subtract opcode bytes offset
                off_regex = len(m.group(0)) - len(binary_string)
                addr = offset + off_regex + m.start()
                try:
                    string = StaticString.from_utf8(binary_string, addr, min_length)
                    yield string
                except ValueError:
                    pass
            except AttributeError:
                break


def find_amd64_stackstrings(section_data, offset, min_length):
    """
    Stackstrings in amd64 architecture are found
    by searching for the following pattern:

    .text:000000000048FFA9 48 83 FB 0F                                   cmp     rbx, 0Fh
    .text:000000000048FFAD 75 69                                         jnz     short loc_490018
    .text:000000000048FFAF 48 BA 50 61 73 73 77 6F 72 64                 mov     rdx, 64726F7773736150h
    .text:000000000048FFB9 48 39 10                                      cmp     [rax], rdx
    .text:000000000048FFBC 75 5A                                         jnz     short loc_490018
    .text:000000000048FFBE 81 78 08 69 73 50 72                          cmp     dword ptr [rax+8], 72507369h
    .text:000000000048FFC5 75 51                                         jnz     short loc_490018
    .text:000000000048FFC7 66 81 78 0C 61 6E                             cmp     word ptr [rax+0Ch], 6E61h
    .text:000000000048FFCD 75 49                                         jnz     short loc_490018
    .text:000000000048FFCF 80 78 0E 6B                                   cmp     byte ptr [rax+0Eh], 6Bh ; 'k'
    .text:000000000048FFD3 75 43                                         jnz     short loc_490018
    """
    extract_stackstring_pattern = re.compile(
        b"\x48\xba(........)|\x48\xb8(........)|\x81\x78\x08(....)|\x81\x79\x08(....)|\x66\x81\x78\x0c(..)|\x66\x81\x79\x0c(..)|\x80\x78\x0e(.)|\x80\x79\x0e(.)"
    )

    yield from find_stack_strings_with_regex(extract_stackstring_pattern, section_data, offset, min_length)


def find_i386_stackstrings(section_data, offset, min_length):
    """
    Stackstrings in i386 architecture are found
    by searching for the following pattern:

    .text:0048CED3 75 6D                                         jnz     short loc_48CF42
    .text:0048CED5 81 7D 00 50 61 73 73                          cmp     dword ptr [ebp+0], 73736150h
    .text:0048CEDC 75 64                                         jnz     short loc_48CF42
    .text:0048CEDE 66 81 7D 04 77 6F                             cmp     word ptr [ebp+4], 6F77h
    .text:0048CEE4 75 5C                                         jnz     short loc_48CF42
    .text:0048CEE6 80 7D 06 72                                   cmp     byte ptr [ebp+6], 72h ; 'r'
    .text:0048CEEA 75 56                                         jnz     short loc_48CF42
    """
    extract_stackstring_pattern = re.compile(
        b"\x81\xf9(....)|\x81\x38(....)|\x81\x7d\x00(....)|\x81\x3B(....)|\x66\x81\xf9(..)|\x66\x81\x7b\x04(..)|\x66\x81\x78\x04(..)|\x66\x81\x7d\x04(..)|\x80\x7b\x06(.)|\x80\x7d\x06(.)|\x80\xf8(.)|\x80\x78\x06(.)",
        re.DOTALL,
    )

    yield from find_stack_strings_with_regex(extract_stackstring_pattern, section_data, offset, min_length)


def get_stackstrings(pe: pefile.PE, min_length: int) -> Iterable[StaticString]:
    """
    Find stackstrings in the given PE file.
    """

    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue

        code = section.get_data()

        code_raw_data = section.PointerToRawData

        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            stack_string = find_amd64_stackstrings(code, code_raw_data, min_length)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            stack_string = find_i386_stackstrings(code, code_raw_data, min_length)
        else:
            raise ValueError("unhandled architecture")

        yield from stack_string


VA: TypeAlias = int


def get_image_range(pe: pefile.PE) -> Tuple[VA, VA]:
    """return the range of the image in memory."""
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    return image_base, image_base + image_size


def find_amd64_lea_xrefs(buf: bytes, base_addr: VA) -> Iterable[VA]:
    """
    scan the given data found at the given base address
    to find all the 64-bit RIP-relative LEA instructions,
    extracting the target virtual address.
    """
    rip_relative_insn_length = 7
    rip_relative_insn_re = re.compile(
        # use rb, or else double escape the term "\x0D", or else beware!
        rb"""
        (?:                   # non-capturing group
              \x48 \x8D \x05  # 48 8d 05 aa aa 00 00    lea    rax,[rip+0xaaaa] 
            | \x48 \x8D \x0D  # 48 8d 0d aa aa 00 00    lea    rcx,[rip+0xaaaa]
            | \x48 \x8D \x15  # 48 8d 15 aa aa 00 00    lea    rdx,[rip+0xaaaa]
            | \x48 \x8D \x1D  # 48 8d 1d aa aa 00 00    lea    rbx,[rip+0xaaaa]
            | \x48 \x8D \x2D  # 48 8d 2d aa aa 00 00    lea    rbp,[rip+0xaaaa]
            | \x48 \x8D \x35  # 48 8d 35 aa aa 00 00    lea    rsi,[rip+0xaaaa]
            | \x48 \x8D \x3D  # 48 8d 3d aa aa 00 00    lea    rdi,[rip+0xaaaa]
            | \x4C \x8D \x05  # 4c 8d 05 aa aa 00 00    lea     r8,[rip+0xaaaa]
            | \x4C \x8D \x0D  # 4c 8d 0d aa aa 00 00    lea     r9,[rip+0xaaaa]
            | \x4C \x8D \x15  # 4c 8d 15 aa aa 00 00    lea    r10,[rip+0xaaaa]
            | \x4C \x8D \x1D  # 4c 8d 1d aa aa 00 00    lea    r11,[rip+0xaaaa]
            | \x4C \x8D \x25  # 4c 8d 25 aa aa 00 00    lea    r12,[rip+0xaaaa]
            | \x4C \x8D \x2D  # 4c 8d 2d aa aa 00 00    lea    r13,[rip+0xaaaa]
            | \x4C \x8D \x35  # 4c 8d 35 aa aa 00 00    lea    r14,[rip+0xaaaa]
            | \x4C \x8D \x3D  # 4c 8d 3d aa aa 00 00    lea    r15,[rip+0xaaaa]
        )
        (?P<offset>....)
        """,
        re.DOTALL | re.VERBOSE,
    )

    for match in rip_relative_insn_re.finditer(buf):
        offset_bytes = match.group("offset")
        offset = struct.unpack("<i", offset_bytes)[0]

        yield base_addr + match.start() + offset + rip_relative_insn_length


def find_i386_lea_xrefs(buf: bytes) -> Iterable[VA]:
    """
    scan the given data
    to find all the 32-bit absolutely addressed LEA instructions,
    extracting the target virtual address.
    """
    absolute_insn_re = re.compile(
        rb"""
        (
              \x8D \x05  # 8d 05 aa aa 00 00       lea    eax,ds:0xaaaa
            | \x8D \x1D  # 8d 1d aa aa 00 00       lea    ebx,ds:0xaaaa
            | \x8D \x0D  # 8d 0d aa aa 00 00       lea    ecx,ds:0xaaaa
            | \x8D \x15  # 8d 15 aa aa 00 00       lea    edx,ds:0xaaaa
            | \x8D \x35  # 8d 35 aa aa 00 00       lea    esi,ds:0xaaaa
            | \x8D \x3D  # 8d 3d aa aa 00 00       lea    edi,ds:0xaaaa
        )
        (?P<address>....)
        """,
        re.DOTALL + re.VERBOSE,
    )

    for match in absolute_insn_re.finditer(buf):
        address_bytes = match.group("address")
        address = struct.unpack("<I", address_bytes)[0]

        yield address


def find_lea_xrefs(pe: pefile.PE) -> Iterable[VA]:
    """
    scan the executable sections of the given PE file
    for LEA instructions that reference valid memory addresses,
    yielding the virtual addresses.
    """
    low, high = get_image_range(pe)

    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue

        code = section.get_data()

        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            xrefs = find_amd64_lea_xrefs(code, section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            xrefs = find_i386_lea_xrefs(code)
        else:
            raise ValueError("unhandled architecture")

        for xref in xrefs:
            if low <= xref < high:
                yield xref


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


def find_longest_monotonically_increasing_run(l: List[int]) -> Tuple[int, int]:
    """
    for the given sorted list of values,
    find the (start, end) indices of the longest run of values
    such that each value is greater than or equal to the previous value.

    for example:

        [4, 4, 1, 2, 3, 0, 0] -> (2, 4)
               ^^^^^^^
    """
    max_run_length = 0
    max_run_end_index = 0

    current_run_length = 0
    prior_value = 0

    for i, value in enumerate(l):
        if value >= prior_value:
            current_run_length += 1
        else:
            current_run_length = 1

        if current_run_length > max_run_length:
            max_run_length = current_run_length
            max_run_end_index = i

        prior_value = value

    max_run_start_index = max_run_end_index - max_run_length + 1

    return max_run_start_index, max_run_end_index


def read_struct_string(pe: pefile.PE, instance: StructString) -> str:
    """
    read the string for the given struct String instance,
    validating that it looks like UTF-8,
    or raising a ValueError.
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase

    instance_rva = instance.address - image_base

    # fetch data for the string *and* the next byte,
    # which we'll use to ensure the string is not NULL terminated.
    buf = pe.get_data(instance_rva, instance.length + 1)
    instance_data = buf[: instance.length]
    next_byte = buf[instance.length]

    try:
        s = instance_data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("struct string instance does not contain valid UTF-8")

    # re-encoding the string should produce the same bytes,
    # otherwise, the string may not be the length intended.
    if s.encode("utf-8") != instance_data:
        raise ValueError("struct string length incorrect")

    # string in string blob should not be NULL terminated
    if next_byte == 0x00:
        raise ValueError("struct string is NULL terminated")

    return s


def find_string_blob_range(pe: pefile.PE, struct_strings: List[StructString]) -> Tuple[VA, VA]:
    """
    find the range of the string blob, as loaded in memory.

    the current algorithm relies on the fact that the Go compiler stores
    the strings in length-sorted order, from shortest to longest.
    so we use the recovered candidate struct String instances to find the longest
    run of monotonically increasing lengths, which should be the string blob.
    then we carve for all the data between | 00 00 00 00 |.

    in practice, the longest run is hundreds or thousands of entries long,
    versus a dozen or so for the next longest non-string blob run.
    so its pretty clear.

    we use this algorithm because it lets us find the string blob without
    reading all the data of the candidate struct string instances, of which
    there might be hundreds of thousands and takes many minutes.

    note: this algorithm relies heavily on the strings being stored in length-sorted order.
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase

    struct_strings.sort(key=lambda s: s.address)

    run_start, run_end = find_longest_monotonically_increasing_run(list(map(lambda s: s.length, struct_strings)))

    # pick the mid string, so that we avoid any junk data on the edges of the string blob
    run_mid = (run_start + run_end) // 2
    instance = struct_strings[run_mid]

    s = read_struct_string(pe, instance)
    assert s is not None
    logger.debug("string blob: struct string instance: 0x%x: %s...", instance.address, s[:16])

    instance_rva = instance.address - image_base
    section = pe.get_section_by_rva(instance_rva)
    section_data = section.get_data()
    instance_offset = instance_rva - section.VirtualAddress

    # kubelet.exe has an embedded non-UTF-8 sequence of bytes, including | 00 00 |
    # so we use a larger needle | 00 00 00 00 |
    #
    # see: https://github.com/Arker123/flare-floss/pull/3#issuecomment-1623354852
    next_null = section_data.find(b"\x00\x00\x00\x00", instance_offset)
    assert next_null != -1

    prev_null = section_data.rfind(b"\x00\x00\x00\x00", 0, instance_offset)
    assert prev_null != -1

    section_start = image_base + section.VirtualAddress
    blob_start, blob_end = (section_start + prev_null, section_start + next_null)
    logger.debug("string blob: [0x%x-0x%x]", blob_start, blob_end)

    return blob_start, blob_end


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
    for the given PE file compiled by Go,
    find the string blob and then extract strings from it.

    we rely on code and memory scanning techniques to identify
    pointers into this table, which is then segmented into strings.

    we expect the string blob to generally contain UTF-8 strings;
    however, this isn't guaranteed:

    > // string is the set of all strings of 8-bit bytes, conventionally but not
    > // necessarily representing UTF-8-encoded text. A string may be empty, but
    > // not nil. Values of string type are immutable.
    > type string string

    https://github.com/golang/go/blob/36ea4f9680f8296f1c7d0cf7dbb1b3a9d572754a/src/builtin/builtin.go#L70-L73

    its still the best we can do, though.
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase

    with floss.utils.timing("find struct string candidates"):
        struct_strings = list(sorted(set(get_struct_string_candidates(pe)), key=lambda s: s.address))
        if struct_strings == []:
            logger.warning("Failed to find struct string candidates: Is this a Go binary?")
            return

    with floss.utils.timing("find string blob"):
        string_blob_start, string_blob_end = find_string_blob_range(pe, struct_strings)

    with floss.utils.timing("collect string blob strings"):
        string_blob_size = string_blob_end - string_blob_start
        string_blob_buf = pe.get_data(string_blob_start - image_base, string_blob_size)

        string_blob_pointers: List[VA] = []

        for instance in struct_strings:
            if not (string_blob_start <= instance.address < string_blob_end):
                continue

            string_blob_pointers.append(instance.address)

        for xref in find_lea_xrefs(pe):
            if not (string_blob_start <= xref < string_blob_end):
                continue

            string_blob_pointers.append(xref)

        last_size = 0
        string_blob_pointers = list(sorted(set(string_blob_pointers)))
        for start, end in zip(string_blob_pointers, string_blob_pointers[1:]):
            assert string_blob_start <= start < string_blob_end
            assert string_blob_start <= end < string_blob_end

            size = end - start
            string_blob_offset = start - string_blob_start
            sbuf = string_blob_buf[string_blob_offset : string_blob_offset + size]

            try:
                s = sbuf.decode("utf-8")
            except UnicodeDecodeError:
                continue

            if not s:
                continue

            if last_size > len(s):
                # today, the string blob is stored in order of length,
                # shortest to longest, so we can detect when we missed a string.
                #
                # for example:
                #
                #   0x4aab99:  nmidlelocked=
                #   0x4aaba7:  on zero Value
                #   0x4aabb5:  out of range  procedure in        <<< missed!
                #   0x4aabd1:  to finalizer
                #   0x4aabdf:  untyped args
                #   0x4aabed: -thread limit
                #
                # we probably missed the string: " procedure in "
                logger.warn("probably missed a string blob string ending at: 0x%x", start - 1)

            try:
                string = StaticString.from_utf8(sbuf, get_rdata_file_offset(pe, start), min_length)
                yield string
            except ValueError:
                pass

        # when we recover the last string from the string blob table,
        # it may have some junk at the end.
        #
        # this is because the string blob might be stored next to non-zero, non-string data.
        # when we search for the | 00 00 00 00 | for the end of the string blob,
        # we may pick up some of this non-string data.
        #
        # so we try to recover the last string by searching for the longest
        # valid UTF-8 string from that last pointer.
        # it still may have junk appended to it, but at least its UTF-8.
        last_pointer = string_blob_pointers[-1]
        last_pointer_offset = last_pointer - string_blob_start
        last_buf = string_blob_buf[last_pointer_offset:]
        for size in range(len(last_buf), 0, -1):
            try:
                s = last_buf[:size].decode("utf-8")
            except UnicodeDecodeError:
                continue
            else:
                try:
                    string = StaticString.from_utf8(last_buf[:size], last_pointer, min_length)
                    yield string
                except ValueError:
                    pass
                break


def extract_go_strings(sample, min_length) -> List[StaticString]:
    """
    extract Go strings from the given PE file
    """

    p = pathlib.Path(sample)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    go_strings: List[StaticString] = list()
    go_strings.extend(get_string_blob_strings(pe, min_length))
    go_strings.extend(get_stackstrings(pe, min_length))

    return go_strings


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

    logging.basicConfig(level=logging.DEBUG)

    go_strings = sorted(extract_go_strings(args.path, args.min_length), key=lambda s: s.offset)
    for string in go_strings:
        print(f"{string.offset:#x}: {string.string}")


if __name__ == "__main__":
    sys.exit(main())

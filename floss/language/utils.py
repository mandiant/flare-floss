import re
import array
import struct
from typing import List, Tuple, Iterable, Optional
from dataclasses import dataclass

import pefile
from typing_extensions import TypeAlias

import floss.utils

VA: TypeAlias = int


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

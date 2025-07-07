import re
import array
import struct
import hashlib
from typing import List, Tuple, Iterable, Optional
from dataclasses import dataclass

import pefile
import tabulate
from typing_extensions import TypeAlias

import floss.utils
from floss.results import StaticString, StringEncoding
from floss.render.sanitize import sanitize

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



    ```rust
        /// # Representation
        ///
        /// A `String` is made up of three components: a pointer to some bytes, a
        /// length, and a capacity. The pointer points to an internal buffer `String`
        /// uses to store its data. The length is the number of bytes currently stored
        /// in the buffer, and the capacity is the size of the buffer in bytes. As such,
        /// the length will always be less than or equal to the capacity.
        ///

    ```
    We only use pointer and length data

    https://github.com/rust-lang/rust/blob/3911a63b7777e19dad4043542f908018e70c0bdd/library/alloc/src/string.rs

    """

    address: VA
    length: int


def get_rdata_section(pe: pefile.PE) -> pefile.SectionStructure:
    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            return section

    raise ValueError("no .rdata section found")


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


def find_i386_push_xrefs(buf: bytes) -> Iterable[VA]:
    """
    scan the given data found at the given base address
    to find all the 32-bit PUSH instructions,
    extracting the target virtual address.
    """
    push_insn_re = re.compile(
        rb"""
        (
              \x68       # 68 aa aa 00 00       push   0xaaaa
        )
        (?P<address>....)
        """,
        re.DOTALL + re.VERBOSE,
    )

    for match in push_insn_re.finditer(buf):
        address_bytes = match.group("address")
        address = struct.unpack("<I", address_bytes)[0]

        yield address


def find_amd64_push_xrefs(buf: bytes) -> Iterable[VA]:
    """
    scan the given data found at the given base address
    to find all the 64-bit PUSH instructions,
    extracting the target virtual address.
    """
    push_insn_re = re.compile(
        rb"""
        (
              \x68       # 68 aa aa 00 00       push   0xaaaa
        )
        (?P<address>....)
        """,
        re.DOTALL + re.VERBOSE,
    )

    for match in push_insn_re.finditer(buf):
        address_bytes = match.group("address")
        address = struct.unpack("<Q", address_bytes)[0]

        yield address


def find_push_xrefs(pe: pefile.PE) -> Iterable[VA]:
    """
    scan the executable sections of the given PE file
    for PUSH instructions that reference valid memory addresses,
    yielding the virtual addresses.
    """
    low, high = get_image_range(pe)

    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue

        code = section.get_data()

        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            xrefs = find_amd64_push_xrefs(code)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            xrefs = find_i386_push_xrefs(code)
        else:
            raise ValueError("unhandled architecture")

        for xref in xrefs:
            if low <= xref < high:
                yield xref


def find_i386_mov_xrefs(buf: bytes) -> Iterable[VA]:
    """
    scan the given data found at the given base address
    to find all the 32-bit MOV instructions,
    extracting the target virtual address.
    """
    mov_insn_re = re.compile(
        rb"""
        (
              \xB9       # b9 aa aa 00 00       mov    ecx,0xaaaa
            | \xBB       # bb aa aa 00 00       mov    ebx,0xaaaa
            | \xBA       # ba aa aa 00 00       mov    edx,0xaaaa
            | \xB8       # b8 aa aa 00 00       mov    eax,0xaaaa
            | \xBE       # be aa aa 00 00       mov    esi,0xaaaa
            | \xBF       # bf aa aa 00 00       mov    edi,0xaaaa
        )
        (?P<address>....)
        """,
        re.DOTALL + re.VERBOSE,
    )

    for match in mov_insn_re.finditer(buf):
        address_bytes = match.group("address")
        address = struct.unpack("<I", address_bytes)[0]

        yield address


def find_amd64_mov_xrefs(buf: bytes) -> Iterable[VA]:
    """
    scan the given data found at the given base address
    to find all the 64-bit MOV instructions,
    extracting the target virtual address.
    """
    mov_insn_re = re.compile(
        rb"""
        (
              \x48 \xC7 \xC0       # 48 c7 c0 aa aa 00 00       mov    rax,0xaaaa
            | \x48 \xC7 \xC1       # 48 c7 c1 aa aa 00 00       mov    rcx,0xaaaa
            | \x48 \xC7 \xC2       # 48 c7 c2 aa aa 00 00       mov    rdx,0xaaaa
            | \x48 \xC7 \xC3       # 48 c7 c3 aa aa 00 00       mov    rbx,0xaaaa
            | \x48 \xC7 \xC5       # 48 c7 c5 aa aa 00 00       mov    rbp,0xaaaa
            | \x48 \xC7 \xC6       # 48 c7 c6 aa aa 00 00       mov    rsi,0xaaaa
            | \x48 \xC7 \xC7       # 48 c7 c7 aa aa 00 00       mov    rdi,0xaaaa
        )
        (?P<address>....)
        """,
        re.DOTALL + re.VERBOSE,
    )

    for match in mov_insn_re.finditer(buf):
        address_bytes = match.group("address")
        address = struct.unpack("<Q", address_bytes)[0]

        yield address


def find_mov_xrefs(pe: pefile.PE) -> Iterable[VA]:
    """
    scan the executable sections of the given PE file
    for MOV instructions that reference valid memory addresses,
    yielding the virtual addresses.
    """
    low, high = get_image_range(pe)

    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue

        code = section.get_data()

        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            xrefs = find_amd64_mov_xrefs(code)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            xrefs = find_i386_mov_xrefs(code)
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

    if not buf:
        return

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

        # TODO add .text here for Go version 1.12?
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
            va = candidate.address
            rva = va - image_base

            if not (low <= va < high):
                continue

            target_section = pe.get_section_by_rva(rva)
            if not target_section:
                # string instance must be in a section
                continue

            # TODO in older Go versions, e.g. 1.12, this may be the case (stored in .text), see 33b5da...
            if target_section.IMAGE_SCN_MEM_EXECUTE:
                # string instances aren't found with the code
                continue

            if not target_section.IMAGE_SCN_MEM_READ:
                # string instances must be readable, naturally
                continue

            try:
                section_start, _, section_data = next(filter(lambda s: s[0] <= candidate.address < s[1], section_datas))
            except StopIteration:
                continue

            instance_offset = candidate.address - section_start
            # remember: section_data is a memoryview, so this is a fast slice.
            # when not using memoryview, this takes a *long* time (dozens of seconds or longer).
            instance_data = section_data[instance_offset : instance_offset + candidate.length]

            if len(instance_data) != candidate.length:
                continue

            yield candidate

            # we would want to be able to validate that structure actually points
            # to valid UTF-8 data;
            # however, even copying the bytes here is very slow,
            # dozens of seconds or more (suspect many minutes).


def get_extract_stats(
    pe: pefile, all_ss_strings: List[StaticString], lang_strings: List[StaticString], min_len: int, min_blob_len=0
) -> float:
    # min_blob_len: this is the minimum length of a string blob in binary file to be considered for extraction
    all_strings = list()
    # these are ascii, extract these utf-8 to get fewer chunks (ascii may split on two-byte characters, for example)
    for ss in all_ss_strings:
        sec = pe.get_section_by_rva(ss.offset)
        secname = sec.Name.decode("utf-8").split("\x00")[0] if sec else ""
        all_strings.append((secname, ss))

    len_all_ss = 0
    len_lang_str = 0

    lang_str_found = list()
    results = list()
    for secname, s in all_strings:
        if secname != ".rdata":
            continue

        if len(s.string) <= min_blob_len:
            continue

        len_all_ss += len(s.string)

        orig_len = len(s.string)
        sha256 = hashlib.sha256()
        sha256.update(s.string.encode("utf-8"))
        s_id = sha256.hexdigest()[:3].upper()
        s_range = (s.offset, s.offset + len(s.string))

        found = False
        for lang_str in lang_strings:
            sec = pe.get_section_by_rva(lang_str.offset)
            lang_str_sec = sec.Name.decode("utf-8").split("\x00")[0] if sec else ""

            if lang_str_sec != ".rdata":
                continue

            if (
                lang_str.string
                and lang_str.string in s.string
                and lang_str_sec == secname
                and s.offset <= lang_str.offset <= s.offset + orig_len
            ):
                found = True
                len_lang_str += len(lang_str.string)

                # remove found string data
                idx = s.string.find(lang_str.string)
                assert idx != -1
                if idx == 0:
                    new_offset = s.offset + idx + len(lang_str.string)
                else:
                    new_offset = s.offset

                replaced_s = s.string.replace(lang_str.string, "", 1)
                replaced_len = len(replaced_s)
                s_trimmed = StaticString(
                    string=replaced_s,
                    offset=new_offset,
                    encoding=s.encoding,
                )

                type_ = "substring"
                if s.string[: len(lang_str.string)] == lang_str.string and s.offset == lang_str.offset:
                    type_ = "exactsubstr"

                results.append((secname, s_id, s_range, True, type_, s, replaced_len, lang_str))

                s = s_trimmed

                lang_str_found.append(lang_str)

                if replaced_len < min_len:
                    results.append((secname, s_id, s_range, False, "missing", s, orig_len - replaced_len, lang_str))
                    break

        if not found:
            null = StaticString(string="", offset=0, encoding=StringEncoding.UTF8)
            results.append((secname, s_id, s_range, False, "", s, 0, null))

    rows = list()
    for lang_str in lang_strings:
        sec = pe.get_section_by_rva(lang_str.offset)
        lang_str_sec = sec.Name.decode("utf-8").split("\x00")[0] if sec else ""
        if lang_str_sec != ".rdata":
            continue

        if lang_str in lang_str_found:
            continue

        lang_str_data = lang_str.string
        if len(lang_str.string) >= 50:
            lang_str_data = lang_str.string[:36] + "...." + lang_str.string[-10:]
        lang_str_data = sanitize(lang_str_data)

        rows.append(
            (
                f"{lang_str_sec}",
                f"",
                f"",
                f"{lang_str.offset:8x}",
                f"",
                f"unmatched Language string",
                f"",
                f"",
                f"{len(lang_str.string) if lang_str.string else ''}",
                f"{lang_str_data}",
                f"{hex(lang_str.offset) if lang_str.offset else ''}",
            )
        )

    for r in results:
        secname, s_id, s_range, found, msg, s, len_after, lang_str = r

        sdata = s.string
        if len(s.string) >= 50:
            sdata = s.string[:36] + "...." + s.string[-10:]
        sdata = sanitize(sdata)

        lang_str_data = lang_str.string
        if len(lang_str.string) >= 50:
            lang_str_data = lang_str.string[:36] + "...." + lang_str.string[-10:]
        lang_str_data = sanitize(lang_str_data)

        len_info = f"{len(s.string):3d}"
        if found:
            len_info = f"{len(s.string):3d} > {len_after:3d} ({(len(s.string) - len_after) * -1:2d})"

        rows.append(
            (
                f"{secname}",
                f"<{s_id}>",
                f"{s_range[0]:x} - {s_range[1]:x}",
                f"{s.offset:8x}",
                f"{found}",
                f"{msg}",
                len_info,
                f"{sdata}",
                f"{len(lang_str.string) if lang_str.string else ''}",
                f"{lang_str_data}",
                f"{hex(lang_str.offset) if lang_str.offset else ''}",
            )
        )

    rows = sorted(rows, key=lambda t: t[3])

    print(
        tabulate.tabulate(
            rows,
            headers=[
                "section",
                "id",
                "range",
                "offset",
                "found",
                "msg",
                "slen",
                "string",
                "lang_str_len",
                "lang_string",
                "lang_str_off",
            ],
            tablefmt="psql",
        )
    )

    print(".rdata only")
    print("len all string chars:", len_all_ss)
    print("len lang string chars  :", len_lang_str)
    print(f"Percentage of string chars extracted: {round(100 * (len_lang_str / len_all_ss))}%")
    print()

    return 100 * (len_lang_str / len_all_ss)


def get_missed_strings(
    all_ss_strings: List[StaticString], lang_strings: List[StaticString], min_len: int
) -> List[StaticString]:
    missed_strings = list()

    for s in all_ss_strings:
        orig_len = len(s.string)

        found = False
        for lang_str in lang_strings:
            if lang_str.string and lang_str.string in s.string and s.offset <= lang_str.offset <= s.offset + orig_len:
                found = True

                # remove found string data
                idx = s.string.find(lang_str.string)
                assert idx != -1
                if idx == 0:
                    new_offset = s.offset + idx + len(lang_str.string)
                else:
                    new_offset = s.offset

                replaced_s = s.string.replace(lang_str.string, "", 1)
                replaced_len = len(replaced_s)
                s_trimmed = StaticString(
                    string=replaced_s,
                    offset=new_offset,
                    encoding=s.encoding,
                )
                s = s_trimmed

                if replaced_len < min_len:
                    break

        if not found:
            missed_strings.append(s)

    return missed_strings

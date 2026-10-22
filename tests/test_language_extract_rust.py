import pathlib

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.rust.extract import extract_rust_strings, get_static_strings_from_rdata


@pytest.fixture(scope="module")
def rust_strings32():
    n = 6
    path = pathlib.Path(__file__).parent / "data" / "language" / "rust" / "rust-hello" / "bin" / "rust-hello.exe"
    return extract_rust_strings(path, n)


@pytest.fixture(scope="module")
def rust_strings64():
    n = 6
    path = pathlib.Path(__file__).parent / "data" / "language" / "rust" / "rust-hello" / "bin" / "rust-hello64.exe"
    return extract_rust_strings(path, n)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        pytest.param("Hello, world!", 0xAD044, StringEncoding.UTF8, "rust_strings32"),
        # .rdata:00000001400BD030 48 65 6C 6C 6F 2C aHelloWorld     db 'Hello, world!',0Ah,0
        # .rdata:00000001400BD03F 00                                align 20h
        # .rdata:00000001400BD040                   ; const ___str_ pieces
        # .rdata:00000001400BD040 30 D0 0B 40 01 00 pieces          ___str_ <offset aHelloWorld, 0Eh>
        # .rdata:00000001400BD040 00 00 00 00                                               ; "Hello, world!\n"
        pytest.param("Hello, world!", 0xBB030, StringEncoding.UTF8, "rust_strings64"),
        # .rdata:00000001400BD050 69 6E 76 61 6C 69 aInvalidArgs    db 'invalid args',0
        # .rdata:00000001400BD05D 00 00 00                          align 20h
        # .rdata:00000001400BD060 50 D0 0B 40 01 00 stru_1400BD060  ___str_ <offset aInvalidArgs, 0Ch>
        # .rdata:00000001400BD060 00 00 00 00                                               ; "invalid args"
        pytest.param("invalid args", 0xBB050, StringEncoding.UTF8, "rust_strings64"),
    ],
)
def test_data_string_offset(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        # .text:0000000140021155 4C 8D 05 2C DA 09 lea     r8, aAccesserror ; "AccessError"
        # .text:000000014002115C 48 8D 74 24 20    lea     rsi, [rsp+38h+var_18]
        # .text:0000000140021161 41 B9 0B 00 00 00 mov     r9d, 11
        pytest.param("AccessError", 0xBCB88, StringEncoding.UTF8, "rust_strings64"),
        pytest.param("already destroyed", 0xBCB93, StringEncoding.UTF8, "rust_strings64"),
    ],
)
def test_lea_mov(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        # .text:0041EF8C 68 50 08 4B 00            push    offset unk_4B0850 ; "AccessError"
        # .text:0041EFB8 68 5B 08 4B 00            push    offset unk_4B085B "already destroyed"
        pytest.param("AccessError", 0xAE850, StringEncoding.UTF8, "rust_strings32"),
        pytest.param("already destroyed", 0xAE85B, StringEncoding.UTF8, "rust_strings32"),
    ],
)
def test_push(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,rust_strings",
    [
        # .text:0046B04A BA 1A 00 00 00                                mov     edx, 1Ah        ; jumptable 0046A19C case 8752
        # .text:0046B04F B9 A0 C2 4B 00                                mov     ecx, offset unk_4BC2A0
        # .text:0046B054 E9 93 F8 FF FF                                jmp     loc_46A8EC      ; jumptable 0046A1CA case 0
        pytest.param("DW_AT_SUN_return_value_ptr", 0xBA2A0, StringEncoding.UTF8, "rust_strings32"),
        pytest.param("DW_AT_SUN_c_vla", 0xBA2BA, StringEncoding.UTF8, "rust_strings32"),
    ],
)
def test_mov_jmp(request, string, offset, encoding, rust_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(rust_strings)


import struct as _struct


def _make_elf64(blob: bytes, rodata_va: int, addends, machine: int = 62) -> bytes:
    """Build a minimal ET_DYN ELF64 LSB with NULL, .rodata (holding ``blob``), .rela.dyn
    (one R_*_RELATIVE per addend) and .shstrtab sections -- enough for the Rust ELF extractor
    to find the string blob and its relocation-derived slice boundaries, with no real toolchain."""
    ehdr_size = 64
    ro_off = ehdr_size
    rela_off = (ro_off + len(blob) + 7) & ~7
    rela = b"".join(_struct.pack("<QQq", 0x1000 + 8 * i, (0 << 32) | 8, a) for i, a in enumerate(addends))
    shstr_off = rela_off + len(rela)
    names = b"\x00.rodata\x00.rela.dyn\x00.shstrtab\x00"
    shoff = (shstr_off + len(names) + 7) & ~7

    def shdr(name, typ, flags, addr, off, size, link, info, align, entsize):
        return _struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, size, link, info, align, entsize)

    sections = (
        shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        + shdr(names.index(b".rodata"), 1, 2, rodata_va, ro_off, len(blob), 0, 0, 1, 0)
        + shdr(names.index(b".rela.dyn"), 4, 0, 0, rela_off, len(rela), 0, 0, 8, 24)
        + shdr(names.index(b".shstrtab"), 3, 0, 0, shstr_off, len(names), 0, 0, 1, 0)
    )
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += _struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, 0, shoff, 0, ehdr_size, 0, 0, 64, 4, 3)

    data = bytearray(shoff + len(sections))
    data[0:64] = ehdr
    data[ro_off : ro_off + len(blob)] = blob
    data[rela_off : rela_off + len(rela)] = rela
    data[shstr_off : shstr_off + len(names)] = names
    data[shoff : shoff + len(sections)] = sections
    return bytes(data)


def test_extract_rust_strings_elf_splits_blob(tmp_path):
    # two logical strings concatenated with no separator in .rodata; a RELATIVE relocation
    # points at the second one, so the extractor must split the b2s run there (issue #1286)
    blob = b"canary-one-endpointcanary-two-config"
    rodata_va = 0x2000
    split_va = rodata_va + blob.index(b"canary-two")
    sample = tmp_path / "rust.elf"
    sample.write_bytes(_make_elf64(blob, rodata_va, [split_va]))

    strings = sorted(extract_rust_strings(sample, 4), key=lambda s: s.offset)
    recovered = {s.string for s in strings}
    assert "canary-one-endpoint" in recovered
    assert "canary-two-config" in recovered

    # the split piece carries the correct file offset (.rodata starts at file offset 64 here)
    off = next(s.offset for s in strings if s.string == "canary-two-config")
    assert off == 64 + blob.index(b"canary-two")

    # the .rodata-range filter keeps these ELF strings
    assert get_static_strings_from_rdata(sample, strings)

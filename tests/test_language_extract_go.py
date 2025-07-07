import pathlib

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.go.extract import extract_go_strings


@pytest.fixture(scope="module")
def go_strings32():
    n = 6
    path = pathlib.Path(__file__).parent / "data" / "language" / "go" / "go-hello" / "bin" / "go-hello.exe"
    return extract_go_strings(path, n)


@pytest.fixture(scope="module")
def go_strings64():
    n = 6
    path = pathlib.Path(__file__).parent / "data" / "language" / "go" / "go-hello" / "bin" / "go-hello64.exe"
    return extract_go_strings(path, n)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .data:00534944 A0 35 4A 00                       dd offset aAdaptivestacks ; "adaptivestackstart"
        # .data:00534948 12                                db  12h
        pytest.param("adaptivestackstart", 0xA1BA0, StringEncoding.UTF8, "go_strings32"),
        # .data:00534944 A0 35 4A 00                       dd offset aAdaptivestacks ; "adaptivestackstart"
        # .data:00534948 12                                db  12h
        pytest.param("adaptivestackstart", 0xA9E33, StringEncoding.UTF8, "go_strings64"),
    ],
)
def test_data_string_offset(request, string, offset, encoding, go_strings):
    # .data:0000000000541568 33 A8 4A 00 00 00…                dq offset aAdaptivestacks ; "adaptivestackstart"
    # .data:0000000000541570 12                                db  12h
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:0048B12F 8D 05 F8 08 4C 00 lea     eax, off_4C08F8 ; "hello world"
        # .text:0048B135 89 44 24 24       mov     [esp+28h+var_4], eax
        pytest.param("hello world", 0xA03E1, StringEncoding.UTF8, "go_strings32"),
        # .text:000000000048DE46 48 8D 15 13 BB 03 00          lea     rdx, off_4C9960 ; "hello world"
        # .text:000000000048DE4D 48 89 54 24 30                mov     qword ptr [rsp+40h+var_18+8], rdx
        pytest.param("hello world", 0xA873A, StringEncoding.UTF8, "go_strings64"),
    ],
)
def test_lea_mov(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:000000000040428F 48 8D 05 2C 72 0A 00          lea     rax, aWriteOfGoPoint ; "write of Go pointer "
        # .text:0000000000404296 BB 14 00 00 00                mov     ebx, 14h
        # .text:000000000040429B 0F 1F 44 00 00                nop     dword ptr [rax+rax+00h]
        # .text:00000000004042A0 E8 DB 16 03 00                call    runtime_printstring
        pytest.param("write of Go pointer ", 0xAAAC2, StringEncoding.UTF8, "go_strings64"),
        # NOTE: for 32-bit, the string is present in binary file but is not referenced by any instruction
        # 004A4200  6E 6F 74 20 65 6D 70 74  79 77 72 69 74 65 20 6F  not emptywrite o
        # 004A4210  66 20 47 6F 20 70 6F 69  6E 74 65 72 20 77 73 32  f Go pointer ws2
        pytest.param("write of Go pointer ", 0xA2809, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_lea_mov2(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:00000000004032EA B9 1C 00 00 00                                mov     ecx, 1Ch
        # .text:00000000004032EF 48 89 C7                                      mov     rdi, rax
        # .text:00000000004032F2 48 89 DE                                      mov     rsi, rbx
        # .text:00000000004032F5 31 C0                                         xor     eax, eax
        # .text:00000000004032F7 48 8D 1D A6 A2 0A 00                          lea     rbx, unk_4AD5A4
        pytest.param("comparing uncomparable type ", 0xACBA4, StringEncoding.UTF8, "go_strings64"),
        # .text:00403276 8D 15 64 63 4A 00                             lea     edx, unk_4A6364
        # .text:0040327C 89 54 24 04                                   mov     [esp+1Ch+var_18], edx
        # .text:00403280 C7 44 24 08 1C 00 00 00                       mov     [esp+1Ch+var_14], 1Ch
        pytest.param("comparing uncomparable type ", 0xA4964, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_mov_lea(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:00000000004467E4 48 8D 05 7E 67 06 00          lea     rax, aOutOfMemorySta ; "out of memory (stackalloc)"
        # .text:00000000004467EB BB 1A 00 00 00                mov     ebx, 1Ah
        # .text:00000000004467F0 E8 4B CF FE FF                call    runtime_throw
        pytest.param("out of memory (stackalloc)", 0xAC569, StringEncoding.UTF8, "go_strings64"),
        # NOTE: for 32-bit, the string is present in binary file but is not referenced by any instruction
        # 004A5D00  20 64 6F 75 62 6C 65 20  77 61 6B 65 75 70 6F 75   double wakeupou
        # 004A5D10  74 20 6F 66 20 6D 65 6D  6F 72 79 20 28 73 74 61  t of memory (sta
        # 004A5D20  63 6B 61 6C 6C 6F 63 29  70 65 72 73 69 73 74 65  ckalloc)persiste
        pytest.param("out of memory (stackalloc)", 0xA430E, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_lea_mov_call(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:0000000000481211 48 C7 40 10 19 00 00 00       mov     qword ptr [rax+10h], 19h
        # .text:0000000000481219 48 8D 0D 71 B6 02 00          lea     rcx, aExpandenvironm ; "ExpandEnvironmentStringsW"
        # .text:0000000000481220 48 89 48 08                   mov     [rax+8], rcx
        pytest.param("ExpandEnvironmentStringsW", 0xABE91, StringEncoding.UTF8, "go_strings64"),
        # .text:0047EACA C7 40 0C 19 00 00 00                          mov     dword ptr [eax+0Ch], 19h
        # .text:0047EAD1 8D 0D 36 56 4A 00                             lea     ecx, unk_4A5636
        # .text:0047EAD7 89 48 08                                      mov     [eax+8], ecx
        pytest.param("ExpandEnvironmentStringsW", 0xA3C36, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_mov_lea_mov(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # 00000000004AB080  20 6E 6F 74 20 66 6F 75  6E 64 20 6D 61 72 6B 72   not found markr
        # 00000000004AB090  6F 6F 74 20 6A 6F 62 73  20 64 6F 6E 65 0A 20 74  oot jobs done. t
        pytest.param(" markroot jobs done\n", 0xAA68A, StringEncoding.UTF8, "go_strings64"),
        # 004A3DE0  66 6F 75 6E 64 20 6D 61  72 6B 72 6F 6F 74 20 6A  found markroot j
        # 004A3DF0  6F 62 73 20 64 6F 6E 65  0A 20 74 6F 20 75 6E 61  obs done. to una
        pytest.param(" markroot jobs done\n", 0xA23E5, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_strings_with_newline_char_0A(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.skip(reason="not extracted via go_strings")
@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .idata:000000000062232A word_62232A     dw 0                    ; DATA XREF: .idata:0000000000622480↓o
        # .idata:000000000062232C                 db 'AddVectoredExceptionHandler',0                mov     [rax+8], rcx
        pytest.param("AddVectoredExceptionHandler", 0x1C5B2C, StringEncoding.ASCII, "go_strings64"),
        # .idata:005E531E word_5E531E     dw 0                    ; DATA XREF: .idata:005E53D4↓o
        # .idata:005E5320                 db 'AddVectoredExceptionHandler',0                                     mov     [eax+8], ecx
        pytest.param("AddVectoredExceptionHandler", 0x1B5120, StringEncoding.ASCII, "go_strings32"),
    ],
)
def test_import_data(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)

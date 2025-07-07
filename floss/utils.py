# Copyright 2017 Google LLC
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

import os
import re
import sys
import mmap
import time
import inspect
import logging
import argparse
import builtins
import contextlib
from typing import Set, Tuple, Iterable, Optional
from pathlib import Path
from collections import OrderedDict

import tqdm
import tabulate
import vivisect
import viv_utils
import envi.archs
import viv_utils.emulator_drivers
from envi import Emulator

import floss.strings
import floss.logging_

from .const import MEGABYTE, MOD_NAME, MAX_STRING_LENGTH
from .results import StaticString
from .strings import extract_ascii_unicode_strings
from .api_hooks import ENABLED_VIV_DEFAULT_HOOKS

STACK_MEM_NAME = "[stack]"

logger = floss.logging_.getLogger(__name__)


class InstallContextMenu(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        super(InstallContextMenu, self).__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        # Theoretically, we don't need to check the platform again here,
        # because non-Windows platforms will not accept the --install-right-click-menu parameter at all.
        # This judgment is just to make the mypy type check pass.
        # The same logic applies to `UninstallContextMenu` below.
        if sys.platform == "win32":
            import winreg as reg

            menu_name = "Open with FLOSS"
            icon_path = None

            if getattr(sys, "frozen", False):
                # If this is a standalone floss.exe, the path to the floss is sys.executable
                menu_command = f'C:\\windows\\system32\\cmd.exe /K "^"{sys.executable}^" ^"%1^""'
                icon_path = sys.executable
            else:
                menu_command = f'C:\\windows\\system32\\cmd.exe /K "python -m floss ^"%1^""'

            # Create `shell` if it does not exist
            try:
                shell_key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\\Classes\\*\\shell", 0, reg.KEY_SET_VALUE)
            except FileNotFoundError:
                shell_key = reg.CreateKey(reg.HKEY_CURRENT_USER, r"Software\\Classes\\*\\shell")
                shell_key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\\Classes\\*\\shell", 0, reg.KEY_SET_VALUE)

            reg.SetValue(shell_key, menu_name, reg.REG_SZ, menu_name)

            menu_key = reg.OpenKey(shell_key, menu_name, 0, reg.KEY_SET_VALUE)
            if icon_path:
                reg.SetValueEx(menu_key, "Icon", 0, reg.REG_SZ, icon_path)
            reg.SetValue(menu_key, "command", reg.REG_SZ, menu_command)
            sys.exit(0)


class UninstallContextMenu(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        super(UninstallContextMenu, self).__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if sys.platform == "win32":
            import winreg as reg

            menu_name = "Open with FLOSS"

            shell_key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\\Classes\\*\\shell")
            menu_key = reg.OpenKey(shell_key, menu_name)

            reg.DeleteKey(menu_key, "command")
            reg.DeleteKey(shell_key, menu_name)
            sys.exit(0)


def set_vivisect_log_level(level) -> None:
    logging.getLogger("vivisect").setLevel(level)
    logging.getLogger("vivisect.base").setLevel(level)
    logging.getLogger("vivisect.impemu").setLevel(level)
    logging.getLogger("vtrace").setLevel(level)
    logging.getLogger("envi").setLevel(level)
    logging.getLogger("envi.codeflow").setLevel(level)


def make_emulator(vw) -> Emulator:
    """
    create an emulator using consistent settings.
    """
    emu = vw.getEmulator(logwrite=True, taintbyte=b"\xFE")
    remove_stack_memory(emu)
    emu.initStackMemory(stacksize=int(0.5 * MEGABYTE))
    emu.setStackCounter(emu.getStackCounter() - int(0.25 * MEGABYTE))
    # do not short circuit rep prefix
    emu.setEmuOpt("i386:repmax", 256)  # 0 == no limit on rep prefix
    viv_utils.emulator_drivers.remove_default_viv_hooks(emu, allow_list=ENABLED_VIV_DEFAULT_HOOKS)
    return emu


def remove_stack_memory(emu: Emulator):
    # TODO this is a hack while vivisect's initStackMemory() has a bug
    memory_snap = emu.getMemorySnap()
    for i in range((len(memory_snap) - 1), -1, -1):
        (_, _, info, _) = memory_snap[i]
        if info[3] == STACK_MEM_NAME:
            del memory_snap[i]
            emu.setMemorySnap(memory_snap)
            emu.stack_map_base = None
            return
    raise ValueError("`STACK_MEM_NAME` not in memory map")


def dump_stack(emu):
    """
    Convenience debugging routine for showing
     state current state of the stack.
    """
    esp = emu.getStackCounter()
    stack_str = ""
    for i in range(16, -16, -4):
        if i == 0:
            sp = "<= SP"
        else:
            sp = "%02x" % (-i)
        stack_str = "%s\n0x%08x - 0x%08x %s" % (stack_str, (esp - i), floss.utils.get_stack_value(emu, -i), sp)
    logger.trace(stack_str)
    return stack_str


def get_stack_value(emu, offset):
    return emu.readMemoryFormat(emu.getStackCounter() + offset, "<P")[0]


def getPointerSize(vw):
    arch = vw.getMeta("Architecture")
    if arch == "amd64":
        return 8
    elif arch == "i386":
        return 4
    else:
        raise NotImplementedError("unexpected architecture: %s" % (vw.arch.__class__.__name__))


def get_imagebase(vw):
    basename = vw.getFileByVa(vw.getEntryPoints()[0])
    return vw.getFileMeta(basename, "imagebase")


def get_vivisect_meta_info(vw, selected_functions, decoding_function_features):
    info = OrderedDict()
    entry_points = vw.getEntryPoints()
    basename = None
    if entry_points:
        basename = vw.getFileByVa(entry_points[0])

    # "blob" is the filename for shellcode
    if basename and basename != "blob":
        version = vw.getFileMeta(basename, "Version")
        md5sum = vw.getFileMeta(basename, "md5sum")
        baseva = hex(vw.getFileMeta(basename, "imagebase"))
    else:
        version = "N/A"
        md5sum = "N/A"
        baseva = "N/A"

    info["version"] = version
    info["MD5 Sum"] = md5sum
    info["format"] = vw.getMeta("Format")
    info["architecture"] = vw.getMeta("Architecture")
    info["platform"] = vw.getMeta("Platform")
    disc = vw.getDiscoveredInfo()[0]
    undisc = vw.getDiscoveredInfo()[1]
    if disc + undisc > 0:
        info["percentage of discovered executable surface area"] = "%.1f%% (%s / %s)" % (
            disc * 100.0 / (disc + undisc),
            disc,
            disc + undisc,
        )
    info["base VA"] = baseva
    info["entry point(s)"] = ", ".join(map(hex, entry_points))
    info["number of imports"] = len(vw.getImports())
    info["number of exports"] = len(vw.getExports())
    info["number of functions"] = len(vw.getFunctions())

    if selected_functions:
        meta = []
        for fva in selected_functions:
            if is_thunk_function(vw, fva) or viv_utils.flirt.is_library_function(vw, fva):
                continue

            xrefs_to = len(vw.getXrefsTo(fva))
            num_args = len(vw.getFunctionArgs(fva))
            function_meta = vw.getFunctionMetaDict(fva)
            instr_count = function_meta.get("InstructionCount")
            block_count = function_meta.get("BlockCount")
            size = function_meta.get("Size")
            score = round(decoding_function_features.get(fva, {}).get("score", 0), 3)
            meta.append((hex(fva), score, xrefs_to, num_args, size, block_count, instr_count))
        info["selected functions' info"] = "\n%s" % tabulate.tabulate(
            meta, headers=["fva", "score", "#xrefs", "#args", "size", "#blocks", "#instructions"]
        )

    return info


def hex(i):
    return "0x%x" % (i)


# TODO ideally avoid emulation in the first place
#  libary detection appears to fail, called via __amsg_exit or __abort
#  also see issue #296 for another possible solution
FP_STRINGS = (
    "R6002",
    "R6016",
    "R6030",
    "Program: ",
    "Runtime Error!",
    "bad locale name",
    "ios_base::badbit set",
    "ios_base::eofbit set",
    "ios_base::failbit set",
    "- CRT not initialized",
    "program name unknown>",
    "<program name unknown>",
    "- floating point not loaded",
    "Program: <program name unknown>",
    "- not enough space for thread data",
    # all printable ASCII chars
    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
)

# ignore FLOSS artifacts, like strings created during emulation
FP_FLOSS_ARTIFACTS = (
    MOD_NAME,
    # hard-coded observed FP substrings
    MOD_NAME[1:],
    MOD_NAME[2:],
    MOD_NAME[:-1],
    MOD_NAME[1:-1],
    MOD_NAME[2:-1],
)


def extract_strings(buffer: bytes, min_length: int, exclude: Optional[Set[str]] = None) -> Iterable[StaticString]:
    if len(buffer) < min_length:
        return

    for s in floss.strings.extract_ascii_unicode_strings(buffer):
        if len(s.string) > MAX_STRING_LENGTH:
            continue

        if s.string in FP_STRINGS:
            continue

        if s.string in FP_FLOSS_ARTIFACTS:
            logger.trace("filtered FLOSS artifact: %s", s.string)
            continue

        decoded_string = strip_string(s.string)

        if len(decoded_string) < min_length:
            logger.trace("filtered: %s -> %s", s.string, decoded_string)
            continue

        logger.trace("strip: %s -> %s", s.string, decoded_string)

        if exclude and decoded_string in exclude:
            continue

        yield StaticString(string=decoded_string, offset=s.offset, encoding=s.encoding)


# FP string starts
# pVA, VA, 0VA, ..VA
FP_FILTER_PREFIX_1 = re.compile(r"^.{0,2}[0pP]?[]^\[_\\V]A")
# FP string ends
FP_FILTER_SUFFIX_1 = re.compile(r"[0pP]?[VWU][A@]$|Tp$")
# same printable ASCII char 4 or more consecutive times
FP_FILTER_REP_CHARS_1 = re.compile(r"([ -~])\1{3,}")
# same 4 printable ASCII chars 5 or more consecutive times
# /v7+/v7+/v7+/v7+
# ignore space and % for potential format strings, like %04d%02d%02d%02d%02d
FP_FILTER_REP_CHARS_2 = re.compile(r"([^% ]{4})\1{4,}")
# AaaAaAAaAAAaaAA-LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32
FP_FILTER_MINGW32 = re.compile(r"[aA]*-LIBGCCW32-.*-GTHR-MINGW32")
# aeriedjD#shasj
FP_FILTER_JUNK1 = re.compile(r"(aeriedjD#shasj)+")
# fatal error:
FP_FILTER_FATAL = re.compile(r".*fatal error: .*")
# lAll0Y
FP_FILER_LALL = re.compile(r"^lAll")

# be stricter removing FP strings for shorter strings
MAX_STRING_LENGTH_FILTER_STRICT = 6
# e.g. [ESC], [Alt], %d.dll
FP_FILTER_STRICT_INCLUDE = re.compile(r"^\[.*?]$|%[sd]")
# remove special characters
FP_FILTER_STRICT_SPECIAL_CHARS = re.compile(r"[^A-Za-z0-9.]")
FP_FILTER_STRICT_KNOWN_FP = re.compile(r"^O.*A$")


def strip_string(s) -> str:
    """
    Return string stripped from false positive (FP) pre- or suffixes.
    :param s: input string
    :return: string stripped from FP pre- or suffixes
    """
    for reg in (
        FP_FILTER_PREFIX_1,
        FP_FILTER_SUFFIX_1,
        FP_FILTER_REP_CHARS_1,
        FP_FILTER_REP_CHARS_2,
        FP_FILTER_MINGW32,
        FP_FILTER_JUNK1,
        FP_FILTER_FATAL,
        FP_FILER_LALL,
    ):
        s = re.sub(reg, "", s)
    if len(s) <= MAX_STRING_LENGTH_FILTER_STRICT:
        if not re.match(FP_FILTER_STRICT_INCLUDE, s):
            for reg2 in (FP_FILTER_STRICT_KNOWN_FP, FP_FILTER_STRICT_SPECIAL_CHARS):
                s = re.sub(reg2, "", s)
    return s


@contextlib.contextmanager
def redirecting_print_to_tqdm():
    """
    tqdm (progress bar) expects to have fairly tight control over console output.
    so calls to `print()` will break the progress bar and make things look bad.
    so, this context manager temporarily replaces the `print` implementation
    with one that is compatible with tqdm.
    via: https://stackoverflow.com/a/42424890/87207
    """
    old_print = print

    def new_print(*args, **kwargs):
        # If tqdm.tqdm.write raises error, use builtin print
        try:
            tqdm.tqdm.write(*args, **kwargs)
        except:
            old_print(*args, **kwargs)

    try:
        # Globaly replace print with new_print
        builtins.print = new_print
        yield
    finally:
        builtins.print = old_print


@contextlib.contextmanager
def timing(msg):
    t0 = time.time()
    yield
    t1 = time.time()
    logger.trace("perf: %s: %0.2fs", msg, t1 - t0)


def get_runtime_diff(time0):
    return round(time.time() - time0, 4)


def is_all_zeros(buffer: bytes):
    return all([b == 0 for b in buffer])


def get_progress_bar(functions, disable_progress, desc="", unit=""):
    pbar = tqdm.tqdm
    if disable_progress:
        # do not use tqdm to avoid unnecessary side effects when caller intends
        # to disable progress completely
        pbar = lambda s, *args, **kwargs: s
    return pbar(functions, desc=desc, unit=unit)


def is_thunk_function(vw, function_address):
    return vw.getFunctionMetaDict(function_address).get("Thunk", False)


def round_(i: int, size: int) -> int:
    """
    Round `i` to the nearest greater-or-equal-to multiple of `size`.
    """
    if i % size == 0:
        return i
    return i + (size - (i % size))


def readStringAtRva(emu, rva, maxsize=None, charsize=1):
    """
    Borrowed from vivisect/PE/__init__.py
    :param emu: emulator
    :param rva: virtual address of string
    :param maxsize: maxsize of string
    :param charsize: size of character (2 for wide string)
    :return: the read string
    """
    ret = bytearray()
    # avoid infinite loop
    if maxsize == 0:
        return bytes()
    while True:
        if maxsize and maxsize <= len(ret):
            break
        x = emu.readMemory(rva, 1)
        if x == b"\x00" or x is None:
            break
        ret += x
        rva += charsize
    return bytes(ret)


def contains_funcname(api, function_names: Tuple[str, ...]):
    """
    Returns True if the function name from the call API is part of any of the `function_names`
    This ignores casing and underscore prefixes like `_malloc` or `__malloc`
    """
    funcname = get_call_funcname(api)
    if not funcname or funcname in ("UnknownApi", "?"):
        return False
    funcname = funcname.lower()
    return any(fn.lower().lstrip("_") in funcname for fn in function_names)


def call_return(emu, api, argv, value):
    call_conv = get_call_conv(api)
    cconv = emu.getCallingConvention(call_conv)
    cconv.execCallReturn(emu, value, len(argv))


def get_call_conv(api):
    return api[2]


def get_call_funcname(api):
    return api[3]


def is_string_type_enabled(type_, disabled_types, enabled_types):
    if disabled_types:
        return type_ not in disabled_types
    elif enabled_types:
        return type_ in enabled_types
    else:
        return True


def get_max_size(size: int, max_: int, api: Optional[Tuple] = None, argv: Optional[Tuple] = None) -> int:
    if size > max_:
        post = ""
        if api:
            post = get_call_funcname(api)
        if argv:
            post = f" ({post} - {argv})"
        logger.trace("size too large 0x%x, truncating to: 0x%x%s", size, max_, post)
        size = max_
    return size


def get_referenced_strings(vw: vivisect.VivWorkspace, fva: int) -> Set[str]:
    # modified from capa
    f: viv_utils.Function = viv_utils.Function(vw, fva)
    strings: Set[str] = set()
    for bb in f.basic_blocks:
        for insn in bb.instructions:
            for i, oper in enumerate(insn.opers):
                if isinstance(oper, envi.archs.i386.disasm.i386ImmOper):
                    v = oper.getOperValue(oper)
                elif isinstance(oper, envi.archs.i386.disasm.i386ImmMemOper):
                    # like 0x10056CB4 in `lea eax, dword [0x10056CB4]`
                    v = oper.imm
                elif isinstance(oper, envi.archs.i386.disasm.i386SibOper):
                    # like 0x401000 in `mov eax, 0x401000[2 * ebx]`
                    v = oper.imm
                elif isinstance(oper, envi.archs.amd64.disasm.Amd64RipRelOper):
                    v = oper.getOperAddr(insn)
                else:
                    continue

                for v in derefs(vw, v):
                    try:
                        s = read_string(vw, v)
                    except ValueError:
                        continue
                    else:
                        # see strings.py for why we don't include \r and \n
                        strings.update([ss.rstrip("\x00") for ss in re.split("\r\n", s)])
    return strings


def derefs(vw, p):
    """
    recursively follow the given pointer, yielding the valid memory addresses along the way.
    useful when you may have a pointer to string, or pointer to pointer to string, etc.

    this is a "do what i mean" type of helper function.
    """
    depth = 0
    while True:
        if not vw.isValidPointer(p):
            return
        yield p

        try:
            next = vw.readMemoryPtr(p)
        except Exception:
            # if not enough bytes can be read, such as end of the section.
            # unfortunately, viv returns a plain old generic `Exception` for this.
            return

        # sanity: pointer points to self
        if next == p:
            return

        # sanity: avoid chains of pointers that are unreasonably deep
        depth += 1
        if depth > 10:
            return

        p = next


def read_string(vw, offset: int) -> str:
    try:
        alen = vw.detectString(offset)
    except envi.exc.SegmentationViolation:
        pass
    else:
        if alen > 0:
            return read_memory(vw, offset, alen).decode("utf-8")

    try:
        ulen = vw.detectUnicode(offset)
    except envi.exc.SegmentationViolation:
        pass
    except IndexError:
        # potential vivisect bug detecting Unicode at segment end
        pass
    else:
        if ulen > 0:
            if ulen % 2 == 1:
                # vivisect seems to mis-detect the end unicode strings
                # off by one, too short
                ulen += 1
            else:
                # vivisect seems to mis-detect the end unicode strings
                # off by two, too short
                ulen += 2
            return read_memory(vw, offset, ulen).decode("utf-16")

    raise ValueError("not a string", offset)


def read_memory(vw, va: int, size: int) -> bytes:
    # as documented in #176, vivisect will not readMemory() when the section is not marked readable.
    #
    # but here, we don't care about permissions.
    # so, copy the viv implementation of readMemory and remove the permissions check.
    #
    # this is derived from:
    #   https://github.com/vivisect/vivisect/blob/5eb4d237bddd4069449a6bc094d332ceed6f9a96/envi/memory.py#L453-L462
    for mva, mmaxva, mmap, mbytes in vw._map_defs:
        if va >= mva and va < mmaxva:
            mva, msize, mperms, mfname = mmap
            offset = va - mva
            return mbytes[offset : offset + size]
    raise envi.exc.SegmentationViolation(va)


def get_static_strings(sample: Path, min_length: int) -> list:
    """
    Returns list of static strings from the file which are above the minimum length
    """

    if sample.stat().st_size == 0:
        logger.warning("File is empty")
        return []

    with sample.open("r") as f:
        if hasattr(mmap, "MAP_PRIVATE"):
            # unix
            kwargs = {"flags": mmap.MAP_PRIVATE, "prot": mmap.PROT_READ}
        else:
            # windows
            kwargs = {"access": mmap.ACCESS_READ}

        with contextlib.closing(mmap.mmap(f.fileno(), 0, **kwargs)) as buf:
            return list(extract_ascii_unicode_strings(buf, min_length))

# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import contextlib

import envi
import viv_utils.emulator_drivers

import floss.utils
import floss.logging_

logger = floss.logging_.getLogger(__name__)


CURRENT_PROCESS_ID = 7331

# these default vivisect function hooks (imphooks) return as we expect, so we allow them
ENABLED_VIV_DEFAULT_HOOKS = (
    "kernel32.LoadLibraryA",
    "kernel32.LoadLibraryW",
    "kernel32.GetProcAddress",
    "kernel32.GetModuleHandleA",
    "kernel32.GetModuleHandleW",
    "kernel32.LoadLibraryExA",
    "kernel32.LoadLibraryExW",
    "kernel32.GetModuleHandleA",
    "kernel32.GetModuleHandleW",
)


class ApiMonitor(viv_utils.emulator_drivers.Monitor):
    """
    The ApiMonitor observes emulation and cleans up API function returns.
    """

    def __init__(self, function_index):
        self.function_index = function_index
        super().__init__()

    def apicall(self, emu, api, argv):
        pc = emu.getProgramCounter()
        logger.trace("apicall: 0x%x %s %s", pc, api, argv)

    def prehook(self, emu, op, startpc):
        # overridden from Monitor
        # helpful for debugging decoders, but super verbose!
        logger.trace("prehook: 0x%x %s", startpc, op)

    def posthook(self, emu, op, endpc):
        # overridden from Monitor
        if op.mnem == "ret":
            try:
                self._check_return(emu, op)
            except Exception as e:
                logger.trace("%s", e)

    # TODO remove stack fixes? works sometimes, but does it add value?
    def _check_return(self, emu, op):
        """
        Ensure that the target of the return is within the allowed set of functions.
        Do nothing, if return address is valid. If return address is invalid:
        _fix_return modifies program counter and stack pointer if a valid return address is found
        on the stack or raises an Exception if no valid return address is found.
        """
        function_start = self.function_index[op.va]
        return_addresses = self._get_return_vas(emu, function_start)

        if op.opers:
            # adjust stack in case of `ret imm16` instruction
            emu.setStackCounter(emu.getStackCounter() - op.opers[0].imm)

        return_address = floss.utils.get_stack_value(emu, -4)
        if return_address not in return_addresses:
            logger.trace(
                "Return address 0x%08x is invalid, expected one of: %s",
                return_address,
                ", ".join(map(hex, return_addresses)),
            )
            self._fix_return(emu, return_address, return_addresses)
            # TODO return, handle Exception
        else:
            logger.trace("Return address 0x%08x is valid, returning", return_address)
            # TODO return?

    def _get_return_vas(self, emu, function_start):
        """
        Get the list of valid addresses to which a function should return.
        """
        return_vas = []
        callers = emu.vw.getCallers(function_start)
        for caller in callers:
            call_op = emu.parseOpcode(caller)
            return_va = call_op.va + call_op.size
            return_vas.append(return_va)
        return return_vas

    def _fix_return(self, emu, return_address, return_addresses):
        """
        Find a valid return address from return_addresses on the stack. Adjust the stack accordingly
        or raise an Exception if no valid address is found within the search boundaries.
        Modify program counter and stack pointer, so the emulator does not return to a garbage address.
        """
        floss.utils.dump_stack(emu)
        NUM_ADDRESSES = 4
        pointer_size = emu.getPointerSize()
        STACK_SEARCH_WINDOW = pointer_size * NUM_ADDRESSES
        esp = emu.getStackCounter()
        for offset in range(0, STACK_SEARCH_WINDOW, pointer_size):
            ret_va_candidate = floss.utils.get_stack_value(emu, offset)
            if ret_va_candidate in return_addresses:
                emu.setProgramCounter(ret_va_candidate)
                emu.setStackCounter(esp + offset + pointer_size)
                logger.trace("Returning to 0x%08x, adjusted stack:", ret_va_candidate)
                floss.utils.dump_stack(emu)
                return

        floss.utils.dump_stack(emu)
        raise Exception("No valid return address found...")


def pointerSize(emu):
    """
    Convenience method whose name might be more readable
     than fetching emu.imem_psize.
    Returns the size of a pointer in bytes for the given emulator.
    :rtype: int
    """
    return emu.imem_psize


def popStack(emu):
    """
    Remove the element at the top of the stack.
    :rtype: int
    """
    v = emu.readMemoryFormat(emu.getStackCounter(), "<P")[0]
    emu.setStackCounter(emu.getStackCounter() + pointerSize(emu))
    return v


# TODO convert stateless/stateful hooks
class GetProcessHeapHook:
    """
    Hook and handle calls to GetProcessHeap, returning 0.
    """

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name == "kernel32.GetProcessHeap":
            # nop
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, 42, len(argv))
            return True


def round(i: int, size: int) -> int:
    """
    Round `i` to the nearest greater-or-equal-to multiple of `size`.
    """
    if i % size == 0:
        return i
    return i + (size - (i % size))


class AllocateHeapHook:
    """
    Hook calls to heap allocation functions, allocate memory in a "heap" section, and return pointers to this memory.
    The base heap address is 0x96960000.
    The max allocation size is 10 MB.
    """

    def __init__(self, *args, **kwargs):
        self._heap_addr = 0x96960000
        super().__init__(*args, **kwargs)

    # TODO shrink max allocation size?
    MAX_ALLOCATION_SIZE = 10 * 1024 * 1024

    def _allocate_mem(self, emu, size):
        # align to 16-byte boundary (64-bit), also works for 32-bit, which is normally 8-bytes
        size = round(size, 16)
        if size > self.MAX_ALLOCATION_SIZE:
            size = self.MAX_ALLOCATION_SIZE
        va = self._heap_addr
        logger.trace("RtlAllocateHeap: mapping %s bytes at %s", hex(size), hex(va))
        emu.addMemoryMap(va, envi.memory.MM_RWX, "[heap allocation]", b"\x00" * (size + 4))
        emu.writeMemory(va, b"\x00" * size)
        self._heap_addr += size
        return va

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name == "kernel32.LocalAlloc" or name == "kernel32.GlobalAlloc" or name == "kernel32.VirtualAlloc":
            size = argv[1]
        elif name in ("kernel32.VirtualAllocEx", "kernel32.HeapAlloc", "ntdll.RtlAllocateHeap"):
            size = argv[2]
        else:
            # not handled by this hook
            return False
        va = self._allocate_mem(emu, size)
        cconv = emu.getCallingConvention(cconv)
        cconv.execCallReturn(emu, va, len(argv))
        return True


class MallocHeap(AllocateHeapHook):
    """
    Hook calls to malloc and handle them like calls to RtlAllocateHeapHook.
    """

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name in ("msvcrt.malloc", "msvcrt.calloc", "malloc", "_malloc"):
            size = argv[0]
            va = self._allocate_mem(emu, size)
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, va, len(argv))
            return True
        elif name == "_calloc_base":
            size = argv[0]
            count = argv[1]
            va = self._allocate_mem(emu, size * count)
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, va, 2)  # TODO len(argv)?
            return True


class HeapFree:
    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name in ("kernel32.VirtualFree", "kernel32.HeapFree", "ntdll.RtlFreeHeap"):
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, 1, len(argv))  # If the function succeeds, the return value is nonzero.
            return True


class MemcpyHook:
    """
    Hook and handle calls to memcpy and memmove.
    """

    MAX_COPY_SIZE = 1024 * 1024 * 32  # don't attempt to copy more than 32MB, or something is wrong

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name in ("msvcrt.memcpy", "msvcrt.memmove", "memmove"):
            dst, src, count = argv
            if count > self.MAX_COPY_SIZE:
                logger.trace("unusually large memcpy, truncating to 32MB: 0x%x", count)
                count = self.MAX_COPY_SIZE
            data = emu.readMemory(src, count)
            emu.writeMemory(dst, data)
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, 0x0, len(argv))
            return True


def readStringAtRva(emu, rva, maxsize=None):
    """
    Borrowed from vivisect/PE/__init__.py
    :param emu: emulator
    :param rva: virtual address of string
    :param maxsize: maxsize of string
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
        rva += 1
    return bytes(ret)


class StrlenHook:
    """
    Hook and handle calls to strlen
    """

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        # TODO kernel32.lstrlenW, _wcslen, wcslen
        if name and name.lower() in ("msvcrt.strlen", "_strlen", "kernel32.lstrlena"):
            string_va = argv[0]
            s = readStringAtRva(emu, string_va, 256)
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, len(s), len(argv))
            return True


class StrnlenHook:
    """
    Hook and handle calls to strnlen.
    """

    # TODO make much shorter
    MAX_COPY_SIZE = 1024 * 1024 * 32

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name == "msvcrt.strnlen":
            string_va, maxlen = argv
            if maxlen > self.MAX_COPY_SIZE:
                logger.trace("unusually large strnlen, truncating to 32MB: 0x%x", maxlen)
                maxlen = self.MAX_COPY_SIZE
            s = readStringAtRva(emu, string_va, maxsize=maxlen)
            slen = s.index(b"\x00")
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, slen, len(argv))
            return True


class StrncmpHook:
    """
    Hook and handle calls to strncmp.
    """

    # TODO make much shorter
    # TODO combine with above
    MAX_COPY_SIZE = 1024 * 1024 * 32

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name == "msvcrt.strncmp":
            s1va, s2va, num = argv
            if num > self.MAX_COPY_SIZE:
                logger.trace("unusually large strnlen, truncating to 32MB: 0x%x", num)
                num = self.MAX_COPY_SIZE

            s1 = readStringAtRva(emu, s1va, maxsize=num)
            s2 = readStringAtRva(emu, s2va, maxsize=num)

            s1 = s1.partition(b"\x00")[0]
            s2 = s2.partition(b"\x00")[0]

            def cmp(a, b):
                return (a > b) - (a < b)

            result = cmp(s1, s2)

            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, result, len(argv))
            return True


class MemchrHook:
    """
    Hook and handle calls to memchr
    """

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        cconv = emu.getCallingConvention(cconv)
        if name == "msvcrt.memchr":
            ptr, value, num = argv
            value = bytes([value])
            memory = emu.readMemory(ptr, num)
            try:
                idx = memory.index(value)
                cconv.execCallReturn(emu, ptr + idx, len(argv))
            except ValueError:  # substring not found
                cconv.execCallReturn(emu, 0, len(argv))
            return True


class MemsetHook:
    """
    Hook and handle calls to memset
    """

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name == "msvcrt.memset":
            ptr, value, num = argv
            value = bytes([value] * num)
            emu.writeMemory(ptr, value)

            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, ptr, len(argv))
            return True


class ExitExceptionHook:
    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name in ("kernel32.ExitProcess", "kernel32.RaiseException"):
            raise viv_utils.emulator_drivers.StopEmulation()
        elif name == "kernel32.TerminateProcess":
            h_process = argv[0]
            if h_process == CURRENT_PROCESS_ID:
                raise viv_utils.emulator_drivers.StopEmulation()


class PrologHook:
    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name in ("__EH_prolog3", "__SEH_prolog4", "ntdll.seh4_prolog", "__SEH_epilog4"):
            # nop
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, 0, len(argv))
            return True


class SecurityCheckCookieHook:
    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name in ("__security_check_cookie", "@__security_check_cookie@4"):
            # nop
            # TODO nop helper!
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, 0, len(argv))
            return True


class GetLastErrorHook:
    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name == "kernel32.GetLastError":
            # TODO should there be no errors ever?
            error_success = 0
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, error_success, len(argv))
            return True


class GetCurrentProcessHook:
    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name == "kernel32.GetCurrentProcess":
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, CURRENT_PROCESS_ID, len(argv))
            return True


class CriticalSectionHook:
    """
    Hook calls to:
      - InitializeCriticalSection
    """

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api
        if name == "kernel32.InitializeCriticalSection":
            (hsection,) = argv
            emu.writeMemory(hsection, b"CS")
            cconv = emu.getCallingConvention(cconv)
            cconv.execCallReturn(emu, 0, len(argv))
            return True


# TODO track all unhooked API calls for later user information
#  cannot add a hook here because hooks are used in non-deterministic order
DEFAULT_HOOKS = (
    GetProcessHeapHook(),
    AllocateHeapHook(),
    MallocHeap(),
    HeapFree(),
    ExitExceptionHook(),
    PrologHook(),
    SecurityCheckCookieHook(),
    MemcpyHook(),
    StrlenHook(),
    MemchrHook(),
    MemsetHook(),
    StrnlenHook(),
    StrncmpHook(),
    GetLastErrorHook(),
    CriticalSectionHook(),
)

# TODO
# kernel32.GetModuleHandleA, kernel32.GetModuleHandleW
# msvcrt.printf, msvcrt.vfprintf, snprintf, etc.
# kernel32.GetModuleFileNameA, kernel32.GetModuleFileNameW


@contextlib.contextmanager
def defaultHooks(driver):
    """
    Install and remove the default set of hooks to handle common functions.

    intended usage:

        with defaultHooks(driver):
            driver.runFunction()
            ...
    """
    try:
        for hook in DEFAULT_HOOKS:
            driver.add_hook(hook)
        yield
    finally:
        for hook in DEFAULT_HOOKS:
            driver.remove_hook(hook)

# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import contextlib
from typing import Any, List, Tuple

import envi
import viv_utils.emulator_drivers

import floss.utils as fu
import floss.logging_
from floss.const import MOD_NAME

logger = floss.logging_.getLogger(__name__)

HEAP_BASE = 0x96960000
MAX_STR_SIZE = 512
MAX_MEMORY_ALLOC_SIZE = 5 * 1024 * 1024
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
    # TODO the below APIs are named incorrectly currently in vivisect, should be fixed in vivisect > 1.0.8
    "kernel32.GetModuleHandleExA",
    "kernel32.GetModuleHandleExW",
)


class ApiMonitor(viv_utils.emulator_drivers.Monitor):
    """The ApiMonitor observes emulation and cleans up API function returns."""

    def __init__(self, function_index):
        self.function_index = function_index
        super().__init__()

    def apicall(self, emu, api, argv):
        """Log API calls and their arguments."""
        pc = emu.getProgramCounter()
        logger.trace("apicall: 0x%x %s %s", pc, api, argv)

    def prehook(self, emu, op, startpc):
        """Log the start of an instruction."""
        # overridden from Monitor
        # helpful for debugging decoders, but super verbose!
        logger.trace("prehook: 0x%x %s", startpc, op)

    def posthook(self, emu, op, endpc):
        """Log the end of an instruction."""
        # overridden from Monitor
        if op.mnem == "ret":
            try:
                self._check_return(emu, op)
            except Exception as e:
                logger.trace("%s", e)

    # TODO remove stack fixes? works sometimes, but does it add value?
    def _check_return(self, emu, op):
        """Ensure that the target of the return is within the allowed set of functions.
        Do nothing, if return address is valid. If return address is invalid:
        _fix_return modifies program counter and stack pointer if a valid return address is found
        on the stack or raises an Exception if no valid return address is found.

        Args:
            emu: The emulator.
            op: The opcode.
        """
        function_start = self.function_index[op.va]
        return_addresses = self._get_return_vas(emu, function_start)

        if op.opers:
            # adjust stack in case of `ret imm16` instruction
            emu.setStackCounter(emu.getStackCounter() - op.opers[0].imm)

        return_address = fu.get_stack_value(emu, -4)
        if return_address not in return_addresses:
            logger.trace(
                "Return address 0x%08x is invalid, expected one of: %s",
                return_address,
                ", ".join(map(hex, return_addresses)),
            )
            self._fix_return(emu, return_address, return_addresses)
        else:
            logger.trace("Return address 0x%08x is valid, returning", return_address)

    def _get_return_vas(self, emu, function_start):
        """Get the list of valid addresses to which a function should return.

        Args:
            emu: The emulator.
            function_start: The start address of the function.

        Returns:
            A set of valid return addresses.
        """
        return_vas = set([])
        callers = emu.vw.getCallers(function_start)
        for caller in callers:
            call_op = emu.parseOpcode(caller)
            return_va = call_op.va + call_op.size
            return_vas.add(return_va)
        return return_vas

    def _fix_return(self, emu, return_address, return_addresses):
        """Find a valid return address from return_addresses on the stack. Adjust the stack accordingly
        or raise an Exception if no valid address is found within the search boundaries.
        Modify program counter and stack pointer, so the emulator does not return to a garbage address.

        Args:
            emu: The emulator.
            return_address: The return address.
            return_addresses: The set of valid return addresses.

        Raises:
            Exception: If no valid return address is found.
        """
        fu.dump_stack(emu)
        NUM_ADDRESSES = 4
        pointer_size = emu.getPointerSize()
        STACK_SEARCH_WINDOW = pointer_size * NUM_ADDRESSES
        esp = emu.getStackCounter()
        for offset in range(0, STACK_SEARCH_WINDOW, pointer_size):
            ret_va_candidate = fu.get_stack_value(emu, offset)
            if ret_va_candidate in return_addresses:
                emu.setProgramCounter(ret_va_candidate)
                emu.setStackCounter(esp + offset + pointer_size)
                logger.trace("Returning to 0x%08x, adjusted stack:", ret_va_candidate)
                fu.dump_stack(emu)
                return

        fu.dump_stack(emu)
        raise Exception("No valid return address found...")


class DemoHook:
    """A demo hook to demonstrate the API of the hook classes."""
    def __call__(
        self,
        emu: viv_utils.emulator_drivers.EmulatorDriver,
        api: Tuple[str, Any, str, str, List],
        argv: List,
    ):
        # api: (rettype, retname, callconv, funcname, [(argtype, argname), ...)]
        ...


class GetProcessHeapHook:
    """Hook calls to GetProcessHeap and return a fake heap handle."""

    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("GetProcessHeap",)):
            fu.call_return(emu, api, argv, 42)
            return True


class GetModuleFileNameHook:
    """Hook calls to GetModuleFileName and return the name of the current module."""

    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("GetModuleFileNameA",)):
            unicode = False
            hModule, lpFilename, nSize = argv
        elif fu.contains_funcname(api, ("GetModuleFileNameW",)):
            unicode = True
            hModule, lpFilename, nSize = argv
        elif fu.contains_funcname(api, ("GetModuleFileNameExA",)):
            unicode = False
            hProcess, hModule, lpFilename, nSize = argv
        elif fu.contains_funcname(api, ("GetModuleFileNameExW",)):
            unicode = False
            hProcess, hModule, lpFilename, nSize = argv
        else:
            return False

        if hModule == 0:
            if unicode:
                libname = MOD_NAME.encode("ascii")
            else:
                libname = MOD_NAME.encode("utf16-le")

            emu.writeMemory(lpFilename, libname)
            fu.call_return(emu, api, argv, len(libname))
            return True

        return False


class MemoryAllocationHook:
    """Hook calls to memory allocation functions: allocate memory and return pointer to this memory."""

    _heap_addr = HEAP_BASE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _allocate_mem(self, emu, size):
        """Allocate memory and return the address of the allocated memory. The memory is initialized with zeros.

        Args:
            emu: The emulator.
            size: The size of the memory to allocate.

        Returns:
            The address of the allocated memory.
        """
        va = self._heap_addr
        # align to 16-byte boundary (64-bit), also works for 32-bit, which is normally 8-bytes
        size = fu.round_(size, 16)
        size = fu.get_max_size(size, MAX_MEMORY_ALLOC_SIZE)
        logger.trace("mapping 0x%x bytes at 0x%x", size, va)
        emu.addMemoryMap(
            va, envi.memory.MM_RWX, "[heap allocation]", b"\x00" * (size + 4)
        )
        self._heap_addr += size
        return va

    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("malloc",)):
            size = argv[0]
        elif fu.contains_funcname(api, ("VirtualAlloc", "LocalAlloc", "GlobalAlloc")):
            size = argv[1]
        elif fu.contains_funcname(
            api, ("VirtualAllocEx", "HeapAlloc", "RtlAllocateHeap")
        ):
            size = argv[2]
        elif fu.contains_funcname(api, ("calloc", "calloc_base")):
            # size, count
            size = argv[0] * argv[1]
        else:
            # not handled by this hook
            return False

        va = self._allocate_mem(emu, size)
        fu.call_return(emu, api, argv, va)
        return True


class CppNewObjectHook(MemoryAllocationHook):
    """Hook calls to:
      - C++ new operator
    Thanks to @BenjaminSoelberg
    """
    ZNWJ = "Znwj"  # operator new(unsigned int)
    ZNAJ = "Znaj"  # operator new[](unsigned int)
    YAPAXI_Z_32 = "??2@YAPAXI@Z"  # void * __cdecl operator new(unsigned int)
    YAPEAX_K_Z_64 = (
        "??2@YAPEAX_K@Z"  # void * __ptr64 __cdecl operator new(unsigned __int64)
    )
    DEFAULT_SIZE = 0x1000

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, emu, api, argv):
        if fu.contains_funcname(
            api, (self.ZNWJ, self.ZNWJ, self.YAPAXI_Z_32, self.YAPEAX_K_Z_64)
        ):
            if argv and len(argv) > 0:
                size = argv[0]
            else:
                size = (
                    self.DEFAULT_SIZE
                )  # will allocate a default block size if vivisect failed to extract argv

            va = self._allocate_mem(emu, size)
            fu.call_return(emu, api, argv, va)
            return True


class MemoryFreeHook:
    """Hook calls to memory free functions: free memory and return success."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(
            api, ("free", "free_base", "VirtualFree", "HeapFree", "RtlFreeHeap")
        ):
            # If the function succeeds, the return value is nonzero.
            fu.call_return(emu, api, argv, 1)
            return True


class MemcpyHook:
    """Hook calls to memory copy functions: copy memory from source to destination."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("memcpy", "memmove")):
            dst, src, count = argv
        elif fu.contains_funcname(api, ("mempcy_s", "wmemcpy_s")):
            dst, dst_size, src, count = argv
        else:
            return False

        count = fu.get_max_size(count, MAX_MEMORY_ALLOC_SIZE, api, argv)
        data = emu.readMemory(src, count)
        emu.writeMemory(dst, data)
        fu.call_return(emu, api, argv, 0)
        return True


class StrlenHook:
    """Hook calls to string length functions: return the length of the string."""

    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("strlen", "lstrlena")):
            string_va = argv[0]
            s = fu.readStringAtRva(emu, string_va, MAX_STR_SIZE)
        elif fu.contains_funcname(api, ("wcslen", "lstrlenw")):
            string_va = argv[0]
            s = fu.readStringAtRva(emu, string_va, MAX_STR_SIZE, charsize=2)
        elif fu.contains_funcname(api, ("strnlen",)):
            string_va, maxlen = argv
            maxlen = fu.get_max_size(maxlen, MAX_STR_SIZE, api, argv)
            s = fu.readStringAtRva(emu, string_va, maxsize=maxlen)
        else:
            return False

        fu.call_return(emu, api, argv, len(s))
        return True


class StrncmpHook:
    """Hook calls to string compare functions: compare two strings."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("strncmp",)):
            s1va, s2va, num = argv
            num = fu.get_max_size(num, MAX_STR_SIZE, api, argv)
            s1 = fu.readStringAtRva(emu, s1va, maxsize=num)
            s2 = fu.readStringAtRva(emu, s2va, maxsize=num)

            def cmp(a, b):
                """Compare two strings.

                Args:
                    a: The first string.
                    b: The second string.

                Returns:
                    int: -1 if a < b, 0 if a == b, 1 if a > b.
                """
                return (a > b) - (a < b)

            result = cmp(s1, s2)
            fu.call_return(emu, api, argv, result)
            return True


class MemchrHook:
    """Hook calls to memchr: search for a character in a memory block."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("memchr",)):
            ptr, value, num = argv
            memory = emu.readMemory(ptr, num)
            value = bytes([value])
            try:
                idx = memory.index(value)
                offset = ptr + idx
            except ValueError:  # substring not found
                offset = 0
            fu.call_return(emu, api, argv, offset)
            return True


class MemsetHook:
    """Hook calls to memset: fill memory with a constant byte."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("memset",)):
            ptr, value, num = argv
            num = fu.get_max_size(num, MAX_MEMORY_ALLOC_SIZE, api, argv)
            value = bytes([value] * num)
            emu.writeMemory(ptr, value)
            fu.call_return(emu, api, argv, ptr)
            return True


class PrintfHook:
    """Hook calls to printf: write formatted data to stdout."""
    # TODO disabled for now as incomplete (need to implement string format) and could result in FP strings as is
    def __call__(self, emu, api, argv):
        # TODO vfprintf, vfwprintf, vfprintf_s, vfwprintf_s, vsnprintf, vsnwprintf, etc.
        if fu.contains_funcname(api, ("vsprintf", "vswprintf", "wvsprintfA")):
            buf, format_, *va_list = argv
            format_str = fu.readStringAtRva(emu, format_, maxsize=MAX_STR_SIZE)
            emu.writeMemory(buf, format_str)
            fu.call_return(emu, api, argv, buf)
            return True


class ExitExceptionHook:
    """Hook calls to exit and raise exception."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("ExitProcess", "RaiseException")):
            raise viv_utils.emulator_drivers.StopEmulation()
        if fu.contains_funcname(api, ("TerminateProcess",)):
            h_process = argv[0]
            if h_process == CURRENT_PROCESS_ID:
                raise viv_utils.emulator_drivers.StopEmulation()


class SehPrologEpilogHook:
    """Hook calls to SEH prolog and epilog functions and return success."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(
            api,
            (
                "__EH_prolog",
                "__EH_prolog3",
                "__SEH_prolog4",
                "seh4_prolog",
                "__SEH_epilog4",
            ),
        ):
            # nop
            fu.call_return(emu, api, argv, 0)
            return True


class SecurityCheckCookieHook:
    """Hook calls to __security_check_cookie and return success."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(
            api, ("__security_check_cookie", "@__security_check_cookie@4")
        ):
            # nop
            fu.call_return(emu, api, argv, 0)
            return True


class GetLastErrorHook:
    """Hook calls to GetLastError and return success."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("GetLastError",)):
            # always assuming success
            error_success = 0
            fu.call_return(emu, api, argv, error_success)
            return True


class GetCurrentProcessHook:
    """Hook calls to GetCurrentProcess and return a fake process handle."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("GetCurrentProcess",)):
            fu.call_return(emu, api, argv, CURRENT_PROCESS_ID)
            return True


class CriticalSectionHook:
    """Hook calls to InitializeCriticalSection and return a fake critical section handle."""
    def __call__(self, emu, api, argv):
        if fu.contains_funcname(api, ("InitializeCriticalSection",)):
            (hsection,) = argv
            emu.writeMemory(hsection, b"CS")
            fu.call_return(emu, api, argv, 0)
            return True


DEFAULT_HOOKS = (
    GetProcessHeapHook(),
    GetModuleFileNameHook(),
    MemoryAllocationHook(),
    CppNewObjectHook(),
    MemoryFreeHook(),
    ExitExceptionHook(),
    SehPrologEpilogHook(),
    SecurityCheckCookieHook(),
    MemcpyHook(),
    StrlenHook(),
    MemchrHook(),
    MemsetHook(),
    # PrintfHook(), currently disabled, see comments above
    StrncmpHook(),
    GetLastErrorHook(),
    GetCurrentProcessHook(),
    CriticalSectionHook(),
)


@contextlib.contextmanager
def defaultHooks(driver):
    """Install and remove the default set of hooks to handle common functions.

    intended usage:

        with defaultHooks(driver):
            driver.runFunction()
            ...

    Args:
        driver: The emulator driver.
    """
    try:
        for hook in DEFAULT_HOOKS:
            driver.add_hook(hook)
        yield
    finally:
        for hook in DEFAULT_HOOKS:
            driver.remove_hook(hook)

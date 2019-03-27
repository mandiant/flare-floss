# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import contextlib
from abc import abstractmethod

import envi
import viv_utils
from viv_utils.emulator_drivers import Hook, UnsupportedFunction


class ApiMonitor(viv_utils.emulator_drivers.Monitor):
    """
    The ApiMonitor observes emulation and cleans up API function returns.
    """

    def __init__(self, vw, function_index):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)
        self.function_index = function_index

    def apicall(self, emu, op, pc, api, argv):
        # overridden from Monitor
        self.d("apicall: %s %s %s %s %s", emu, op, pc, api, argv)

    def prehook(self, emu, op, startpc):
        # overridden from Monitor
        pass

    def posthook(self, emu, op, endpc):
        # overridden from Monitor
        if op.mnem == "ret":
            try:
                self._check_return(emu, op)
            except Exception as e:
                self.d(str(e))

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

        return_address = self.getStackValue(emu, -4)
        if return_address not in return_addresses:
            self._logger.debug("Return address 0x%08X is invalid, expected one of: %s",
                               return_address,
                               ', '.join(map(hex, return_addresses)))
            self._fix_return(emu, return_address, return_addresses)
            # TODO return, handle Exception
        else:
            self._logger.debug("Return address 0x%08X is valid, returning", return_address)
            # TODO return?

    def _get_return_vas(self, emu, function_start):
        """
        Get the list of valid addresses to which a function should return.
        """
        return_vas = []
        callers = self._vw.getCallers(function_start)
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
        self.dumpStack(emu)
        NUM_ADDRESSES = 4
        pointer_size = emu.getPointerSize()
        STACK_SEARCH_WINDOW = pointer_size * NUM_ADDRESSES
        esp = emu.getStackCounter()
        for offset in xrange(0, STACK_SEARCH_WINDOW, pointer_size):
            ret_va_candidate = self.getStackValue(emu, offset)
            if ret_va_candidate in return_addresses:
                emu.setProgramCounter(ret_va_candidate)
                emu.setStackCounter(esp + offset + pointer_size)
                self._logger.debug("Returning to 0x%08X, adjusted stack:", ret_va_candidate)
                self.dumpStack(emu)
                return

        self.dumpStack(emu)
        raise Exception("No valid return address found...")

    def dumpStack(self, emu):
        """
        Convenience debugging routine for showing
         state current state of the stack.
        """
        esp = emu.getStackCounter()
        stack_str = ""
        for i in xrange(16, -16, -4):
            if i == 0:
                sp = "<= SP"
            else:
                sp = "%02x" % (-i)
            stack_str = "%s\n0x%08x - 0x%08x %s" % (stack_str, (esp - i), self.getStackValue(emu, -i), sp)
        self.d(stack_str)

    def dumpState(self, emu):
        self.i("eip: 0x%x", emu.getRegisterByName("eip"))
        self.i("esp: 0x%x", emu.getRegisterByName("esp"))
        self.i("eax: 0x%x", emu.getRegisterByName("eax"))
        self.i("ebx: 0x%x", emu.getRegisterByName("ebx"))
        self.i("ecx: 0x%x", emu.getRegisterByName("ecx"))
        self.i("edx: 0x%x", emu.getRegisterByName("edx"))

        self.dumpStack(emu)


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


class LenientNamedHook(Hook):
    """
    Lenient named hook class
    Will accept a series of call names like:
        malloc
        _malloc
        __malloc
        msvcrt.malloc
    """

    def __init__(self, shortnames):
        super(LenientNamedHook, self).__init__()
        self.shortnames = [shortname.lower() for shortname in shortnames]

    def hook(self, callname, emu, callconv, api, argv):
        if callname:
            shortname = self.make_shortname(callname)
            if self.accept(shortname, emu, callconv, api, argv):
                return self.handle(shortname, emu, callconv, api, argv)

        return None

    def accept(self, shortname, emu, callconv, api, argv):
        return shortname in self.shortnames

    @abstractmethod
    def handle(self, shortname, emu, callconv, api, argv):
        raise UnsupportedFunction()

    @staticmethod
    def make_shortname(callname):
        shortname = callname[callname.find(".") + 1:].lower()  # Note that if no dot is found, it will copy whole string
        while shortname.startswith("_"):
            shortname = shortname[1:]

        return shortname


class GetProcessHeapHook(LenientNamedHook):
    """
    Hook and handle calls to GetProcessHeap, returning 0.
    """

    GET_PROCESS_HEAP = "GetProcessHeap"

    def __init__(self):
        super(GetProcessHeapHook, self).__init__([self.GET_PROCESS_HEAP])

    def handle(self, shortname, emu, callconv, api, argv):
        # nop
        callconv.execCallReturn(emu, 42, len(argv))
        return True


def round(i, size):
    """
    Round `i` to the nearest greater-or-equal-to multiple of `size`.

    :type i: int
    :type size: int
    :rtype: int
    """
    if i % size == 0:
        return i
    return i + (size - (i % size))


class BaseAllocatorHook(LenientNamedHook):
    """
    A generic hook that supports unique memory allocations (not thread safe).
    The base heap address is 0x96960000.
    The max allocation size is 10 MB.
    """
    MAX_ALLOCATION_SIZE = 10 * 1024 * 1024
    _heap_addr = 0x96960000  # Shared across all instances.

    def _allocate_mem(self, emu, size):
        size = round(size, 0x1000)
        if size > self.MAX_ALLOCATION_SIZE:
            size = self.MAX_ALLOCATION_SIZE
        va = self._heap_addr
        self.d("BaseAllocatorHook: mapping %s bytes at %s", hex(size), hex(va))
        emu.addMemoryMap(va, envi.memory.MM_RWX, "[heap allocation]", "\x00" * size)
        self._heap_addr += size
        return va


# TODO: What about heap alloc/heapCreate and so on ???
class RtlAllocateHeapHook(BaseAllocatorHook):
    """
    Hook calls to RtlAllocateHeap, allocate memory in a "heap"
     section, and return pointers to this memory.
    """

    HEAP_ALLOC = "HeapAlloc"
    RTL_ALLOCATE_HEAP = "RtlAllocateHeap"

    def __init__(self):
        super(RtlAllocateHeapHook, self).__init__([self.HEAP_ALLOC, self.RTL_ALLOCATE_HEAP])

    def handle(self, shortname, emu, callconv, api, argv):
        # works for kernel32.HeapAlloc
        hheap, flags, size = argv
        va = self._allocate_mem(emu, size)
        callconv.execCallReturn(emu, va, len(argv))
        return True


class AllocateHeapHook(BaseAllocatorHook):
    """
    Hook calls to AllocateHeap and handle them like calls to BaseAllocatorHook.
    """

    LOCAL_ALLOC = "LocalAlloc"
    GLOBAL_ALLOC = "GlobalAlloc"
    VIRTUAL_ALLOC = "VirtualAlloc"
    VIRTUAL_ALLOC_EX = "VirtualAllocEx"

    def __init__(self):
        super(AllocateHeapHook, self).__init__([self.LOCAL_ALLOC, self.GLOBAL_ALLOC,
                                                self.VIRTUAL_ALLOC, self.VIRTUAL_ALLOC_EX])

    def handle(self, shortname, emu, callconv, api, argv):
        if shortname in [self.LOCAL_ALLOC, self.GLOBAL_ALLOC, self.VIRTUAL_ALLOC]:
            size = argv[1]
        elif shortname == self.VIRTUAL_ALLOC_EX:
            size = argv[2]
        else:
            raise UnsupportedFunction()
        va = self._allocate_mem(emu, size)
        callconv.execCallReturn(emu, va, len(argv))
        return True


class MallocHeapHook(BaseAllocatorHook):
    """
    Hook calls to malloc.
    """

    MALLOC = "malloc"
    CALLOC = "calloc"

    def __init__(self):
        super(MallocHeapHook, self).__init__([self.MALLOC, self.CALLOC])

    def handle(self, shortname, emu, callconv, api, argv):
        if shortname == self.MALLOC:
            size = argv[0]
        elif shortname == self.CALLOC:
            size = argv[0] * argv[1]
        else:
            raise UnsupportedFunction()
        va = self._allocate_mem(emu, size)
        callconv.execCallReturn(emu, va, len(argv))
        return True


class MemcpyHook(LenientNamedHook):
    """
    Hook and handle calls to memcpy and memmove.
    """

    MEMCPY = "memcpy"
    MEMMOVE = "memmove"
    MAX_COPY_SIZE = 1024 * 1024 * 32  # don't attempt to copy more than 32MB, or something is wrong

    def __init__(self):
        super(MemcpyHook, self).__init__([self.MEMCPY, self.MEMMOVE])

    def handle(self, shortname, emu, callconv, api, argv):
        dst, src, count = argv
        if count > self.MAX_COPY_SIZE:
            self.d('unusually large memcpy, truncating to 32MB: 0x%x', count)
            count = self.MAX_COPY_SIZE
        data = emu.readMemory(src, count)
        emu.writeMemory(dst, data)
        callconv.execCallReturn(emu, 0x0, len(argv))
        return True


def readStringAtRva(emu, rva, maxsize=None):
    """
    Borrowed from vivisect/PE/__init__.py
    :param emu: emulator
    :param rva: virtual address of string
    :param maxsize: maxsize of string
    :return: the read string
    """
    ret = []
    while True:
        if maxsize and maxsize <= len(ret):
            break
        x = emu.readMemory(rva, 1)
        if x == '\x00' or x is None:
            break
        ret.append(x)
        rva += 1
    return ''.join(ret)


class StrlenHook(LenientNamedHook):
    """
    Hook and handle calls to strlen
    """

    STRLEN = "strlen"
    LSTRLENA = "lstrlena"

    def __init__(self):
        super(StrlenHook, self).__init__([self.STRLEN, self.LSTRLENA])

    def handle(self, shortname, emu, callconv, api, argv):
        string_va = argv[0]
        s = readStringAtRva(emu, string_va, 256)
        callconv.execCallReturn(emu, len(s), len(argv))
        return True


class StrnlenHook(LenientNamedHook):
    """
    Hook and handle calls to strnlen.
    """

    MAX_COPY_SIZE = 1024 * 1024 * 32
    STRNLEN = "strnlen"

    def __init__(self):
        super(StrnlenHook, self).__init__([self.STRNLEN])

    def handle(self, shortname, emu, callconv, api, argv):
        string_va, maxlen = argv
        if maxlen > self.MAX_COPY_SIZE:
            self.d('unusually large strnlen, truncating to 32MB: 0x%x', maxlen)
            maxlen = self.MAX_COPY_SIZE
        s = readStringAtRva(emu, string_va, maxsize=maxlen)
        slen = len(s.partition('\x00')[0])
        callconv.execCallReturn(emu, slen, len(argv))
        return True


class StrncmpHook(LenientNamedHook):
    """
    Hook and handle calls to strncmp.
    """

    MAX_COPY_SIZE = 1024 * 1024 * 32
    STRNCMP = "strncmp"

    def __init__(self):
        super(StrncmpHook, self).__init__([self.STRNCMP])

    def handle(self, shortname, emu, callconv, api, argv):
        s1va, s2va, num = argv
        if num > self.MAX_COPY_SIZE:
            self.d('unusually large strnlen, truncating to 32MB: 0x%x', num)
            num = self.MAX_COPY_SIZE

        s1 = readStringAtRva(emu, s1va, maxsize=num)
        s2 = readStringAtRva(emu, s2va, maxsize=num)

        s1 = s1.partition('\x00')[0]
        s2 = s2.partition('\x00')[0]

        result = cmp(s1, s2)

        callconv.execCallReturn(emu, result, len(argv))
        return True


class MemchrHook(LenientNamedHook):
    """
    Hook and handle calls to memchr
    """

    MEMCHR = "memchr"

    def __init__(self):
        super(MemchrHook, self).__init__([self.MEMCHR])

    def handle(self, shortname, emu, callconv, api, argv):
        ptr, value, num = argv
        value = chr(value)
        memory = emu.readMemory(ptr, num)
        try:
            idx = memory.index(value)
            callconv.execCallReturn(emu, ptr + idx, len(argv))
        except ValueError:  # substring not found
            callconv.execCallReturn(emu, 0, len(argv))
        return True


class ExitProcessHook(LenientNamedHook):
    """
    Hook calls to ExitProcess and stop emulation when these are hit.
    """

    EXIT_PROCESS = "ExitProcess"

    def __init__(self):
        super(ExitProcessHook, self).__init__([self.EXIT_PROCESS])

    def handle(self, shortname, emu, callconv, api, argv):
        raise viv_utils.emulator_drivers.StopEmulation()


class InitializeCriticalSectionHook(LenientNamedHook):
    """
    Hook calls to:
      - InitializeCriticalSection
    """

    INITIALIZE_CRITICAL_SECTION = "InitializeCriticalSection"

    def __init__(self):
        super(InitializeCriticalSectionHook, self).__init__([self.INITIALIZE_CRITICAL_SECTION])

    def handle(self, shortname, emu, callconv, api, argv):
        hsection, = argv
        emu.writeMemory(hsection, 0xDEADBEAF)
        callconv.execCallReturn(emu, 0, len(argv))
        return True


class CppNewObjectHook(BaseAllocatorHook):
    """
    Hook calls to:
      - C++ new operator
    """

    ZNWJ = "Znwj"                     # operator new(unsigned int)
    ZNAJ = "Znaj"                     # operator new[](unsigned int)
    YAPAXI_Z_32 = "??2@YAPAXI@Z"      # void * __cdecl operator new(unsigned int)
    YAPEAX_K_Z_64 = "??2@YAPEAX_K@Z"  # void * __ptr64 __cdecl operator new(unsigned __int64)
    DEFAULT_SIZE = 0x1000

    def __init__(self):
        super(CppNewObjectHook, self).__init__([self.ZNWJ, self.ZNAJ, self.YAPAXI_Z_32, self.YAPEAX_K_Z_64])

    def handle(self, shortname, emu, callconv, api, argv):
        if argv and len(argv) > 0:
            size = argv[0]
        else:
            size = self.DEFAULT_SIZE  # Will allocate a default block size if vivisect failed to extract argv
        va = self._allocate_mem(emu, size)
        callconv.execCallReturn(emu, va, len(argv))
        return True


DEFAULT_HOOKS = [
    GetProcessHeapHook(),
    RtlAllocateHeapHook(),
    AllocateHeapHook(),
    MallocHeapHook(),
    CppNewObjectHook(),
    ExitProcessHook(),
    MemcpyHook(),
    StrlenHook(),
    MemchrHook(),
    StrnlenHook(),
    StrncmpHook(),
    InitializeCriticalSectionHook(),
]


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

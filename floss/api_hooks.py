import contextlib

import envi
import viv_utils


class ApiMonitor(viv_utils.emulator_drivers.Monitor):
    '''
    The ApiMonitor observes emulation and cleans up API function returns.
    '''

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
        '''
        Ensure that the target of the return is within the allowed set of functions.
        Do nothing, if return address is valid. If return address is invalid:
        _fix_return modifies program counter and stack pointer if a valid return address is found
        on the stack or raises an Exception if no valid return address is found.
        '''
        function_start = self.function_index[op.va]
        return_addresses = self._get_return_vas(emu, function_start)

        if op.opers:
            # adjust stack in case of `ret imm16` instruction
            emu.setStackCounter(emu.getStackCounter() - op.opers[0].imm)

        return_address = self.getStackValue(emu, -4)
        if return_address not in return_addresses:
            self._logger.debug("Return address 0x%08X is invalid", return_address)
            self._fix_return(emu, return_address, return_addresses)
            # TODO return, handle Exception
        else:
            self._logger.debug("Return address 0x%08X is valid, returning", return_address)
            # TODO return?

    def _get_return_vas(self, emu, function_start):
        '''
        Get the list of valid addresses to which a function should return.
        '''
        return_vas = []
        callers = self._vw.getCallers(function_start)
        for caller in callers:
            call_op = emu.parseOpcode(caller)
            return_va = call_op.va + call_op.size
            return_vas.append(return_va)
        return return_vas

    def _fix_return(self, emu, return_address, return_addresses):
        '''
        Find a valid return address from return_addresses on the stack. Adjust the stack accordingly
        or raise an Exception if no valid address is found within the search boundaries.
        Modify program counter and stack pointer, so the emulator does not return to a garbage address.
        '''
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
        '''
        Convenience debugging routine for showing
         state current state of the stack.
        '''
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
    '''
    Convenience method whose name might be more readable
     than fetching emu.imem_psize.
    Returns the size of a pointer in bytes for the given emulator.
    :rtype: int
    '''
    return emu.imem_psize


def popStack(emu):
    '''
    Remove the element at the top of the stack.
    :rtype: int
    '''
    v = emu.readMemoryFormat(emu.getStackCounter(), "<P")[0]
    emu.setStackCounter(emu.getStackCounter() + pointerSize(emu))
    return v


class GetProcessHeapHook(viv_utils.emulator_drivers.Hook):
    '''
    Hook and handle calls to GetProcessHeap, returning 0.
    '''

    def hook(self, callname, emu, callconv, api, argv):
        if callname == "kernel32.GetProcessHeap":
            # nop
            callconv.execCallReturn(emu, 0, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


def round(i, size):
    '''
    Round `i` to the nearest greater-or-equal-to multiple of `size`.

    :type i: int
    :type size: int
    :rtype: int
    '''
    if i % size == 0:
        return i
    return i + (i - (i % size))


class RtlAllocateHeapHook(viv_utils.emulator_drivers.Hook):
    '''
    Hook calls to RtlAllocateHeap, allocate memory in a "heap"
     section, and return pointers to this memory.
    The base heap address is 0x69690000.
    The max allocation size is 10 MB.
    '''

    def __init__(self, *args, **kwargs):
        super(RtlAllocateHeapHook, self).__init__(*args, **kwargs)
        self._heap_addr = 0x69690000

    MAX_ALLOCATION_SIZE = 10 * 1024 * 1024

    def _allocate_mem(self, emu, size):
        size = round(size, 0x1000)
        if size > self.MAX_ALLOCATION_SIZE:
            size = self.MAX_ALLOCATION_SIZE
        va = self._heap_addr
        self.d("RtlAllocateHeap: mapping %s bytes at %s", hex(size), hex(va))
        emu.addMemoryMap(va, envi.memory.MM_RWX, "[heap allocation]", "\x00" * (size + 4))
        emu.writeMemory(va, "\x00" * size)
        self._heap_addr += size
        return va

    def hook(self, callname, driver, callconv, api, argv):
        # works for kernel32.HeapAlloc
        if callname == "ntdll.RtlAllocateHeap":
            emu = driver
            hheap, flags, size = argv
            va = self._allocate_mem(emu, size)
            callconv.execCallReturn(emu, va, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class AllocateHeap(RtlAllocateHeapHook):
    '''
    Hook calls to AllocateHeap and handle them like calls to RtlAllocateHeapHook.
    '''

    def __init__(self, *args, **kwargs):
        super(AllocateHeap, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "kernel32.LocalAlloc" or \
           callname == "kernel32.GlobalAlloc" or \
           callname == "kernel32.VirtualAlloc":
            size = argv[1]
        elif callname == "kernel32.VirtualAllocEx":
            size = argv[2]
        else:
            raise viv_utils.emulator_drivers.UnsupportedFunction()
        va = self._allocate_mem(driver, size)
        callconv.execCallReturn(driver, va, len(argv))
        return True


class MallocHeap(RtlAllocateHeapHook):
    '''
    Hook calls to malloc and handle them like calls to RtlAllocateHeapHook.
    '''

    def __init__(self, *args, **kwargs):
        super(MallocHeap, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.malloc" or \
           callname == "msvcrt.calloc":
            size = argv[0]
            va = self._allocate_mem(driver, size)
            callconv.execCallReturn(driver, va, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class MemcpyHook(viv_utils.emulator_drivers.Hook):
    '''
    Hook and handle calls to memcpy.
    '''

    def __init__(self, *args, **kwargs):
        super(MemcpyHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.memcpy":
            emu = driver
            dst, src, count = argv
            data = emu.readMemory(src, count)
            emu.writeMemory(dst, data)
            callconv.execCallReturn(emu, 0x0, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class StrlenHook(viv_utils.emulator_drivers.Hook):
    """
    Hook and handle calls to strlen
    """

    def __init__(self, *args, **kwargs):
        super(StrlenHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.strlen":
            emu = driver
            string_va = argv[0]
            s = self.readStringAtRva(emu, string_va, 256)
            callconv.execCallReturn(emu, len(s), len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()

    def readStringAtRva(self, emu, rva, maxsize=None):
        """
        Borrowed from vivisect/PE/__init__.py
        :param emu: emulator
        :param rva: virtual address of string
        :param maxsize: maxsize of string
        :return: the read string
        """
        ret = ''
        while True:
            if maxsize and maxsize <= len(ret):
                break
            x = emu.readMemory(rva, 1)
            if x == '\x00' or x is None:
                break
            ret += x
            rva += 1
        return ret


class MemchrHook(viv_utils.emulator_drivers.Hook):
    """
    Hook and handle calls to memchr
    """

    def __init__(self, *args, **kwargs):
        super(MemchrHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.memchr":
            emu = driver
            ptr, value, num = argv
            value = chr(value)
            memory = emu.readMemory(ptr, num)
            try:
                idx = memory.index(value)
                callconv.execCallReturn(emu, ptr + idx, len(argv))
            except ValueError:  # substring not found
                callconv.execCallReturn(emu, 0, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class ExitProcessHook(viv_utils.emulator_drivers.Hook):
    '''
    Hook calls to ExitProcess and stop emulation when these are hit.
    '''

    def __init__(self, *args, **kwargs):
        super(ExitProcessHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "kernel32.ExitProcess":
            raise viv_utils.emulator_drivers.StopEmulation()


DEFAULT_HOOKS = [
    GetProcessHeapHook(),
    RtlAllocateHeapHook(),
    AllocateHeap(),
    MallocHeap(),
    ExitProcessHook(),
    MemcpyHook(),
    StrlenHook(),
    MemchrHook(),
]


@contextlib.contextmanager
def defaultHooks(driver):
    '''
    Install and remove the default set of hooks to handle common functions.

    intended usage:

        with defaultHooks(driver):
            driver.runFunction()
            ...
    '''
    try:
        for hook in DEFAULT_HOOKS:
            driver.add_hook(hook)
        yield
    finally:
        for hook in DEFAULT_HOOKS:
            driver.remove_hook(hook)

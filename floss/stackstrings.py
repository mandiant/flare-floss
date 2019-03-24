# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import logging

from collections import namedtuple

import viv_utils
import envi.archs.i386
import envi.archs.amd64
import viv_utils.emulator_drivers

import strings
from utils import makeEmulator, is_fp_string, strip_string, MAX_STRING_LENGTH


logger = logging.getLogger(__name__)
MAX_STACK_SIZE = 0x10000

MIN_NUMBER_OF_MOVS = 5

CallContext = namedtuple("CallContext",
                         [
                             "pc",  # the current program counter, type: int
                             "sp",  # the current stack counter, type: int
                             "init_sp",   # the initial stack counter at start of function, type: int
                             "stack_memory",  # the active stack frame contents, type: str
                         ])


class StackstringContextMonitor(viv_utils.emulator_drivers.Monitor):
    """
    Observes emulation and extracts the active stack frame contents:
      - at each function call in a function, and
      - based on heuristics looking for mov instructions to a hardcoded buffer.
    """

    def __init__(self, vw, init_sp, bb_ends):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)
        # type: List[CallContext]
        self.ctxs = []

        self._init_sp = init_sp
        # index of VAs of the last instruction of all basic blocks
        self._bb_ends = bb_ends
        # count of stack mov instructions in current basic block.
        # not guaranteed to grow greater than MIN_NUMBER_OF_MOVS.
        self._mov_count = 0

    # overrides emulator_drivers.Monitor
    def apicall(self, emu, op, pc, api, argv):
        self.extract_context(emu, op)

    def extract_context(self, emu, op):
        """
        Extract only the bytes on the stack between the base pointer
         (specifically, stack pointer at function entry),
        and stack pointer.
        """
        stack_top = emu.getStackCounter()
        stack_bottom = self._init_sp
        stack_size = stack_bottom - stack_top
        if stack_size > MAX_STACK_SIZE:
            logger.debug('stack size too big: 0x%x', stack_size)
            return

        stack_buf = emu.readMemory(stack_top, stack_size)
        ctx = CallContext(op.va, stack_top, stack_bottom, stack_buf)
        self.ctxs.append(ctx)

    # overrides emulator_drivers.Monitor
    def posthook(self, emu, op, endpc):
        self.check_mov_heuristics(emu, op, endpc)

    def check_mov_heuristics(self, emu, op, endpc):
        """
        Extract contexts at end of a basic block (bb) if bb contains enough movs to a harcoded buffer.
        """
        # TODO check number of written bytes?
        # count movs, shortcut if this basic block has enough writes to trigger context extraction already
        if self._mov_count < MIN_NUMBER_OF_MOVS and self.is_stack_mov(op):
            self._mov_count += 1

        if endpc in self._bb_ends:
            if self._mov_count >= MIN_NUMBER_OF_MOVS:
                self.extract_context(emu, op)
            # reset counter at end of basic block
            self._mov_count = 0

    def is_stack_mov(self, op):
        if not op.mnem.startswith("mov"):
            return False

        opnds = op.getOperands()
        if not opnds:
            # no operands, e.g. movsb, movsd
            # fail safe and count these regardless of where data is moved to.
            return True
        return isinstance(opnds[0], envi.archs.i386.disasm.i386SibOper) or isinstance(opnds[0], envi.archs.i386.disasm.i386RegMemOper)


def extract_call_contexts(vw, fva, bb_ends):
    emu = makeEmulator(vw)
    monitor = StackstringContextMonitor(vw, emu.getStackCounter(), bb_ends)
    driver = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(emu)
    driver.add_monitor(monitor)
    driver.runFunction(fva, maxhit=1, maxrep=0x100, func_only=True)
    return monitor.ctxs


# StackString represents a stackstring extracted from a function.
StackString = namedtuple("StackString",
                         [
                             # type: int
                             # the address from which the stackstring was extracted.
                             "fva",

                             # type: str
                             # the string contents.
                             "s",

                             # type: int
                             # the program counter at which the stackstring existed.
                             "pc",

                             # here's what the following members represent...
                             #
                             #
                             # [smaller addresses]
                             #
                             # +---------------+  <- sp (top of stack)
                             # |               | \
                             # +---------------+  | offset
                             # |               | /
                             # +---------------+
                             # | "abc"         | \
                             # +---------------+  |
                             # |               |  |
                             # +---------------+  | frame_offset
                             # |               |  |
                             # +---------------+  |
                             # |               | /
                             # +---------------+  <- init_sp (bottom of stack, probably bp)
                             #
                             # [bigger addresses]

                             # type: int
                             # the stack counter at which the stackstring existed.
                             # aka, the top of the stack frame
                             "sp",

                             # type: int
                             # the initial stack counter at the start of the function.
                             # aka, the bottom of the stack frame
                             "init_sp",

                             # type: int
                             # the offset into the stack frame at which the stackstring existed.
                             "offset",

                             # type: int
                             # the offset from the function frame at which the stackstring existed.
                             "frame_offset",
                         ])


def getPointerSize(vw):
    if isinstance(vw.arch, envi.archs.amd64.Amd64Module):
        return 8
    elif isinstance(vw.arch, envi.archs.i386.i386Module):
        return 4
    else:
        raise NotImplementedError("unexpected architecture: %s" % (vw.arch.__class__.__name__))


def get_basic_block_ends(vw):
    """
    Return the set of VAs that are the last instructions of basic blocks.
    """
    index = set([])
    for funcva in vw.getFunctions():
        f = viv_utils.Function(vw, funcva)
        for bb in f.basic_blocks:
            if len(bb.instructions) == 0:
                continue
            index.add(bb.instructions[-1].va)
    return index


def extract_stackstrings(vw, selected_functions, min_length, no_filter=False):
    """
    Extracts the stackstrings from functions in the given workspace.

    :param vw: The vivisect workspace from which to extract stackstrings.
    :param selected_functions: list of selected functions
    :param min_length: minimum string length
    :param no_filter: do not filter deobfuscated stackstrings
    :rtype: Generator[StackString]
    """
    logger.debug('extracting stackstrings from %d functions', len(selected_functions))
    bb_ends = get_basic_block_ends(vw)
    for fva in selected_functions:
        logger.debug('extracting stackstrings from function: 0x%x', fva)
        seen = set([])
        for ctx in extract_call_contexts(vw, fva, bb_ends):
            logger.debug('extracting stackstrings at checkpoint: 0x%x stacksize: 0x%x', ctx.pc, ctx.init_sp - ctx.sp)
            for s in strings.extract_ascii_strings(ctx.stack_memory):
                if len(s.s) > MAX_STRING_LENGTH:
                    continue

                if no_filter:
                    decoded_string = s.s
                elif not is_fp_string(s.s):
                    decoded_string = strip_string(s.s)
                else:
                    continue

                if decoded_string not in seen and len(decoded_string) >= min_length:
                    frame_offset = (ctx.init_sp - ctx.sp) - s.offset - getPointerSize(vw)
                    yield(StackString(fva, decoded_string, ctx.pc, ctx.sp, ctx.init_sp, s.offset, frame_offset))
                    seen.add(decoded_string)
            for s in strings.extract_unicode_strings(ctx.stack_memory):
                if len(s.s) > MAX_STRING_LENGTH:
                    continue

                if no_filter:
                    decoded_string = s.s
                elif not is_fp_string(s.s):
                    decoded_string = strip_string(s.s)
                else:
                    continue

                if decoded_string not in seen and len(decoded_string) >= min_length:
                    frame_offset = (ctx.init_sp - ctx.sp) - s.offset - getPointerSize(vw)
                    yield(StackString(fva, decoded_string, ctx.pc, ctx.sp, ctx.init_sp, s.offset, frame_offset))
                    seen.add(decoded_string)

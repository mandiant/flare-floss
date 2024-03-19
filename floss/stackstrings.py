# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

from dataclasses import dataclass
from typing import List, Optional, Set

import envi.archs.amd64
import envi.archs.i386
import tqdm
import viv_utils
import viv_utils.emulator_drivers

import floss.strings
import floss.utils
from floss.render import Verbosity
from floss.results import StackString
from floss.utils import extract_strings, getPointerSize

logger = floss.logging_.getLogger(__name__)
MAX_STACK_SIZE = 0x10000

MIN_NUMBER_OF_MOVS = 5


@dataclass(frozen=True)
class CallContext:
    """Context for stackstring extraction.

    Attributes:
        pc: the current program counter
        sp: the current stack counter
        init_sp: the initial stack counter at start of function
        stack_memory: the active stack frame contents
        pre_ctx_strings: strings identified before this context
    """
    pc: int
    sp: int
    init_sp: int
    stack_memory: bytes
    pre_ctx_strings: Optional[Set[str]]


class StackstringContextMonitor(viv_utils.emulator_drivers.Monitor):
    """Observes emulation and extracts the active stack frame contents:

      - at each function call in a function, and
      - based on heuristics looking for mov instructions to a hardcoded buffer.
    """
    def __init__(self, init_sp, bb_ends):
        super().__init__()
        self.ctxs: List[CallContext] = []

        self._init_sp = init_sp
        # index of VAs of the last instruction of all basic blocks
        self._bb_ends = bb_ends
        # count of stack mov instructions in current basic block.
        # not guaranteed to grow greater than MIN_NUMBER_OF_MOVS.
        self._mov_count = 0

    def apicall(self, emu, api, argv):
        self.update_contexts(emu, emu.getProgramCounter())

    # TODO remove va arg? see below
    def update_contexts(self, emu, va) -> None:
        try:
            self.ctxs.append(self.get_call_context(emu, va))
        except ValueError as e:
            logger.debug("%s", e)

    # TODO get va here from emu?
    def get_call_context(
        self, emu, va, pre_ctx_strings: Optional[Set[str]] = None
    ) -> CallContext:
        """Collects context information related to a function call.

        Retrieves the stack boundaries, reads the stack memory, and creates a `CallContext` object to encapsulate the extracted information.  Optionally integrates pre-existing context strings.

        Args:
            self: Likely a reference to an analysis object or a context tracker.
            emu:  The Vivisect emulator object.
            va: The virtual address of the function call.
            pre_ctx_strings:  An optional set of strings for filtering or refining context generation.

        Returns:
            CallContext:  An object representing the context of the function call.

        Raises:
            ValueError: If the calculated stack size exceeds a maximum threshold (`MAX_STACK_SIZE`).
        """
        stack_top = emu.getStackCounter()
        stack_bottom = self._init_sp
        stack_size = stack_bottom - stack_top
        if stack_size > MAX_STACK_SIZE:
            raise ValueError("stack size too big: 0x%x" % stack_size)

        stack_buf = emu.readMemory(stack_top, stack_size)
        # would probably be an optimization here to strip garbage bytes, however, then we cannot easily track
        # the correct frame offset
        ctx = CallContext(va, stack_top, stack_bottom, stack_buf, pre_ctx_strings)
        return ctx

    # overrides emulator_drivers.Monitor
    def posthook(self, emu, op, endpc):
        self.check_mov_heuristics(emu, op, endpc)

    def check_mov_heuristics(self, emu, op, endpc):
        """Extract contexts at end of a basic block (bb) if bb contains enough movs to a harcoded buffer.

        Args:
            emu: The Vivisect emulator object.
            op: The current instruction.
            endpc: The virtual address of the end of the basic block.
        """
        # TODO check number of written bytes via writelog?
        # count movs, shortcut if this basic block has enough writes to trigger context extraction already
        if self._mov_count < MIN_NUMBER_OF_MOVS and self.is_stack_mov(op):
            self._mov_count += 1

        if endpc in self._bb_ends:
            if self._mov_count >= MIN_NUMBER_OF_MOVS:
                self.update_contexts(emu, op.va)
            # reset counter at end of basic block
            self._mov_count = 0

    def is_stack_mov(self, op):
        """Check if the given instruction is a move to a stack address.

        Args:
            op: The current instruction.

        Returns:
            bool: True if the instruction is a move to a stack address, False otherwise.
        """
        if not op.mnem.startswith("mov"):
            return False

        opnds = op.getOperands()
        if not opnds:
            # no operands, e.g. movsb, movsd
            # fail safe and count these regardless of where data is moved to.
            return True
        return isinstance(opnds[0], envi.archs.i386.disasm.i386SibOper) or isinstance(
            opnds[0], envi.archs.i386.disasm.i386RegMemOper
        )


def extract_call_contexts(vw, fva, bb_ends):
    """Extracts call contexts from a function.

    Args:
        vw: The vivisect workspace.
        fva: The function virtual address.
        bb_ends: The set of virtual addresses that are the last instructions of basic blocks.

    Returns:
        List[CallContext]: A list of call contexts.
    """
    emu = floss.utils.make_emulator(vw)
    monitor = StackstringContextMonitor(emu.getStackCounter(), bb_ends)
    driver = viv_utils.emulator_drivers.FullCoverageEmulatorDriver(emu, repmax=256)
    # note: we don't use ApiMonitor with our custom API hooks here
    driver.add_monitor(monitor)
    try:
        driver.run(fva)
    except Exception as e:
        logger.debug("error during emulation of function: %s", str(e))
    return monitor.ctxs


def get_basic_block_ends(vw):
    """Return the set of VAs that are the last instructions of basic blocks.

    Args:
        vw: The vivisect workspace.

    Returns:
        Set[int]: A set of virtual addresses.
    """
    index = set([])
    for funcva in vw.getFunctions():
        f = viv_utils.Function(vw, funcva)
        for bb in f.basic_blocks:
            if len(bb.instructions) == 0:
                continue
            index.add(bb.instructions[-1].va)
    return index


def extract_stackstrings(
    vw,
    selected_functions,
    min_length,
    verbosity=Verbosity.DEFAULT,
    disable_progress=False,
) -> List[StackString]:
    """Extracts the stackstrings from functions in the given workspace.

    Args:
        vw: The vivisect workspace.
        selected_functions: A list of virtual addresses of functions to analyze.
        min_length: The minimum length of a string to extract.
        verbosity: The verbosity level.
        disable_progress: A flag to disable the progress bar.

    Returns:
        List[StackString]: A list of stackstrings.
    """
    logger.info("extracting stackstrings from %d functions", len(selected_functions))

    stack_strings = list()
    bb_ends = get_basic_block_ends(vw)

    pb = floss.utils.get_progress_bar(
        selected_functions,
        disable_progress,
        desc="extracting stackstrings",
        unit=" functions",
    )
    with tqdm.contrib.logging.logging_redirect_tqdm(), floss.utils.redirecting_print_to_tqdm():
        for fva in pb:
            seen: Set[str] = floss.utils.get_referenced_strings(vw, fva)
            logger.debug("extracting stackstrings from function 0x%x", fva)
            ctxs = extract_call_contexts(vw, fva, bb_ends)
            for n, ctx in enumerate(ctxs, 1):
                logger.trace(
                    "extracting stackstrings at checkpoint: 0x%x stacksize: 0x%x",
                    ctx.pc,
                    ctx.init_sp - ctx.sp,
                )
                for s in extract_strings(ctx.stack_memory, min_length, seen):
                    frame_offset = (
                        (ctx.init_sp - ctx.sp) - s.offset - getPointerSize(vw)
                    )
                    ss = StackString(
                        function=fva,
                        string=s.string,
                        encoding=s.encoding,
                        program_counter=ctx.pc,
                        stack_pointer=ctx.sp,
                        original_stack_pointer=ctx.init_sp,
                        offset=s.offset,
                        frame_offset=frame_offset,
                    )
                    floss.results.log_result(ss, verbosity)
                    seen.add(s.string)
                    stack_strings.append(ss)
    return stack_strings

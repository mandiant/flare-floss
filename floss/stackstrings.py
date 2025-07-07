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


from typing import Set, List, Optional
from dataclasses import dataclass

import tqdm
import viv_utils
import envi.archs.i386
import envi.archs.amd64
import viv_utils.emulator_drivers

import floss.utils
import floss.strings
from floss.utils import getPointerSize, extract_strings
from floss.render import Verbosity
from floss.results import StackString

logger = floss.logging_.getLogger(__name__)
MAX_STACK_SIZE = 0x10000

MIN_NUMBER_OF_MOVS = 5


@dataclass(frozen=True)
class CallContext:
    """
    Context for stackstring extraction.

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
    """
    Observes emulation and extracts the active stack frame contents:
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
    def get_call_context(self, emu, va, pre_ctx_strings: Optional[Set[str]] = None) -> CallContext:
        """
        Returns a context with the bytes on the stack between the base pointer
         (specifically, stack pointer at function entry), and stack pointer.
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
        """
        Extract contexts at end of a basic block (bb) if bb contains enough movs to a harcoded buffer.
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


def extract_stackstrings(
    vw, selected_functions, min_length, verbosity=Verbosity.DEFAULT, disable_progress=False
) -> List[StackString]:
    """
    Extracts the stackstrings from functions in the given workspace.

    :param vw: The vivisect workspace from which to extract stackstrings.
    :param selected_functions: list of selected functions
    :param min_length: minimum string length
    :param verbosity: verbosity level
    :param disable_progress: do NOT show progress bar
    """
    logger.info("extracting stackstrings from %d functions", len(selected_functions))

    stack_strings = list()
    bb_ends = get_basic_block_ends(vw)

    pb = floss.utils.get_progress_bar(
        selected_functions, disable_progress, desc="extracting stackstrings", unit=" functions"
    )
    with tqdm.contrib.logging.logging_redirect_tqdm(), floss.utils.redirecting_print_to_tqdm():
        for fva in pb:
            seen: Set[str] = floss.utils.get_referenced_strings(vw, fva)
            logger.debug("extracting stackstrings from function 0x%x", fva)
            ctxs = extract_call_contexts(vw, fva, bb_ends)
            for n, ctx in enumerate(ctxs, 1):
                logger.trace(
                    "extracting stackstrings at checkpoint: 0x%x stacksize: 0x%x", ctx.pc, ctx.init_sp - ctx.sp
                )
                for s in extract_strings(ctx.stack_memory, min_length, seen):
                    frame_offset = (ctx.init_sp - ctx.sp) - s.offset - getPointerSize(vw)
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

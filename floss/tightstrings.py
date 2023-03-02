# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.

from typing import Set, List, Tuple, Iterator, Optional

import tqdm
import envi.exc
import viv_utils
import tqdm.contrib.logging
import viv_utils.emulator_drivers

import floss.utils
import floss.features.features
from floss.const import TS_MAX_INSN_COUNT, DS_MAX_ADDRESS_REVISITS_EMULATION
from floss.utils import extract_strings
from floss.render import Verbosity
from floss.results import TightString
from floss.stackstrings import CallContext, StackstringContextMonitor

logger = floss.logging_.getLogger(__name__)


class TightstringContextMonitor(StackstringContextMonitor):
    def __init__(self, sp, min_length):
        super().__init__(sp, [])
        self.min_length = min_length

    def apicall(self, emu, api, argv):
        # override base and do nothing here
        pass

    def get_pre_ctx_strings(self, emu) -> Set[str]:
        try:
            stack_buf = self.get_call_context(emu, emu.getProgramCounter()).stack_memory
            return set(map(lambda s: s.string, extract_strings(stack_buf, self.min_length)))
        except ValueError as e:
            logger.debug("%s", e)
        return set()

    def get_context(self, emu, va, pre_ctx_strings: Optional[Set[str]]) -> Iterator[CallContext]:
        try:
            yield self.get_call_context(emu, va, pre_ctx_strings)
        except ValueError as e:
            logger.debug("%s", e)


def extract_tightstring_contexts(vw, fva, min_length, tloops) -> Iterator[CallContext]:
    emu = floss.utils.make_emulator(vw)
    monitor = TightstringContextMonitor(emu.getStackCounter(), min_length)
    driver_single_path = viv_utils.emulator_drivers.SinglePathEmulatorDriver(emu, repmax=256)
    driver_single_path.add_monitor(monitor)
    driver = viv_utils.emulator_drivers.DebuggerEmulatorDriver(
        emu, max_hit=DS_MAX_ADDRESS_REVISITS_EMULATION, max_insn=TS_MAX_INSN_COUNT
    )

    for t in tloops:
        try:
            # find and emulate single path to start of tight loop
            driver_single_path.run_to_va(fva, t.startva)
        except Exception as e:
            logger.debug("error emulating path 0x%x to 0x%x: %s", fva, t.startva, e)
            continue

        # find existing (FP) stackstrings before tightstring loop executes
        pre_ctx_strings = monitor.get_pre_ctx_strings(emu)
        try:
            # emulate tight loop
            driver.run_to_va(t.endva)
        except viv_utils.emulator_drivers.BreakpointHit as e:
            logger.debug("hit breakpoint at 0x%x (reason: %s) in function 0x%x", e.va, e.reason, fva)
        except Exception as e:
            logger.debug("error emulating tight loop starting at 0x%x in function 0x%x: %s", t.startva, fva, e)
        yield from monitor.get_context(emu, t.startva, pre_ctx_strings)


def extract_tightstrings(
    vw, tightloop_functions, min_length, verbosity=Verbosity.DEFAULT, disable_progress=False
) -> List[TightString]:
    """
    Extracts tightstrings from functions that contain tight loops.
    Tightstrings are a special form of stackstrings. Their bytes are loaded on the stack and then modified in a
    tight loop. To extract tightstrings we use a mix between the string decoding and stackstring algorithms.

    To reduce computation time we only run this on previously identified functions that contain tight loops.

    :param vw: The vivisect workspace
    :param tightloop_functions: functions containing tight loops
    :param min_length: minimum string length
    :param verbosity: verbosity level
    :param disable_progress: do NOT show progress bar
    """
    logger.info("extracting tightstrings from %d functions...", len(tightloop_functions))

    tight_strings = list()
    pb = floss.utils.get_progress_bar(
        tightloop_functions.items(), disable_progress, desc="extracting tightstrings", unit=" functions"
    )
    with tqdm.contrib.logging.logging_redirect_tqdm(), floss.utils.redirecting_print_to_tqdm():
        for fva, tloops in pb:
            with floss.utils.timing(f"0x{fva:x}"):
                logger.debug("extracting tightstrings from function 0x%x", fva)
                if isinstance(pb, tqdm.tqdm):
                    pb.set_description(f"extracting tightstrings from function 0x{fva:x}")

                ctxs = extract_tightstring_contexts(vw, fva, min_length, tloops)
                for n, ctx in enumerate(ctxs, 1):
                    logger.trace(
                        "extracting tightstring at checkpoint: 0x%x stacksize: 0x%x", ctx.pc, ctx.init_sp - ctx.sp
                    )
                    logger.trace("pre_ctx strings: %s", ctx.pre_ctx_strings)
                    for s in extract_strings(ctx.stack_memory, min_length, exclude=ctx.pre_ctx_strings):
                        frame_offset = (ctx.init_sp - ctx.sp) - s.offset - floss.utils.getPointerSize(vw)
                        ts = TightString(fva, s.string, s.encoding, ctx.pc, ctx.sp, ctx.init_sp, s.offset, frame_offset)
                        floss.results.log_result(ts, verbosity)
                        tight_strings.append(ts)
    return tight_strings

# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import contextlib
from collections import namedtuple
from typing import List, Set

import envi
import viv_utils
import viv_utils.emulator_drivers
import vivisect

import floss.api_hooks
import floss.logging_
import floss.utils

FunctionContext = namedtuple(
    "FunctionContext", ["emu_snap", "return_address", "decoded_at_va"]
)


logger = floss.logging_.getLogger(__name__)


class CallMonitor(viv_utils.emulator_drivers.Monitor):
    """collect call arguments to a target function during emulation"""

    def __init__(self, call_site_va: int):
        super().__init__()
        self.call_site_va = call_site_va
        self.function_contexts: List[FunctionContext] = list()

    def prehook(self, emu, op, pc):
        """collect function contexts at call sites
        
        Args:
            emu: The emulator.
            op: The operation.
            pc: The program counter.
        """
        logger.trace("%s: %s", hex(pc), op)
        if pc == self.call_site_va:
            # strictly calls here, return address should always be next instruction
            return_address = pc + len(op)
            self.function_contexts.append(
                FunctionContext(emu.getEmuSnap(), return_address, pc)
            )

    def get_contexts(self) -> List[FunctionContext]:
        """return the collected function contexts"""
        return self.function_contexts


@contextlib.contextmanager
def installed_monitor(driver, monitor):
    """install a monitor on an emulator driver for the duration of a context

    Args:
        driver:
        monitor:
    """
    try:
        driver.add_monitor(monitor)
        yield
    finally:
        driver.remove_monitor(monitor)


def extract_decoding_contexts(
    vw: vivisect.VivWorkspace,
    decoder_fva: int,
    index: viv_utils.InstructionFunctionIndex,
) -> List[FunctionContext]:
    """Extract the CPU and memory contexts of all calls to the given function.
    Under the hood, we brute-force emulate all code paths to extract the
     state of the stack, registers, and global memory at each call to
     the given address.

    Args:
        vw: vivisect.VivWorkspace:
        decoder_fva: int:
        index: viv_utils.InstructionFunctionIndex:

    Returns:
        List[FunctionContext]:
    """
    logger.trace("Getting function context for function at 0x%08x...", decoder_fva)

    emu = floss.utils.make_emulator(vw)
    driver = viv_utils.emulator_drivers.FullCoverageEmulatorDriver(emu, repmax=1024)

    contexts = list()
    for caller_va in get_caller_vas(vw, decoder_fva):
        contexts.extend(get_contexts_via_monitor(driver, caller_va, decoder_fva, index))

    logger.trace(
        "Got %d function contexts for function at 0x%08x.", len(contexts), decoder_fva
    )
    return contexts


def get_caller_vas(vw, fva) -> Set[int]:
    """Finds the virtual addresses of functions that call a specified function.

     Analyzes a workspace to identify instructions that call the  function at the provided virtual address (`fva`).  Handles filtering of non-call instructions and recursive calls.

     Args:
         vw:  A Vivisect workspace object.
         fva: The virtual address of the function being analyzed.

     Returns:
         Set[int]: A set of virtual addresses representing the callers of the function.
    """
    caller_vas = set()
    for caller_va in vw.getCallers(fva):
        if not is_call(vw, caller_va):
            continue
        if caller_va == fva:
            # ignore recursive functions
            continue
        caller_vas.add(caller_va)
    return caller_vas


def is_call(vw: vivisect.VivWorkspace, va: int) -> bool:
    """Determines if an instruction at a  virtual address is a call instruction.

    Attempts to parse an instruction and checks if the instruction flags indicate a call type.

    Args:
        vw: A Vivisect workspace object.
        va: The virtual address of the instruction.

    Returns:
        bool: True if the instruction is a call, False otherwise.
    """
    try:
        op = vw.parseOpcode(va)
    except (envi.UnsupportedInstruction, envi.InvalidInstruction) as e:
        logger.trace(
            "  not a call instruction: failed to decode instruction: %s", e.message
        )
        return False

    if op.iflags & envi.IF_CALL:
        return True

    logger.trace("  not a call instruction: %s", op)
    return False


def get_contexts_via_monitor(
    driver, caller_va, decoder_fva: int, index: viv_utils.InstructionFunctionIndex
):
    """Collects function call context information via dynamic monitoring.

    This function sets up a monitor to intercept calls to a target function (`decoder_fva`) made from within a caller function (`caller_va`). It achieves this by emulating the caller function and collecting data about the arguments passed to the target function.

    Args:
        driver:  An object used to control the emulator or analysis environment.
        caller_va: The virtual address of the caller function.
        decoder_fva:  The virtual address of the target function to be monitored.
        index: A VivUtils InstructionFunctionIndex (likely maps virtual addresses to function boundaries).

    Returns:
        List[FunctionContext]: A list of FunctionContext objects representing intercepted call contexts.
    """
    try:
        caller_fva = index[caller_va]
    except KeyError:
        logger.trace("  unknown function")
        return []

    logger.trace("emulating: %s, watching %s" % (hex(caller_fva), hex(decoder_fva)))
    monitor = CallMonitor(caller_va)
    with installed_monitor(driver, monitor):
        with floss.api_hooks.defaultHooks(driver):
            try:
                driver.run(caller_fva)
            except Exception as e:
                logger.debug("error during emulation of function: %s", str(e))
    contexts = monitor.get_contexts()

    logger.trace("   results:")
    for _ in contexts:
        logger.trace("    <context>")

    return contexts

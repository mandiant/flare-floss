# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

from typing import List, Tuple
from dataclasses import dataclass

import viv_utils
import envi.memory
import viv_utils.emulator_drivers
from envi import Emulator

import floss.logging_

from . import api_hooks
from .const import DS_MAX_ADDRESS_REVISITS_EMULATION

logger = floss.logging_.getLogger(__name__)
MAX_MAPS_SIZE = 1024 * 1024 * 100  # 100MB max memory allocated in an emulator instance


def is_import(emu, va):
    """
    Return True if the given VA is that of an imported function.
    """
    # TODO: also check location type
    t = emu.getVivTaint(va)
    if t is None:
        return False
    return t[1] == "import"


# type aliases for envi.memory map
MemoryMapDescriptor = Tuple[
    # va
    int,
    # size
    int,
    # perms
    int,
    # name
    str,
]

# type aliases for envi.memory map
MemoryMap = Tuple[
    # start
    int,
    # end
    int,
    # descriptor
    MemoryMapDescriptor,
    # content
    bytes,
]

# type aliases for envi.memory map
Memory = List[MemoryMap]


@dataclass
class Snapshot:
    """
    A snapshot of the state of the CPU and memory.

    Attributes:
        memory: a snapshot of the memory contents
        sp: the stack counter
        pc: the instruction pointer
    """

    memory: Memory
    sp: int
    pc: int


def get_map_size(emu):
    size = 0
    for mapva, mapsize, mperm, mfname in emu.getMemoryMaps():
        mapsize += size
    return mapsize


class MapsTooLargeError(Exception):
    pass


def make_snapshot(emu: Emulator) -> Snapshot:
    """
    Create a snapshot of the current CPU and memory.
    """
    if get_map_size(emu) > MAX_MAPS_SIZE:
        logger.debug("emulator mapped too much memory: 0x%x", get_map_size(emu))
        raise MapsTooLargeError()
    return Snapshot(emu.getMemorySnap(), emu.getStackCounter(), emu.getProgramCounter())


@dataclass
class Delta:
    """
    a pair of snapshots from before and after an operation.
    facilitates diffing the state of an emulator.
    """

    pre: Snapshot
    post: Snapshot


class DeltaCollectorHook(viv_utils.emulator_drivers.Hook):
    """
    hook that collects Deltas at each imported API call.
    """

    def __init__(self, pre_snap: Snapshot):
        super().__init__()
        self._pre_snap = pre_snap
        self.deltas: List[Delta] = []

    def __call__(self, emu, api, argv):
        if is_import(emu, emu.getProgramCounter()):
            # TODO add apis to ignore here, e.g.
            #  "kernel32.GetSystemTime", "ntdll.RtlFreeHeap", "ntdll.RtlAllocateHeap",
            #  callname = driver._emu.getCallApi(driver._emu.getProgramCounter())[3]
            try:
                # TODO optimize - may leverage writelog
                #  reduce duplicate deltas
                #  reduce redundant (unchanged) data in each delta
                self.deltas.append(Delta(self._pre_snap, make_snapshot(emu)))
            except MapsTooLargeError:
                _, _, _, name, _ = api
                logger.debug("despite call to import %s, maps too large, not extracting strings", name)
                pass


def emulate_function(
    emu: Emulator, function_index, fva: int, return_address: int, max_instruction_count: int
) -> List[Delta]:
    """
    Emulate a function and collect snapshots at each interesting place.
    These interesting places include calls to imported API functions
     and the final state of the emulator.
    Emulation continues until the return address is hit, or
     the given max_instruction_count is hit.
    Some library functions are shimmed, such as memory allocation routines.
    This helps "normal" routines emulate correct using standard library function.
    These include:
      - GetProcessHeap
      - RtlAllocateHeap
      - AllocateHeap
      - malloc

    :type function_index: viv_utils.FunctionIndex
    :param fva: The start address of the function to emulate.
    :param return_address: The expected return address of the function.
     Emulation stops here.
    :param max_instruction_count: The max number of instructions to emulate.
     This helps avoid unexpected infinite loops.
    """
    try:
        pre_snap = make_snapshot(emu)
    except MapsTooLargeError:
        logger.warn("initial snapshot mapped too much memory, can't extract strings")
        return []

    delta_collector = DeltaCollectorHook(pre_snap)

    try:
        logger.debug("Emulating function at 0x%08x", fva)
        driver = viv_utils.emulator_drivers.DebuggerEmulatorDriver(
            emu, repmax=256, max_hit=DS_MAX_ADDRESS_REVISITS_EMULATION, max_insn=max_instruction_count
        )
        monitor = api_hooks.ApiMonitor(function_index)
        driver.add_monitor(monitor)
        driver.add_hook(delta_collector)

        with api_hooks.defaultHooks(driver):
            driver.run_to_va(return_address)

    except viv_utils.emulator_drivers.BreakpointHit as e:
        # TODO track/shortcut instances of this
        if e.reason == "max_insn":
            logger.debug("Halting as emulation has escaped!")
    except envi.InvalidInstruction:
        logger.debug("vivisect encountered an invalid instruction. will continue processing.", exc_info=True)
    except envi.UnsupportedInstruction:
        logger.debug("vivisect encountered an unsupported instruction. will continue processing.", exc_info=True)
    except envi.BreakpointHit:
        logger.debug(
            "vivisect encountered an unexpected emulation breakpoint. will continue processing.", exc_info=True
        )
    except viv_utils.emulator_drivers.StopEmulation:
        pass
    except Exception:
        # TODO we cheat here a bit and skip over various errors
        logger.debug("vivisect encountered an unexpected exception. will continue processing.", exc_info=True)
    logger.debug("Ended emulation at 0x%08x", emu.getProgramCounter())

    deltas = delta_collector.deltas

    try:
        deltas.append(Delta(pre_snap, make_snapshot(emu)))
    except MapsTooLargeError:
        logger.debug("failed to create final snapshot, emulator mapped too much memory, skipping")
        pass

    return deltas

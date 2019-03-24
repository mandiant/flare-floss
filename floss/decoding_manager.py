# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import logging
from collections import namedtuple

import viv_utils
import viv_utils.emulator_drivers
import envi.memory
from enum import Enum

import api_hooks


floss_logger = logging.getLogger("floss")
MAX_MAPS_SIZE = 1024 * 1024 * 100  # 100MB max memory allocated in an emulator instance

# A DecodedString stores the decoded string and meta data about it:
# va: va of string in memory, s: decoded string, decoded_at_va: VA where decoding routine is called,
# fva: function VA of decoding routine, characteristics: meta information dictionary for the
# identified memory location
DecodedString = namedtuple("DecodedString", ["va", "s", "decoded_at_va", "fva", "characteristics"])


class LocationType(Enum):
    STACK = 1
    GLOBAL = 2
    HEAP = 3


def is_import(emu, va):
    """
    Return True if the given VA is that of an imported function.
    """
    # TODO: also check location type
    t = emu.getVivTaint(va)
    if t is None:
        return False
    return t[1] == "import"


# A snapshot represents the current state of the CPU and memory
Snapshot = namedtuple("Snapshot",
                      ["memory",  # The memory snapshot, type: envi.MemorySnapshot
                       "sp",  # The current stack counter, type: int
                       "pc",  # The current instruction pointer, type: int
                       ])


def get_map_size(emu):
    size = 0
    for mapva, mapsize, mperm, mfname in emu.getMemoryMaps():
        mapsize += size
    return size


class MapsTooLargeError(Exception):
    pass


def make_snapshot(emu):
    """
    Create a snapshot of the current CPU and memory.

    :rtype: Snapshot
    """
    if get_map_size(emu) > MAX_MAPS_SIZE:
        floss_logger.debug('emulator mapped too much memory: 0x%x', get_map_size(emu))
        raise MapsTooLargeError()
    return Snapshot(emu.getMemorySnap(), emu.getStackCounter(), emu.getProgramCounter())


# A Delta represents the pair of snapshots from before and
#  after an operation. It facilitates diffing the state of
#  an emalutor.
Delta = namedtuple("Delta",
                   ["pre_snap",  # type: Snapshot
                    "post_snap",  # type: Snapshot
                    ])


class DeltaCollectorHook(viv_utils.emulator_drivers.Hook):
    """
    hook that collects Deltas at each imported API call.
    """

    def __init__(self, pre_snap):
        super(DeltaCollectorHook, self).__init__()

        self._pre_snap = pre_snap
        # this is a public field
        self.deltas = []

    def hook(self, callname, driver, callconv, api, argv):
        if is_import(driver._emu, driver._emu.getProgramCounter()):
            try:
                self.deltas.append(Delta(self._pre_snap, make_snapshot(driver._emu)))
            except MapsTooLargeError:
                floss_logger.debug('despite call to import %s, maps too large, not extracting strings', callname)
                pass


class DebugMonitor(viv_utils.emulator_drivers.Monitor):
    """
    Emulator monitor that is useful during debugging.
    """
    def __init__(self, *args, **kwargs):
        super(DebugMonitor, self).__init__(*args, **kwargs)

    def prehook(self, emu, op, startpc):
        self._logger.debug("prehook: %s: %s", hex(startpc), op)


def emulate_function(emu, function_index, fva, return_address, max_instruction_count):
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

    :type emu: envi.Emulator
    :type function_index: viv_utils.FunctionIndex
    :type fva: int
    :param fva: The start address of the function to emulate.
    :int return_address: int
    :param return_address: The expected return address of the function.
     Emulation stops here.
    :type max_instruction_count: int
    :param max_instruction_count: The max number of instructions to emulate.
     This helps avoid unexpected infinite loops.
    :rtype: Sequence[Delta]
    """
    try:
        pre_snap = make_snapshot(emu)
    except MapsTooLargeError:
        floss_logger.warn('initial snapshot mapped too much memory, can\'t extract strings')
        return []

    delta_collector = DeltaCollectorHook(pre_snap)

    try:
        floss_logger.debug("Emulating function at 0x%08X", fva)
        driver = viv_utils.emulator_drivers.DebuggerEmulatorDriver(emu)
        monitor = api_hooks.ApiMonitor(emu.vw, function_index)
        dbg = DebugMonitor(emu.vw)
        driver.add_monitor(monitor)
        driver.add_hook(delta_collector)

        with api_hooks.defaultHooks(driver):
            driver.runToVa(return_address, max_instruction_count)

    except viv_utils.emulator_drivers.InstructionRangeExceededError:
        floss_logger.debug("Halting as emulation has escaped!")
    except envi.InvalidInstruction:
        floss_logger.debug("vivisect encountered an invalid instruction. will continue processing.",
                           exc_info=True)
    except envi.UnsupportedInstruction:
        floss_logger.debug("vivisect encountered an unsupported instruction. will continue processing.",
                           exc_info=True)
    except envi.BreakpointHit:
        floss_logger.debug("vivisect encountered an unexpected emulation breakpoint. will continue processing.",
                           exc_info=True)
    except viv_utils.emulator_drivers.StopEmulation:
        pass
    except Exception:
        floss_logger.debug("vivisect encountered an unexpected exception. will continue processing.",
                           exc_info=True)
    floss_logger.debug("Ended emulation at 0x%08X", emu.getProgramCounter())

    deltas = delta_collector.deltas

    try:
        deltas.append(Delta(pre_snap, make_snapshot(emu)))
    except MapsTooLargeError:
        floss_logger.debug('failed to create final snapshot, emulator mapped too much memory, skipping')
        pass

    return deltas

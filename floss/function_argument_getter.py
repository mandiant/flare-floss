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


import contextlib
from typing import Set, List
from collections import namedtuple

import envi
import vivisect
import viv_utils
import viv_utils.emulator_drivers

import floss.utils
import floss.logging_
import floss.api_hooks

FunctionContext = namedtuple("FunctionContext", ["emu_snap", "return_address", "decoded_at_va"])


logger = floss.logging_.getLogger(__name__)


class CallMonitor(viv_utils.emulator_drivers.Monitor):
    """collect call arguments to a target function during emulation"""

    def __init__(self, call_site_va: int):
        super().__init__()
        self.call_site_va = call_site_va
        self.function_contexts: List[FunctionContext] = list()

    def prehook(self, emu, op, pc):
        logger.trace("%s: %s", hex(pc), op)
        if pc == self.call_site_va:
            # strictly calls here, return address should always be next instruction
            return_address = pc + len(op)
            self.function_contexts.append(FunctionContext(emu.getEmuSnap(), return_address, pc))

    def get_contexts(self) -> List[FunctionContext]:
        return self.function_contexts


@contextlib.contextmanager
def installed_monitor(driver, monitor):
    try:
        driver.add_monitor(monitor)
        yield
    finally:
        driver.remove_monitor(monitor)


def extract_decoding_contexts(
    vw: vivisect.VivWorkspace, decoder_fva: int, index: viv_utils.InstructionFunctionIndex
) -> List[FunctionContext]:
    """
    Extract the CPU and memory contexts of all calls to the given function.
    Under the hood, we brute-force emulate all code paths to extract the
     state of the stack, registers, and global memory at each call to
     the given address.
    """
    logger.trace("Getting function context for function at 0x%08x...", decoder_fva)

    emu = floss.utils.make_emulator(vw)
    driver = viv_utils.emulator_drivers.FullCoverageEmulatorDriver(emu, repmax=1024)

    contexts = list()
    for caller_va in get_caller_vas(vw, decoder_fva):
        contexts.extend(get_contexts_via_monitor(driver, caller_va, decoder_fva, index))

    logger.trace("Got %d function contexts for function at 0x%08x.", len(contexts), decoder_fva)
    return contexts


def get_caller_vas(vw, fva) -> Set[int]:
    """
    return all unique VAs where function is called from
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
    try:
        op = vw.parseOpcode(va)
    except (envi.UnsupportedInstruction, envi.InvalidInstruction) as e:
        logger.trace("  not a call instruction: failed to decode instruction: %s", e.message)
        return False

    if op.iflags & envi.IF_CALL:
        return True

    logger.trace("  not a call instruction: %s", op)
    return False


def get_contexts_via_monitor(driver, caller_va, decoder_fva: int, index: viv_utils.InstructionFunctionIndex):
    """
    run the given function while collecting arguments to a target function
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

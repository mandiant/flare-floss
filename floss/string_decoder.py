# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

from typing import Set, List
from dataclasses import dataclass

import tqdm
import viv_utils
from vivisect import VivWorkspace

import floss.utils
import floss.results
import floss.strings
import floss.logging_
import floss.decoding_manager
from floss.const import (
    DS_MAX_INSN_COUNT,
    DS_FUNCTION_CALLS_RARE,
    DS_FUNCTION_CALLS_OFTEN,
    DS_FUNCTION_MIN_DECODED_STRINGS,
    DS_FUNCTION_SHORTCUT_THRESHOLD_VERY_OFTEN,
)
from floss.utils import is_all_zeros
from floss.render import Verbosity
from floss.results import AddressType, DecodedString
from floss.decoding_manager import Delta
from floss.function_argument_getter import extract_decoding_contexts

logger = floss.logging_.getLogger(__name__)


def memdiff_search(bytes1, bytes2):
    """
    Use binary searching to find the offset of the first difference
     between two strings.

    :param bytes1: The original sequence of bytes
    :param bytes2: A sequence of bytes to compare with bytes1
    :type bytes1: str
    :type bytes2: str
    :rtype: int offset of the first location a and b differ, None if strings match
    """

    # Prevent infinite recursion on inputs with length of one
    half = (len(bytes1) // 2) or 1

    # Compare first half of the string
    if bytes1[:half] != bytes2[:half]:
        # Have we found the first diff?
        if bytes1[0] != bytes2[0]:
            return 0

        return memdiff_search(bytes1[:half], bytes2[:half])

    # Compare second half of the string
    if bytes1[half:] != bytes2[half:]:
        return memdiff_search(bytes1[half:], bytes2[half:]) + half


def memdiff(bytes1, bytes2):
    """
    Find all differences between two input strings.

    :param bytes1: The original sequence of bytes
    :param bytes2: The sequence of bytes to compare to
    :type bytes1: str
    :type bytes2: str
    :rtype: list of (offset, length) tuples indicating locations bytes1 and
      bytes2 differ
    """
    # Shortcut matching inputs
    if bytes1 == bytes2:
        return []

    # Verify lengths match
    size = len(bytes1)
    if size != len(bytes2):
        raise Exception("memdiff *requires* same size bytes")

    diffs = []

    # Get position of first diff
    diff_start = memdiff_search(bytes1, bytes2)
    diff_offset = None
    for offset, byte in enumerate(bytes1[diff_start:]):
        if bytes2[diff_start + offset] != byte:
            # Store offset if we're not tracking a diff
            if diff_offset is None:
                diff_offset = offset
            continue

        # Bytes match, check if this is the end of a diff
        if diff_offset is not None:
            diffs.append((diff_offset + diff_start, offset - diff_offset))
            diff_offset = None

            # Shortcut if remaining data is equal
            if bytes1[diff_start + offset :] == bytes2[diff_start + offset :]:
                break

    # Bytes are different until the end of input, handle leftovers
    if diff_offset is not None:
        diffs.append((diff_offset + diff_start, offset + 1 - diff_offset))

    return diffs


def should_shortcut(fva: int, n: int, n_calls: int, found_strings: int) -> bool:
    if n_calls < DS_FUNCTION_CALLS_RARE:
        # don't shortcut
        return False
    elif n_calls < DS_FUNCTION_CALLS_OFTEN:
        shortcut_threshold = n_calls // 2
    else:
        # a lot
        shortcut_threshold = DS_FUNCTION_SHORTCUT_THRESHOLD_VERY_OFTEN

    if n >= shortcut_threshold and found_strings <= DS_FUNCTION_MIN_DECODED_STRINGS:
        logger.debug(
            "only %d results after emulating %d contexts, shortcutting emulation of 0x%x", found_strings, n, fva
        )
        return True
    return False


def decode_strings(
    vw: VivWorkspace,
    functions: List[int],
    min_length: int,
    max_insn_count: int = DS_MAX_INSN_COUNT,
    verbosity: int = Verbosity.DEFAULT,
    disable_progress: bool = False,
) -> List[DecodedString]:
    """
    FLOSS string decoding algorithm

    arguments:
        vw: the workspace
        functions: addresses of the candidate decoding routines
        min_length: minimum string length
        max_insn_count: max number of instructions to emulate per function
        verbosity: verbosity level
        disable_progress: no progress bar
    """
    logger.info("decoding strings")

    decoded_strings = list()
    function_index = viv_utils.InstructionFunctionIndex(vw)

    pb = floss.utils.get_progress_bar(functions, disable_progress, desc="decoding strings", unit=" functions")
    with tqdm.contrib.logging.logging_redirect_tqdm(), floss.utils.redirecting_print_to_tqdm():
        for fva in pb:
            seen: Set[str] = floss.utils.get_referenced_strings(vw, fva)
            ctxs = extract_decoding_contexts(vw, fva, function_index)
            n_calls = len(ctxs)
            for n, ctx in enumerate(ctxs, 1):
                if isinstance(pb, tqdm.tqdm):
                    pb.set_description(f"emulating function 0x{fva:x} (call {n}/{n_calls})")

                if should_shortcut(fva, n, n_calls, len(seen)):
                    break

                for delta in emulate_decoding_routine(vw, function_index, fva, ctx, max_insn_count):
                    for delta_bytes in extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                        for s in floss.utils.extract_strings(delta_bytes.bytes, min_length, seen):
                            ds = DecodedString(
                                delta_bytes.address + s.offset,
                                delta_bytes.address_type,
                                s.string,
                                s.encoding,
                                delta_bytes.decoded_at,
                                delta_bytes.decoding_routine,
                            )
                            floss.results.log_result(ds, verbosity)
                            seen.add(ds.string)
                            decoded_strings.append(ds)
        return decoded_strings


def emulate_decoding_routine(vw, function_index, function: int, context, max_instruction_count: int) -> List[Delta]:
    """
    Emulate a function with a given context and extract the CPU and
     memory contexts at interesting points during emulation.
    These "interesting points" include calls to other functions and
     the final state.
    Emulation terminates if the CPU executes an unexpected region of
     memory, or the function returns.
    Implementation note: currently limits emulation to 20,000 instructions.
     This prevents unexpected infinite loops.
     This number is taken from emulating the decoding of "Hello world" using RC4.


    :param vw: The vivisect workspace in which the function is defined.
    :type function_index: viv_utils.FunctionIndex
    :param function: The address of the function to emulate.
    :type context: funtion_argument_getter.FunctionContext
    :param context: The initial state of the CPU and memory
      prior to the function being called.
    :param max_instruction_count: The maximum number of instructions to emulate per function.
    :rtype: Sequence[decoding_manager.Delta]
    """
    emu = floss.utils.make_emulator(vw)
    emu.setEmuSnap(context.emu_snap)
    logger.trace(
        "Emulating function at 0x%08x called at 0x%08x, return address: 0x%08x",
        function,
        context.decoded_at_va,
        context.return_address,
    )
    deltas = floss.decoding_manager.emulate_function(
        emu, function_index, function, context.return_address, max_instruction_count
    )
    return deltas


@dataclass
class DeltaBytes:
    address: int
    address_type: AddressType
    bytes: bytes
    decoded_at: int
    decoding_routine: int


def extract_delta_bytes(delta: Delta, decoded_at_va: int, source_fva: int = 0x0) -> List[DeltaBytes]:
    """
    Extract the sequence of byte sequences that differ from before
     and after snapshots.

    :param delta: The before and after snapshots of memory to diff.
    :param decoded_at_va: The virtual address of a specific call to
    the decoding function candidate that resulted in a memory diff
    :param source_fva: function VA of the decoding routine candidate
    """
    delta_bytes = []

    memory_snap_before = delta.pre.memory
    memory_snap_after = delta.post.memory
    sp = delta.post.sp

    # maps from region start to section tuple
    mem_before = {m[0]: m for m in memory_snap_before}
    mem_after = {m[0]: m for m in memory_snap_after}

    stack_start = 0x0
    stack_end = 0x0
    for m in memory_snap_after:
        if m[0] <= sp < m[1]:
            stack_start, stack_end = m[0], m[1]

    # iterate memory from after the decoding, since if somethings been allocated,
    # we want to know. don't care if things have been deallocated.
    for section_after_start, section_after in mem_after.items():
        (_, _, (_, after_len, _, _), bytes_after) = section_after
        if section_after_start not in mem_before:
            location_type = AddressType.HEAP
            if not is_all_zeros(bytes_after):
                delta_bytes.append(
                    DeltaBytes(section_after_start, location_type, bytes_after, decoded_at_va, source_fva)
                )
            continue

        section_before = mem_before[section_after_start]
        (_, _, (_, before_len, _, _), bytes_before) = section_before

        if after_len < before_len:
            bytes_before = bytes_before[:after_len]

        elif after_len > before_len:
            bytes_before += b"\x00" * (after_len - before_len)

        memory_diff = memdiff(bytes_before, bytes_after)
        for offset, length in memory_diff:
            address = section_after_start + offset

            diff_bytes = bytes_after[offset : offset + length]
            if not (stack_start <= address < stack_end):
                location_type = AddressType.GLOBAL
            else:
                location_type = AddressType.STACK

            if not is_all_zeros(diff_bytes):
                delta_bytes.append(DeltaBytes(address, location_type, diff_bytes, decoded_at_va, source_fva))

    return delta_bytes

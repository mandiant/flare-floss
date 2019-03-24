# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import re
import logging

import strings
import decoding_manager
from utils import makeEmulator, is_fp_string, strip_string, MAX_STRING_LENGTH
from function_argument_getter import get_function_contexts
from decoding_manager import DecodedString, LocationType


floss_logger = logging.getLogger("floss")


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
    half = (len(bytes1) / 2) or 1

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
        raise Exception('memdiff *requires* same size bytes')

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
            if bytes1[diff_start + offset:] == bytes2[diff_start + offset:]:
                break

    # Bytes are different until the end of input, handle leftovers
    if diff_offset is not None:
        diffs.append((diff_offset + diff_start, offset + 1 - diff_offset))

    return diffs


def extract_decoding_contexts(vw, function, max_hits):
    """
    Extract the CPU and memory contexts of all calls to the given function.
    Under the hood, we brute-force emulate all code paths to extract the
     state of the stack, registers, and global memory at each call to
     the given address.

    :param vw: The vivisect workspace in which the function is defined.
    :type function: int
    :param function: The address of the function whose contexts we'll find.
    :param max_hits: The maximum number of hits per address
    :rtype: Sequence[function_argument_getter.FunctionContext]
    """
    return get_function_contexts(vw, function, max_hits)


def emulate_decoding_routine(vw, function_index, function, context, max_instruction_count):
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
    :type function: int
    :param function: The address of the function to emulate.
    :type context: funtion_argument_getter.FunctionContext
    :param context: The initial state of the CPU and memory
      prior to the function being called.
    :type max_instruction_count: int
    :param max_instruction_count: The maximum number of instructions to emulate per function.
    :rtype: Sequence[decoding_manager.Delta]
    """
    emu = makeEmulator(vw)
    emu.setEmuSnap(context.emu_snap)
    floss_logger.debug("Emulating function at 0x%08X called at 0x%08X, return address: 0x%08X",
                       function, context.decoded_at_va, context.return_address)
    deltas = decoding_manager.emulate_function(
        emu,
        function_index,
        function,
        context.return_address,
        max_instruction_count)
    return deltas


def extract_delta_bytes(delta, decoded_at_va, source_fva=0x0):
    """
    Extract the sequence of byte sequences that differ from before
     and after snapshots.

    :type delta: decoding_manager.Delta
    :param delta: The before and after snapshots of memory to diff.
    :type decoded_at_va: int
    :param decoded_at_va: The virtual address of a specific call to
    the decoding function candidate that resulted in a memory diff
    :type source_fva: int
    :param source_fva: function VA of the decoding routine candidate
    :rtype: Sequence[DecodedString]
    """
    delta_bytes = []

    memory_snap_before = delta.pre_snap.memory
    memory_snap_after = delta.post_snap.memory
    sp = delta.post_snap.sp

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
            characteristics = {"location_type": LocationType.HEAP}
            delta_bytes.append(DecodedString(section_after_start, bytes_after,
                                             decoded_at_va, source_fva, characteristics))
            continue

        section_before = mem_before[section_after_start]
        (_, _, (_, before_len, _, _), bytes_before) = section_before

        if after_len < before_len:
            bytes_before = bytes_before[:after_len]

        elif after_len > before_len:
            bytes_before += "\x00" * (after_len - before_len)

        memory_diff = memdiff(bytes_before, bytes_after)
        for offset, length in memory_diff:
            address = section_after_start + offset

            diff_bytes = bytes_after[offset:offset + length]
            if not (stack_start <= address < stack_end):
                # address is in global memory
                characteristics = {"location_type": LocationType.GLOBAL}
            else:
                characteristics = {"location_type": LocationType.STACK}
            delta_bytes.append(DecodedString(address, diff_bytes, decoded_at_va,
                                             source_fva, characteristics))
    return delta_bytes


def extract_strings(b, min_length, no_filter):
    """
    Extract the ASCII and UTF-16 strings from a bytestring.

    :type b: decoding_manager.DecodedString
    :param b: The data from which to extract the strings. Note its a
      DecodedString instance that tracks extra metadata beyond the
      bytestring contents.
    :param min_length: minimum string length
    :param no_filter: do not filter decoded strings
    :rtype: Sequence[decoding_manager.DecodedString]
    """
    ret = []
    for s in strings.extract_ascii_strings(b.s):
        if len(s.s) > MAX_STRING_LENGTH:
            continue

        if no_filter:
            decoded_string = s.s
        elif not is_fp_string(s.s):
            decoded_string = strip_string(s.s)
        else:
            continue

        if len(decoded_string) >= min_length:
            ret.append(DecodedString(b.va + s.offset, decoded_string, b.decoded_at_va, b.fva, b.characteristics))
    for s in strings.extract_unicode_strings(b.s):
        if len(s.s) > MAX_STRING_LENGTH:
            continue

        if no_filter:
            decoded_string = s.s
        elif not is_fp_string(s.s):
            decoded_string = strip_string(s.s)
        else:
            continue

        if len(decoded_string) >= min_length:
            ret.append(DecodedString(b.va + s.offset, decoded_string, b.decoded_at_va, b.fva, b.characteristics))
    return ret

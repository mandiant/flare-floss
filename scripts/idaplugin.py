# TODO currently not maintained or tested
# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

#!/usr/bin/env python3
"""
Run FLOSS to automatically extract obfuscated strings and apply them to the
currently loaded module in IDA Pro.

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
"""
import time
import logging

import idc
import viv_utils

import floss
import floss.main
import floss.identify
import floss.stackstrings
import floss.string_decoder
import floss.decoding_manager
from floss.results import AddressType

logger = logging.getLogger("floss.idaplugin")


MIN_LENGTH = 4


def append_comment(ea, s, repeatable=False):
    """
    add the given string as a (possibly repeating) comment to the given address.
    does not add the comment if it already exists.
    adds the comment on its own line.

    Args:
      ea (int): the address at which to add the comment.
      s (str): the comment text.
      repeatable (bool): if True, set a repeatable comment.

    """
    # see: http://blogs.norman.com/2011/security-research/improving-ida-analysis-of-x64-exception-handling

    if repeatable:
        string = idc.get_cmt(ea, 1)
    else:
        string = idc.get_cmt(ea, 0)

    if not string:
        string = s  # no existing comment
    else:
        if s in string:  # ignore duplicates
            return
        string = string + "\\n" + s

    if repeatable:
        idc.set_cmt(ea, string, 1)
    else:
        idc.set_cmt(ea, string, 0)


def append_lvar_comment(fva, frame_offset, s, repeatable=False):
    """
    add the given string as a (possibly repeatable) stack variable comment to the given function.
    does not add the comment if it already exists.
    adds the comment on its own line.

    Args:
      fva (int): the address of the function with the stack variable.
      frame_offset (int): the offset into the stack frame at which the variable is found.
      s (str): the comment text.
      repeatable (bool): if True, set a repeatable comment.

    """

    stack = idc.get_func_attr(fva, idc.FUNCATTR_FRAME)
    if not stack:
        raise RuntimeError("failed to find stack frame for function: " + hex(fva))

    lvar_offset = idc.get_frame_lvar_size(fva) - frame_offset
    if not lvar_offset:
        raise RuntimeError("failed to compute local variable offset")

    if lvar_offset <= 0:
        raise RuntimeError("failed to compute positive local variable offset")

    string = idc.get_member_cmt(stack, lvar_offset, repeatable)
    if not string:
        string = s
    else:
        if s in string:  # ignore duplicates
            return
        string = string + "\\n" + s

    if not idc.set_member_cmt(stack, lvar_offset, string, repeatable):
        raise RuntimeError("failed to set comment")


def apply_decoded_strings(decoded_strings):
    for ds in decoded_strings:
        if not ds.string:
            continue

        if ds.address_type == AddressType.GLOBAL:
            logger.info("decoded string located at global address 0x%x: %s", ds.address, ds.string)
            append_comment(ds.address, ds.string)
        else:
            logger.info("decoded string at global address 0x%x: %s", ds.decoded_at, ds.string)
            append_comment(ds.decoded_at, ds.string)


def apply_stack_strings(stack_strings):
    for ss in stack_strings:
        if not ss.string:
            continue

        try:
            append_lvar_comment(ss.function, ss.frame_offset, ss.string)
        except RuntimeError as e:
            logger.info("failed to apply stack string: %s", str(e))
            continue
        else:
            logger.info("decoded stack string in function 0x%x: %s", ss.function, ss.string)


def ignore_floss_logs():
    # ignore messages like:
    # WARNING:EmulatorDriver:error during emulation of function: BreakpointHit at 0x1001fbfb
    # ERROR:EmulatorDriver:error during emulation of function ... DivideByZero: DivideByZero at 0x10004940
    # TODO: probably should modify emulator driver to de-prioritize this
    logging.getLogger("EmulatorDriver").setLevel(logging.CRITICAL)

    # ignore messages like:
    # WARNING:Monitor:logAnomaly: anomaly: BreakpointHit at 0x1001fbfb
    logging.getLogger("Monitor").setLevel(logging.ERROR)

    # ignore messages like:
    # WARNING:envi/codeflow.addCodeFlow:parseOpcode error at 0x1001044c: InvalidInstruction("'660f3a0fd90c660f7f1f660f6fe0660f' at 0x1001044c",)
    logging.getLogger("envi/codeflow.addCodeFlow").setLevel(logging.ERROR)

    # ignore messages like:
    # WARNING:vtrace.platforms.win32:LoadLibrary C:\Users\USERNA~1\AppData\Local\Temp\_MEI21~1\vtrace\platforms\windll\amd64\symsrv.dll: [Error 126] The specified module could not be found
    # WARNING:vtrace.platforms.win32:LoadLibrary C:\Users\USERNA~1\AppData\Local\Temp\_MEI21~1\vtrace\platforms\windll\amd64\dbghelp.dll: [Error 126] The specified module could not be found
    logging.getLogger("vtrace.platforms.win32").setLevel(logging.ERROR)

    # ignore messages like:
    # WARNING:plugins.arithmetic_plugin.XORPlugin:identify: Invalid instruction encountered in basic block, skipping: 0x4a0637
    logging.getLogger("floss.plugins.arithmetic_plugin.XORPlugin").setLevel(logging.ERROR)
    logging.getLogger("floss.plugins.arithmetic_plugin.ShiftPlugin").setLevel(logging.ERROR)


def main(argv=None):
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)
    ignore_floss_logs()

    logger.info("loading vivisect workspace...")
    vw = viv_utils.loadWorkspaceFromIdb()
    logger.info("loaded vivisect workspace")

    selected_functions = vw.getFunctions()

    time0 = time.time()

    logger.info("identifying decoding functions...")
    decoding_functions_candidates, meta = floss.identify.find_decoding_function_features(
        vw, selected_functions, disable_progress=True
    )

    logger.info("decoding strings...")
    decoded_strings = floss.string_decoder.decode_strings(
        vw, floss.identify.get_function_fvas(decoding_functions_candidates), MIN_LENGTH, disable_progress=True
    )
    logger.info("decoded %d strings", len(decoded_strings))

    logger.info("extracting stackstrings...")
    stack_strings = floss.stackstrings.extract_stackstrings(vw, selected_functions, MIN_LENGTH, no_filter=True)
    stack_strings = set(stack_strings)
    logger.info("decoded %d stack strings", len(stack_strings))

    # TODO tight strings

    apply_decoded_strings(decoded_strings)

    apply_stack_strings(stack_strings)

    time1 = time.time()
    logger.debug("finished execution after %f seconds", (time1 - time0))

    return 0


if __name__ == "__main__":
    main()

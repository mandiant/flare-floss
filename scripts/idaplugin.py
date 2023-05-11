# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

#!/usr/bin/env python3
"""
Run FLOSS to automatically extract obfuscated strings and apply them to the
currently loaded module in IDA Pro.

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
"""
import os
import time
import logging
from typing import List, Union

import idc
import viv_utils

import floss
import floss.main
import floss.utils
import floss.render
import floss.identify
import floss.stackstrings
import floss.tightstrings
import floss.string_decoder
from floss.results import AddressType, StackString, TightString, DecodedString

logger = logging.getLogger("floss.idaplugin")


MIN_LENGTH = 4


def append_comment(ea: int, s: str, repeatable: bool = False) -> None:
    """
    add the given string as a (possibly repeating) comment to the given address.
    does not add the comment if it already exists.
    adds the comment on its own line.

    Args:
      ea: the address at which to add the comment.
      s: the comment text.
      repeatable: if True, set a repeatable comment.

    """
    # see: http://blogs.norman.com/2011/security-research/improving-ida-analysis-of-x64-exception-handling

    if repeatable:
        cmt = idc.get_cmt(ea, True)
    else:
        cmt = idc.get_cmt(ea, False)

    if not cmt:
        cmt = s  # no existing comment
    else:
        if s in cmt:  # ignore duplicates
            return
        cmt = cmt + "\\n" + s

    if repeatable:
        idc.set_cmt(ea, cmt, True)
    else:
        idc.set_cmt(ea, cmt, False)


def append_lvar_comment(fva: int, frame_offset: int, s: str, repeatable: bool = False) -> None:
    """
    add the given string as a (possibly repeatable) stack variable comment to the given function.
    does not add the comment if it already exists.
    adds the comment on its own line.

    Args:
      fva: the address of the function with the stack variable.
      frame_offset: the offset into the stack frame at which the variable is found.
      s: the comment text.
      repeatable: if True, set a repeatable comment.

    """

    stack = idc.get_func_attr(fva, idc.FUNCATTR_FRAME)
    if not stack:
        raise RuntimeError("failed to find stack frame for function: 0x%x" % fva)

    lvar_offset = (
        idc.get_func_attr(fva, idc.FUNCATTR_FRSIZE) - frame_offset
    )  # alternative: idc.get_frame_lvar_size(fva) - frame_offset
    if not lvar_offset:
        raise RuntimeError("failed to compute local variable offset: 0x%x 0x%x %s" % (fva, stack, s))

    if lvar_offset <= 0:
        raise RuntimeError("failed to compute positive local variable offset: 0x%x 0x%x %s" % (fva, stack, s))

    string = idc.get_member_cmt(stack, lvar_offset, repeatable)
    if not string:
        string = s
    else:
        if s in string:  # ignore duplicates
            return
        string = string + "\\n" + s

    if not idc.set_member_cmt(stack, lvar_offset, string, repeatable):
        raise RuntimeError("failed to set comment: 0x%08x 0x%08x 0x%08x: %s" % (fva, stack, lvar_offset, s))


def apply_decoded_strings(decoded_strings: List[DecodedString]) -> None:
    for ds in decoded_strings:
        if not ds.string:
            continue

        if ds.address_type == AddressType.GLOBAL:
            logger.info("decoded string at global address 0x%x: %s", ds.address, ds.string)
            append_comment(ds.address, ds.string)
        else:
            logger.info("decoded string for function call at 0x%x: %s", ds.decoded_at, ds.string)
            append_comment(ds.decoded_at, ds.string)


def apply_stack_strings(
    stack_strings: List[StackString], tight_strings: List[TightString], lvar_cmt: bool = True, cmt: bool = True
) -> None:
    """
    lvar_cmt: apply stack variable comment
    cmt: apply regular comment
    """
    strings = stack_strings + tight_strings
    for s in strings:
        if not s.string:
            continue

        logger.info(
            "decoded stack/tight string in function 0x%x (pc: 0x%x): %s", s.function, s.program_counter, s.string
        )
        if lvar_cmt:
            try:
                # TODO this often fails due to wrong frame offset
                append_lvar_comment(s.function, s.frame_offset, s.string)
            except RuntimeError as e:
                logger.warning("failed to apply stack/tight string: %s", str(e))
        if cmt:
            append_comment(s.program_counter, s.string)


def ignore_floss_logs():
    logging.getLogger("floss.api_hooks").setLevel(logging.WARNING)
    logging.getLogger("floss.function_argument_getter").setLevel(logging.WARNING)
    logging.getLogger("viv_utils").setLevel(logging.CRITICAL)
    logging.getLogger("viv_utils.emulator_drivers").setLevel(logging.ERROR)
    floss.utils.set_vivisect_log_level(logging.CRITICAL)


def main(argv=None):
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)
    ignore_floss_logs()

    idb_path = idc.get_idb_path()
    fpath, _ = os.path.splitext(idb_path)
    viv_path = fpath + ".viv"
    if os.path.exists(viv_path):
        logger.info("loading vivisect workspace from %r", viv_path)
        vw = viv_utils.getWorkspace(viv_path)
    else:
        logger.info("loading vivisect workspace from IDB...")
        vw = viv_utils.loadWorkspaceFromIdb()
    logger.info("loaded vivisect workspace")

    selected_functions = set(vw.getFunctions())

    time0 = time.time()

    logger.info("identifying decoding functions...")
    decoding_function_features, library_functions = floss.identify.find_decoding_function_features(
        vw, selected_functions, disable_progress=True
    )

    logger.info("extracting stackstrings...")
    selected_functions = floss.identify.get_functions_without_tightloops(decoding_function_features)
    stack_strings = floss.stackstrings.extract_stackstrings(
        vw, selected_functions, MIN_LENGTH, verbosity=floss.render.Verbosity.VERBOSE, disable_progress=True
    )
    logger.info("decoded %d stack strings", len(stack_strings))

    logger.info("extracting tightstrings...")
    tightloop_functions = floss.identify.get_functions_with_tightloops(decoding_function_features)
    tight_strings = floss.tightstrings.extract_tightstrings(
        vw,
        tightloop_functions,
        min_length=MIN_LENGTH,
        verbosity=floss.render.Verbosity.VERBOSE,
        disable_progress=True,
    )
    logger.info("decoded %d tight strings", len(tight_strings))

    apply_stack_strings(stack_strings, tight_strings)

    logger.info("decoding strings...")

    top_functions = floss.identify.get_top_functions(decoding_function_features, 20)
    fvas_to_emulate = floss.identify.get_function_fvas(top_functions)
    fvas_tight_functions = floss.identify.get_tight_function_fvas(decoding_function_features)
    fvas_to_emulate = floss.identify.append_unique(fvas_to_emulate, fvas_tight_functions)
    decoded_strings = floss.string_decoder.decode_strings(
        vw,
        fvas_to_emulate,
        MIN_LENGTH,
        verbosity=floss.render.Verbosity.VERBOSE,
        disable_progress=True,
    )
    logger.info("decoded %d strings", len(decoded_strings))
    apply_decoded_strings(decoded_strings)

    time1 = time.time()
    logger.debug("finished execution after %f seconds", (time1 - time0))

    return 0


if __name__ == "__main__":
    main()

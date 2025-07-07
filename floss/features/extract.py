# Copyright 2021 Google LLC
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

from typing import Any, Tuple, Callable, Iterator

import envi
import networkx
import vivisect
import viv_utils
from networkx import strongly_connected_components
from viv_utils import BasicBlock
from envi.archs.i386.opconst import INS_MOV, INS_ROL, INS_ROR, INS_SHL, INS_SHR, INS_XOR, INS_CALL

import floss.logging_
from floss.const import TS_TIGHT_FUNCTION_MAX_BLOCKS
from floss.features.features import (
    Mov,
    Loop,
    Nzxor,
    Shift,
    CallsTo,
    NzxorLoop,
    TightLoop,
    BlockCount,
    TightFunction,
    KindaTightLoop,
    NzxorTightLoop,
)

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40

SHIFT_ROTATE_INS = (INS_SHL, INS_SHR, INS_ROL, INS_ROR)

logger = floss.logging_.getLogger(__name__)


def extract_insn_nzxor(f, bb, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    if insn.opcode != INS_XOR:
        return

    if insn.opers[0] == insn.opers[1]:
        return

    if is_security_cookie(f, bb, insn):
        return

    yield Nzxor(insn)


def is_security_cookie(f, bb, insn) -> bool:
    """
    check if an instruction is related to security cookie checks
    """
    # security cookie check should use SP or BP
    oper = insn.opers[1]
    if oper.isReg() and oper.reg not in [
        envi.archs.i386.regs.REG_ESP,
        envi.archs.i386.regs.REG_EBP,
        # TODO: do x64 support for real.
        envi.archs.amd64.regs.REG_RBP,
        envi.archs.amd64.regs.REG_RSP,
    ]:
        return False

    # expect security cookie init in first basic block within first bytes (instructions)
    bb0 = f.basic_blocks[0]

    if bb == bb0 and insn.va < (bb.va + SECURITY_COOKIE_BYTES_DELTA):
        return True

    # ... or within last bytes (instructions) before a return
    elif bb.instructions[-1].isReturn() and insn.va > (bb.va + bb.size - SECURITY_COOKIE_BYTES_DELTA):
        return True

    return False


def extract_insn_shift(f, bb, insn):
    if insn.opcode in SHIFT_ROTATE_INS:
        yield Shift(insn)


def extract_insn_mov(f, bb, insn):
    # identify register dereferenced writes to memory
    #   mov byte  [eax], cl
    #   mov dword [edx], eax

    if insn.opcode == INS_MOV:
        # don't handle len(ops) == 0 for `rep movsb` etc. often used for memcpy
        if len(insn.opers) != 2:
            return

        op0, op1 = insn.opers

        if not op0.isDeref():
            return

        if op1.isImmed():
            return

        # as an additional heuristic for global string decoding instructions like
        #   mov     dword_40400C, 0
        # could be captured via envi.archs.i386.disasm.i386ImmMemOper
        #
        # i386RegMemOper could also capture operands with displacement != 0
        #   mov     [edx+4], eax

        if isinstance(op0, envi.archs.i386.disasm.i386RegMemOper):
            if op0.disp == 0:
                yield Mov(insn)


def extract_function_calls_to(f):
    yield CallsTo(f.vw, [x[0] for x in f.vw.getXrefsTo(f.va, rtype=vivisect.const.REF_CODE)])


def extract_function_kinda_tight_loop(f):
    """
    Yields tight loop features in the provided function
    Algorithm by Blaine S.
    """
    try:
        cfg = viv_utils.CFG(f)
        root_bb_vas = {bb.va for bb in cfg.get_root_basic_blocks()}
        leaf_bb_vas = {bb.va for bb in cfg.get_leaf_basic_blocks()}
    except ValueError:
        # likely wrongly identified or analyzed function
        return

    for bb in f.basic_blocks:
        # skip first and last BBs
        if bb.va in root_bb_vas:
            continue

        if bb.va in leaf_bb_vas:
            continue

        succs = tuple(cfg.get_successor_basic_blocks(bb))

        # we're looking for one of two cases:
        #
        # A) block conditionally loops to itself:
        #
        #         |
        #         v v--+
        #       [ a ]  |
        #       /   \--+
        #    [ b ]
        #
        # path: [a]->[a]
        #
        #
        # B) block conditionally branches to block that loops to itself:
        #
        #
        #         |
        #         v v----+
        #       [ a ]    |
        #       /   \    |
        #    [ b ] [ c ] |
        #             \--+
        #
        # path: [a]->[c]->[a]

        # skip blocks that don't have exactly 2 successors
        if len(succs) != 2:
            continue

        # the BB that branches back to `bb`, either [a] or [c]
        # or None if a tight loop is not found.
        loop_bb = None
        is_very_tight = False

        # find very tight loops: [a]->[a]
        for suc in succs:
            if suc.va == bb.va:
                is_very_tight = True
                loop_bb = bb

        # find semi tight loops: [a]->[c]->[a]
        if not loop_bb:
            for suc in succs:
                suc_succs_vas = [s.va for s in cfg.get_successor_basic_blocks(suc)]
                if bb.va in suc_succs_vas:
                    if len(suc_succs_vas) == 1 or bb.va == suc.va:
                        loop_bb = suc
                        break

        if not loop_bb:
            continue

        # get the block after loop, [b]
        next_bb = None
        for suc in succs:
            if loop_bb.va != suc.va:
                next_bb = suc
                break

        if not next_bb:
            continue

        if skip_tightloop(bb, loop_bb):
            continue

        if is_very_tight:
            yield TightLoop(bb.va, next_bb.va)
        else:
            yield KindaTightLoop(bb.va, next_bb.va)


def skip_tightloop(bb: BasicBlock, loop_bb: BasicBlock) -> bool:
    # ignore tight loops that call other functions
    if contains_call(bb) or contains_call(loop_bb):
        return True

    # ignore tight loops that don't write memory
    if not (writes_memory(loop_bb) or writes_memory(bb)):
        return True

    return False


def contains_call(bb):
    for insn in bb.instructions:
        if insn.opcode == INS_CALL:
            return True
    return False


def writes_memory(bb):
    for insn in bb.instructions:
        # don't handle len(ops) == 0 for `rep movsb` or other unexpected instructions
        if len(insn.opers) < 1:
            continue

        # these also cover amd64
        if isinstance(
            insn.opers[0],
            (
                envi.archs.i386.disasm.i386RegMemOper,
                envi.archs.i386.disasm.i386ImmMemOper,
                envi.archs.i386.disasm.i386SibOper,
            ),
        ):
            return True
    return False


def abstract_nzxor_tightloop(features):
    for tl in filter(lambda f: isinstance(f, TightLoop), features):
        for nzxor in filter(lambda f: isinstance(f, Nzxor), features):
            if tl.startva <= nzxor.insn.va <= tl.endva:
                yield NzxorTightLoop()


def abstract_nzxor_loop(features):
    if any(isinstance(f, Nzxor) for f in features) and any(isinstance(f, Loop) for f in features):
        yield NzxorLoop()


def abstract_tightfunction(features):
    """
    (Kinda) TightLoop and only a few basic blocks
    """
    if any(filter(lambda f: isinstance(f, (TightLoop, KindaTightLoop)), features)):
        for block_count in filter(lambda f: isinstance(f, BlockCount), features):
            if block_count.value < TS_TIGHT_FUNCTION_MAX_BLOCKS:
                yield TightFunction()
                return


def extract_function_loop(f):
    """
    parse if a function has a loop
    """
    edges = []

    for bb in f.basic_blocks:
        if len(bb.instructions) > 0:
            for bva, bflags in bb.instructions[-1].getBranches():
                if bva is None:
                    # vivisect may be unable to recover the call target, e.g. on dynamic calls like `call esi`
                    # for this bva is None, and we don't want to add it for loop detection, ref: #617; vivisect#574
                    continue
                # vivisect does not set branch flags for non-conditional jmp so add explicit check
                if (
                    bflags & envi.BR_COND
                    or bflags & envi.BR_FALL
                    or bflags & envi.BR_TABLE
                    or bb.instructions[-1].mnem == "jmp"
                ):
                    edges.append((bb.va, bva))

    g = networkx.DiGraph()
    g.add_edges_from(edges)
    comps = strongly_connected_components(g)
    for comp in comps:
        if len(comp) >= 2:
            # TODO get list of bb start/end eas
            yield Loop(comp)


FUNCTION_HANDLERS = (
    extract_function_calls_to,
    extract_function_loop,
    extract_function_kinda_tight_loop,
    # extract_function_order,  # TODO decoding functions are often one of the first in a program
    # extract_num_api_calls,  # TODO decoding functions don't normally contain many (API) calls
)


def extract_function_features(f):
    for func_handler in FUNCTION_HANDLERS:
        for feature in func_handler(f):
            yield feature


# currently none, but this can change
BASIC_BLOCK_HANDLERS: Tuple[Callable[[Any, Any], Iterator], ...] = ()


def extract_basic_block_features(f: Any, bb: Any) -> Iterator:
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature in bb_handler(f, bb):
            yield feature


INSTRUCTION_HANDLERS = (
    extract_insn_nzxor,
    extract_insn_shift,
    extract_insn_mov,
)


def extract_insn_features(f, bb, insn):
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature in insn_handler(f, bb, insn):
            yield feature


ABSTRACTION_HANDLERS = (
    abstract_nzxor_loop,
    abstract_nzxor_tightloop,
    abstract_tightfunction,
)


def abstract_features(features):
    for abst_handler in ABSTRACTION_HANDLERS:
        for feature in abst_handler(features):
            yield feature

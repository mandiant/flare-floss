# Copyright 2026 Google LLC
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

"""
Static string deobfuscator for Rust binaries using litcrypt / litcrypt2 crates
and keyed XOR/ADD/SUB decoders.
"""

from __future__ import annotations

import io
import logging
import pathlib
import re
import string
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Union

import envi.archs.amd64 as e_amd64
import envi.archs.i386 as e_i386
import pefile
from elftools.elf.elffile import ELFFile
from floss.results import StaticString, StringEncoding

logger = logging.getLogger(__name__)

# AMD64 canonical register IDs (envi reg & 0xFFFF)
REG_RAX = 0
REG_RCX = 1
REG_RDX = 2
REG_RBX = 3
REG_RSP = 4
REG_RBP = 5
REG_RSI = 6
REG_RDI = 7
REG_R8 = 8
REG_R9 = 9
REG_R10 = 10
REG_R11 = 11
REG_R12 = 12
REG_R13 = 13
REG_R14 = 14
REG_R15 = 15

PRINTABLE_CHARS = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")
TEXT_CHARS = set(
    bytes(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._/:@%+=-",
        "ascii",
    )
)

_COMMON_TRIGRAMS = set(
    "the and ing ion tio ent ati for her ter tha ere ate his con res ver all ons nce men ith "
    "ted ers pro thi wit are ess not ive was ect rea com eve per int est sta cti ica ist ear "
    "ain one our iti rat ell ont end ure nte tur nde ant ome ult lin sch dat ild fig onf nfi "
    "poi dpo oin sou urc rce emo tel lem eme etr try eat atu fea net get set key tok sys reg "
    "log src lib run man app use new old add del str num idx cmd nam pat fil hos por use pas "
    "loa sav rea wri sen rec ini exi mai fun can ana nar ary bra rav avo bui uil cha har arl "
    "rli lie del elt lta ech cho vel elo opm pme men nta tal tab abl ble ser erv vic ice cli "
    "ien ent tion ersi rsi sio ver ersi onf nfig figu gur ura rat tio ion def efa fau aul ult "
    "set ett tti tin ing pat ath con nfi onf fig set sta tab chan hann anne nnel el- sta tab "
    "sch hem ema mav ver ers rsi sio on- num mbe ber get tin ing all wit hin out abo ut- per "
    "ata tab tas tes tex typ val var vec web xml yes zip url uri uid utf ascii json http host "
    "dir doc dow dri env err evt fmt gen hex idx img inp key lab lst map max min mod msg obj "
    "opt out pkg pos pre ptr que ref req res ret row siz src std sum sys tab tag tmp top txt "
    "upd usr val vec ver win xml abc def ghi code data file name path user admin login token "
    "endp ndpo dpoi poin oint conf onfi nfig figu bui uil ild ld- d-i -id id- 201 026 261 "
    "rel ele lea eas ase chan hann rele leas ease stab tabl able ble- le-2 anne nnel ault efau "
    "resou esour sourc ource data data- a.bin .bin opt /opt app /app reso settin tting tings "
    "toml .toml onfig fig/ ig/n start arte rted rt-g -gui guid uide star getti ettin tting "
    "flag lag- feat eatu atur ture elem lem- emet metr etry fla ff- off tele emet".split()
)


def _canon_reg(reg_id: Optional[int]) -> Optional[int]:
    """Map any sub-register (e.g. edx, dl) to its 64-bit parent ID in envi."""
    return (reg_id & 0xFFFF) if reg_id is not None else None


def english_score(t: str) -> float:
    """Fraction of 3-grams that match common English/identifier trigrams."""
    low = t.lower()
    grams = [low[i : i + 3] for i in range(len(low) - 2)]
    if not grams:
        return 0.0
    hits = sum(1 for g in grams if g in _COMMON_TRIGRAMS)
    return hits / len(grams)


def looks_like_text(dec: bytes) -> bool:
    """Validate whether decrypted bytes represent plausible string data."""
    if len(dec) < 4:
        return False
    try:
        t = dec.decode("utf-8")
    except UnicodeDecodeError:
        try:
            t = dec.decode("ascii")
        except UnicodeDecodeError:
            return False

    # Check for ASCII indicators / URLs / paths
    if any(
        prefix in t for prefix in ("http://", "https://", "canary::", "/", "\\", "::")
    ):
        return True

    texty = sum(1 for c in dec if c in TEXT_CHARS)
    if texty / len(dec) < 0.85:
        return False

    alnum = sum(1 for c in t if c.isalnum())
    if alnum / len(dec) < 0.50:
        return False

    if not any(c.isalpha() for c in t):
        return False

    es = english_score(t)
    if es < 0.08 and len(t) >= 8:
        return False

    return True


class BinaryView:
    """Abstraction for reading sections, VAs, and offsets from PE or ELF."""

    def __init__(self, sample: Union[pathlib.Path, str, bytes, pefile.PE]):
        self.is_pe: bool = False
        self.is_elf: bool = False
        self.arch: str = "amd64"
        self._pe: Optional[pefile.PE] = None
        self._elf: Optional[ELFFile] = None
        self._raw_data: bytes = b""

        if isinstance(sample, pefile.PE):
            self.is_pe = True
            self._pe = sample
            self._raw_data = sample.__data__
            self._init_pe()
        else:
            if isinstance(sample, (str, pathlib.Path)):
                data = pathlib.Path(sample).read_bytes()
            else:
                data = sample
            self._raw_data = data

            if data.startswith(b"MZ"):
                try:
                    self._pe = pefile.PE(data=data, fast_load=True)
                    self.is_pe = True
                    self._init_pe()
                except Exception:
                    pass
            elif data.startswith(b"\x7fELF"):
                try:
                    self._elf = ELFFile(io.BytesIO(data))
                    self.is_elf = True
                    self._init_elf()
                except Exception:
                    pass

    def _init_pe(self) -> None:
        if (
            self._pe
            and self._pe.FILE_HEADER.Machine
            == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
        ):
            self.arch = "amd64"
        else:
            self.arch = "x86"

    def _init_elf(self) -> None:
        if self._elf and self._elf["e_machine"] == "EM_X86_64":
            self.arch = "amd64"
        else:
            self.arch = "x86"

    def get_text_section(self) -> Tuple[bytes, int]:
        """Return (code_bytes, virtual_address) for the primary executable section."""
        if self.is_pe and self._pe:
            for s in self._pe.sections:
                name = s.Name.rstrip(b"\x00").decode("latin-1", "ignore")
                if name == ".text" or s.IMAGE_SCN_MEM_EXECUTE:
                    va = self._pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
                    return s.get_data(), va
        elif self.is_elf and self._elf:
            sec = self._elf.get_section_by_name(".text")
            if sec:
                return sec.data(), sec["sh_addr"]
            for s in self._elf.iter_sections():
                if s["sh_flags"] & 0x4:  # SHF_EXECINSTR
                    return s.data(), s["sh_addr"]
        return b"", 0

    def read_va(self, va: int, length: int) -> bytes:
        """Read `length` bytes at virtual address `va`."""
        if self.is_pe and self._pe:
            rva = va - self._pe.OPTIONAL_HEADER.ImageBase
            try:
                return self._pe.get_data(rva, length)
            except Exception:
                return b""
        elif self.is_elf and self._elf:
            for seg in self._elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    start = seg["p_vaddr"]
                    end = start + seg["p_filesz"]
                    if start <= va < end:
                        off = seg["p_offset"] + (va - start)
                        return self._raw_data[off : off + length]
        return b""

    def va_to_offset(self, va: int) -> int:
        """Convert virtual address to file raw offset."""
        if self.is_pe and self._pe:
            rva = va - self._pe.OPTIONAL_HEADER.ImageBase
            try:
                return self._pe.get_offset_from_rva(rva)
            except Exception:
                return va
        elif self.is_elf and self._elf:
            for seg in self._elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    start = seg["p_vaddr"]
                    end = start + seg["p_filesz"]
                    if start <= va < end:
                        return seg["p_offset"] + (va - start)
        return va


def extract_litcrypt_strings(
    sample: Union[pathlib.Path, str, bytes, pefile.PE], min_length: int = 4
) -> List[StaticString]:
    """
    Extract statically deobfuscated strings from Rust binaries that use litcrypt,
    litcrypt2, or keyed XOR/ADD/SUB decryption routines.
    """
    binary = BinaryView(sample)
    code, base = binary.get_text_section()
    if not code:
        return []

    if binary.arch == "amd64":
        disasm = e_amd64.Amd64Disasm()
    else:
        disasm = e_i386.i386Disasm()

    # Linear disassembly
    insns = []
    va = base
    end = base + len(code)
    while va < end:
        try:
            op = disasm.disasm(code, va - base, va)
            insns.append(op)
            va += len(op)
        except Exception:
            va += 1

    if not insns:
        return []

    idx = {op.va: i for i, op in enumerate(insns)}
    n_insns = len(insns)

    # 1. Identify decoders: (loop_xor_addr, key_va, keylen, op_type)
    decoders: List[Tuple[int, int, int, str]] = []
    for i, op in enumerate(insns):
        if op.mnem not in ("xor", "add", "sub"):
            continue

        mem_opers = [o for o in op.opers if o.isDeref()]
        if not mem_opers:
            continue

        key_va = None
        for o in mem_opers:
            if isinstance(o, e_amd64.disasm.Amd64RipRelOper):
                key_va = o.getOperAddr(op)
                break

        keylen = None
        # Scan ~16 insns around XOR for key length idioms:
        # (a) `and reg, 0xK` => keylen = K + 1
        # (b) `cmp reg, 0xM` + `cmov*` or jump => keylen = M + 1
        for j in range(max(0, i - 16), min(n_insns, i + 3)):
            pj = insns[j]
            if pj.mnem == "and":
                for o in pj.opers:
                    if isinstance(o, e_i386.disasm.i386ImmOper):
                        imm = o.imm
                        if 0 < imm < 256 and (imm & (imm + 1)) == 0:
                            keylen = imm + 1
            elif pj.mnem == "cmp":
                for o in pj.opers:
                    if isinstance(o, e_i386.disasm.i386ImmOper):
                        imm = o.imm
                        if 0 < imm < 256:
                            for k in range(j + 1, min(n_insns, j + 4)):
                                if insns[k].mnem.startswith("cmov") or insns[
                                    k
                                ].mnem in (
                                    "jae",
                                    "jnb",
                                    "jb",
                                    "ja",
                                    "jnc",
                                ):
                                    keylen = imm + 1
                                    break

        if key_va is None:
            # Key pointer loaded via `lea reg, [rip+disp]` into one of the dereferenced registers
            target_regs: Set[int] = set()
            for o in mem_opers:
                r = _canon_reg(getattr(o, "reg", None))
                if r is not None:
                    target_regs.add(r)
                idx_r = _canon_reg(getattr(o, "index", None))
                if idx_r is not None:
                    target_regs.add(idx_r)

            # Check preceding byte loads (movzx/mov) in the loop
            for j in range(max(0, i - 4), i):
                pj = insns[j]
                if pj.mnem in ("movzx", "mov"):
                    for o in pj.opers:
                        if o.isDeref():
                            r = _canon_reg(getattr(o, "reg", None))
                            if r is not None:
                                target_regs.add(r)
                            idx_r = _canon_reg(getattr(o, "index", None))
                            if idx_r is not None:
                                target_regs.add(idx_r)

            for j in range(i - 1, max(0, i - 60), -1):
                pj = insns[j]
                if pj.mnem == "lea" and len(pj.opers) >= 2:
                    dst = pj.opers[0]
                    src = pj.opers[1]
                    dst_r = _canon_reg(getattr(dst, "reg", None))
                    if dst_r in target_regs:
                        if isinstance(src, e_amd64.disasm.Amd64RipRelOper):
                            key_va = src.getOperAddr(pj)
                            break

        if key_va and keylen:
            decoders.append((op.va, key_va, keylen, op.mnem))

    # Deduplicate decoders by (key_va, keylen)
    seen_decoders: Dict[Tuple[int, int], Tuple[int, str]] = {}
    for addr, kva, kl, opn in decoders:
        seen_decoders.setdefault((kva, kl), (addr, opn))

    def func_entry(xaddr: int) -> Optional[int]:
        """Find the function entry prologue nearest to the XOR loop."""
        i_pos = idx.get(xaddr)
        if i_pos is None:
            return None
        for j in range(i_pos, max(0, i_pos - 400), -1):
            if insns[j].mnem == "push":
                k = j
                while k > 0 and insns[k - 1].mnem == "push":
                    k -= 1
                return insns[k].va
        return None

    # Map all call targets in the binary: target_va -> List[insn_index]
    call_map: Dict[int, List[int]] = {}
    for i, op in enumerate(insns):
        if op.mnem == "call" and op.opers:
            o = op.opers[0]
            if isinstance(o, e_i386.disasm.i386PcRelOper):
                tgt = o.getOperValue(op)
                call_map.setdefault(tgt, []).append(i)

    recovered_strings: List[StaticString] = []

    # 2. Extract strings from generic keyed decoders (litcrypt v1, hand-rolled XOR)
    for (kva, kl), (xaddr, opn) in seen_decoders.items():
        key = binary.read_va(kva, kl)
        if len(key) < kl:
            continue
        if 2 * key.count(0) >= len(key):
            continue

        entry = func_entry(xaddr)
        if not entry or entry not in call_map:
            continue

        decoder_strings: List[Tuple[str, int]] = []
        for ci in call_map[entry]:
            blob_va = None
            length = None

            # Backward scan for ciphertext blob (LEA) and length (MOV imm)
            # SysV AMD64: arg2=RSI (6), arg3=RDX (2)
            # Win64 AMD64: arg2=RDX (2), arg3=R8 (8)
            blob_regs = {REG_RSI, REG_RDX} if not binary.is_pe else {REG_RDX}
            len_regs = {REG_RDX, REG_R8} if not binary.is_pe else {REG_R8}

            for j in range(ci - 1, max(0, ci - 16), -1):
                pj = insns[j]
                if pj.mnem == "lea" and len(pj.opers) >= 2:
                    dst_r = _canon_reg(getattr(pj.opers[0], "reg", None))
                    src = pj.opers[1]
                    if (
                        dst_r in blob_regs
                        and isinstance(src, e_amd64.disasm.Amd64RipRelOper)
                        and blob_va is None
                    ):
                        blob_va = src.getOperAddr(pj)
                if pj.mnem == "mov" and len(pj.opers) >= 2 and length is None:
                    dst_r = _canon_reg(getattr(pj.opers[0], "reg", None))
                    src = pj.opers[1]
                    if dst_r in len_regs and isinstance(src, e_i386.disasm.i386ImmOper):
                        if 0 < src.imm <= 4096:
                            length = src.imm
                if blob_va is not None and length is not None:
                    break

            # Fallback: slice-struct on stack (&[u8] fat pointer passed to function)
            if blob_va is None or length is None:
                slice_disp = None
                for j in range(ci - 1, max(0, ci - 12), -1):
                    pj = insns[j]
                    if pj.mnem == "lea" and len(pj.opers) >= 2:
                        dst_r = _canon_reg(getattr(pj.opers[0], "reg", None))
                        src = pj.opers[1]
                        if (
                            dst_r in (REG_RSI, REG_RDX)
                            and getattr(src, "reg", None) == REG_RSP
                        ):
                            slice_disp = getattr(src, "disp", None)
                            break
                if slice_disp is not None:
                    for j in range(ci - 1, max(0, ci - 28), -1):
                        pj = insns[j]
                        if pj.mnem == "mov" and len(pj.opers) >= 2:
                            dst = pj.opers[0]
                            src = pj.opers[1]
                            if (
                                getattr(dst, "reg", None) == REG_RSP
                                and getattr(dst, "disp", None) == slice_disp + 8
                            ):
                                if (
                                    isinstance(src, e_i386.disasm.i386ImmOper)
                                    and length is None
                                ):
                                    length = src.imm
                    for j in range(ci - 1, max(0, ci - 80), -1):
                        pj = insns[j]
                        if pj.mnem == "lea" and len(pj.opers) >= 2 and blob_va is None:
                            src = pj.opers[1]
                            if isinstance(src, e_amd64.disasm.Amd64RipRelOper):
                                blob_va = src.getOperAddr(pj)
                        if blob_va is not None and length is not None:
                            break

            if blob_va is None or not length or length > 4096:
                continue

            blob = binary.read_va(blob_va, length)
            if not blob:
                continue

            if opn == "xor":
                dec = bytes(blob[k] ^ key[k % kl] for k in range(len(blob)))
            elif opn == "add":
                dec = bytes((blob[k] + key[k % kl]) & 0xFF for k in range(len(blob)))
            else:
                dec = bytes((blob[k] - key[k % kl]) & 0xFF for k in range(len(blob)))

            if dec and looks_like_text(dec):
                s = dec.decode("utf-8", "ignore")
                if len(s) >= min_length:
                    decoder_strings.append((s, binary.va_to_offset(blob_va)))

        # Corroboration: accept if >= 2 call sites decode cleanly (or single high confidence IOC)
        if len(decoder_strings) >= 2 or any(
            "::" in s or "http" in s for s, _ in decoder_strings
        ):
            for s, off in decoder_strings:
                recovered_strings.append(
                    StaticString(string=s, offset=off, encoding=StringEncoding.UTF8)
                )

    # 3. Dedicated litcrypt2 stride-permutation decoder
    recovered_litcrypt2 = _recover_litcrypt2(binary, insns, call_map, min_length)
    recovered_strings.extend(recovered_litcrypt2)

    # Deduplicate by offset and string
    unique: Dict[Tuple[int, str], StaticString] = {}
    for st in recovered_strings:
        unique[(st.offset, st.string)] = st

    return list(unique.values())


def _recover_litcrypt2(
    binary: BinaryView,
    insns: list,
    call_map: Dict[int, List[int]],
    min_length: int,
) -> List[StaticString]:
    """Recover strings from litcrypt2's stride-permutation state machine."""
    out: List[StaticString] = []
    n_insns = len(insns)

    for i, op in enumerate(insns):
        if not (op.mnem.startswith("cmovb") or op.mnem.startswith("cmovc")):
            continue

        idx_reg = _canon_reg(getattr(op.opers[0], "reg", None)) if op.opers else None
        if idx_reg is None:
            continue

        keylen = None
        for j in range(i - 1, max(0, i - 6), -1):
            if insns[j].mnem == "cmp":
                for o in insns[j].opers:
                    if isinstance(o, e_i386.disasm.i386ImmOper) and 8 <= o.imm <= 1024:
                        keylen = o.imm
                        break
            if keylen:
                break
        if not keylen:
            continue

        stride = None
        for j in range(i - 1, max(0, i - 8), -1):
            pj = insns[j]
            if pj.mnem == "lea" and len(pj.opers) >= 2:
                src = pj.opers[1]
                disp = getattr(src, "disp", 0)
                if 0 < disp <= 16:
                    stride = disp
                    break
        if not stride:
            continue

        wrap_eq, wrap_past = 1, 0
        for j in range(i - 1, max(0, i - 5), -1):
            m = insns[j].mnem
            if m in ("sete", "setz"):
                break
            if m in ("setne", "setnz"):
                wrap_eq, wrap_past = 0, 1
                break

        key_va = None
        for j in range(i + 1, min(n_insns, i + 10)):
            pj = insns[j]
            if pj.mnem == "xor" and len(pj.opers) >= 2:
                for o in pj.opers:
                    if isinstance(o, e_amd64.disasm.Amd64RipRelOper):
                        key_va = o.getOperAddr(pj)
                        break
            if key_va:
                break
        if not key_va:
            # Check register-indirect XOR and backtrack to LEA
            for j in range(i + 1, min(n_insns, i + 10)):
                pj = insns[j]
                if pj.mnem == "xor" and len(pj.opers) >= 2:
                    for o in pj.opers:
                        if o.isDeref():
                            r = _canon_reg(getattr(o, "reg", None))
                            idx_r = _canon_reg(getattr(o, "index", None))
                            for k in range(j - 1, max(0, j - 60), -1):
                                pk = insns[k]
                                if pk.mnem == "lea" and len(pk.opers) >= 2:
                                    dst_r = _canon_reg(
                                        getattr(pk.opers[0], "reg", None)
                                    )
                                    if dst_r in (r, idx_r) and isinstance(
                                        pk.opers[1], e_amd64.disasm.Amd64RipRelOper
                                    ):
                                        key_va = pk.opers[1].getOperAddr(pk)
                                        break
                                if key_va:
                                    break
                if key_va:
                    break

        if not key_va:
            continue

        key = binary.read_va(key_va, keylen)
        if len(key) < keylen:
            continue

        # Initial index and const
        init_k = stride
        for j in range(i - 1, max(0, i - 20), -1):
            pj = insns[j]
            if pj.mnem == "mov" and len(pj.opers) >= 2:
                dst_r = _canon_reg(getattr(pj.opers[0], "reg", None))
                if dst_r == idx_reg and isinstance(
                    pj.opers[1], e_i386.disasm.i386ImmOper
                ):
                    if 0 <= pj.opers[1].imm < keylen:
                        init_k = pj.opers[1].imm
                        break

        c0 = key[0]
        for j in range(i - 1, max(0, i - 30), -1):
            pj = insns[j]
            if pj.mnem == "xor" and len(pj.opers) >= 2:
                if (
                    isinstance(pj.opers[1], e_i386.disasm.i386ImmOper)
                    and 0 < pj.opers[1].imm < 256
                ):
                    c0 = pj.opers[1].imm
                    break

        # Decoder function entry
        entry = None
        for j in range(i, max(0, i - 400), -1):
            if insns[j].mnem == "push":
                k = j
                while k > 0 and insns[k - 1].mnem == "push":
                    k -= 1
                entry = insns[k].va
                break

        if not entry or entry not in call_map:
            continue

        def schedule(length: int) -> List[int]:
            seq, k_val = [], init_k
            for _ in range(1, length):
                seq.append(k_val)
                nxt = k_val + stride
                k_val = (
                    nxt if nxt < keylen else (wrap_eq if nxt == keylen else wrap_past)
                )
            return seq

        def decode_litcrypt2(ct: bytes) -> bytes:
            if not ct:
                return b""
            res = bytearray([ct[0] ^ c0])
            for pos, kk in enumerate(schedule(len(ct)), 1):
                res.append(ct[pos] ^ key[kk])
            return bytes(res)

        blob_regs = {REG_RSI, REG_RDX} if not binary.is_pe else {REG_RDX}
        len_regs = {REG_RDX, REG_R8} if not binary.is_pe else {REG_R8}
        lit2_strings: List[Tuple[str, int]] = []

        for ci in call_map[entry]:
            blob_va = None
            length = None
            for j in range(ci - 1, max(0, ci - 20), -1):
                pj = insns[j]
                if pj.mnem == "lea" and len(pj.opers) >= 2 and blob_va is None:
                    dst_r = _canon_reg(getattr(pj.opers[0], "reg", None))
                    if dst_r in blob_regs and isinstance(
                        pj.opers[1], e_amd64.disasm.Amd64RipRelOper
                    ):
                        blob_va = pj.opers[1].getOperAddr(pj)
                if pj.mnem == "mov" and len(pj.opers) >= 2 and length is None:
                    dst_r = _canon_reg(getattr(pj.opers[0], "reg", None))
                    if dst_r in len_regs and isinstance(
                        pj.opers[1], e_i386.disasm.i386ImmOper
                    ):
                        if 0 < pj.opers[1].imm <= 4096:
                            length = pj.opers[1].imm
                if blob_va and length:
                    break

            if blob_va and length:
                ct = binary.read_va(blob_va, length)
                dec = decode_litcrypt2(ct)
                if dec and looks_like_text(dec):
                    s = dec.decode("utf-8", "ignore")
                    if len(s) >= min_length:
                        lit2_strings.append((s, binary.va_to_offset(blob_va)))

        if len(lit2_strings) >= 2 or any(
            "::" in s or "http" in s for s, _ in lit2_strings
        ):
            for s, off in lit2_strings:
                out.append(
                    StaticString(string=s, offset=off, encoding=StringEncoding.UTF8)
                )

    return out

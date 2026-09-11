"""
Go pclntab parser

Extracts a { function_name -> virtual_address } mapping from Go PE binaries
for all pclntab versions: 1.2 (covers 1.2-1.15), 1.16, 1.18, 1.20

This works on stripped and obfuscated binaries (garble / gobfuscate) because
pclntab is a runtime data structure that must survive stripping; only the ELF/PE
*section name* may be erased, which we handle via magic-byte scanning

References used:
- Go pclntab spec        : https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub
- Go upstream source     : https://go.dev/src/debug/gosym/pclntab.go
- GoReSym                : https://github.com/mandiant/GoReSym
- golang_pclntab_parser  : https://github.com/dipusone/golang_pclntab_parser
"""

import struct
import logging
from typing import Dict, List, Tuple, Optional

import pefile

logger = logging.getLogger(__name__)

### pclntab magic bytes (first 6 bytes of table)
# Go 1.2 – 1.15
MAGIC_V12 = b"\xfb\xff\xff\xff\x00\x00"
# Go 1.16 – 1.17
MAGIC_V116 = b"\xfa\xff\xff\xff\x00\x00"
# Go 1.18 – 1.19
MAGIC_V118 = b"\xf0\xff\xff\xff\x00\x00"
# Go 1.20+
MAGIC_V120 = b"\xf1\xff\xff\xff\x00\x00"

# Ordered most-recent-first so we match the likeliest binary first during scan
ALL_MAGICS: Tuple[bytes, ...] = (MAGIC_V120, MAGIC_V118, MAGIC_V116, MAGIC_V12)

# Valid values for quantum (byte 6) and ptrsize (byte 7) in the header
_VALID_QUANTUM = frozenset((1, 2, 4))
_VALID_PTRSIZE = frozenset((4, 8))


### Public API


def parse_pclntab(pe: pefile.PE) -> Dict[str, int]:
    """
    Parse pclntab from pe and return a {function_name: start_va} mapping

    Works on:
    - normal (non-stripped) PE with .gopclntab section
    - stripped PE (magic-byte scan across all sections)
    - garble / gobfuscate binaries (pclntab data survives, section name is gone)
    """
    try:
        pclntab_va, data = _locate_pclntab(pe)
    except ValueError as exc:
        logger.debug("pclntab not found: %s", exc)
        # empty return
        return {}

    if len(data) < 8:
        logger.debug("pclntab too short (%d bytes)", len(data))
        return {}

    magic = data[:6]
    quantum = data[6]
    ptrsize = data[7]

    if quantum not in _VALID_QUANTUM or ptrsize not in _VALID_PTRSIZE:
        logger.debug("invalid pclntab header: quantum=%d ptrsize=%d", quantum, ptrsize)
        return {}

    version = _magic_to_version(magic)
    logger.debug("pclntab at VA=0x%x  version=%s  ptrsize=%d", pclntab_va, version, ptrsize)

    try:
        if version == "1.2":
            return _parse_v12(data, ptrsize)
        elif version == "1.16":
            return _parse_v116(data, ptrsize)
        elif version in ("1.18", "1.20"):
            return _parse_v118(data, ptrsize)
        else:
            logger.debug("unsupported pclntab version: %s", version)
            return {}
    except Exception as exc:
        logger.debug("error parsing pclntab: %s", exc, exc_info=True)
        return {}


def find_runtime_functions(pe: pefile.PE, name_tokens) -> Dict[str, int]:
    """
    Return {name: va} for all pclntab functions whose name contains any of
    the case-insensitive name_tokens (e.g "slicebytetostring")
    """
    all_funcs = parse_pclntab(pe)
    lower_tokens = tuple(t.lower() for t in name_tokens)
    result = {}
    for name, va in all_funcs.items():
        if any(tok in name.lower() for tok in lower_tokens):
            result[name] = va
    return result


### pclntab location


def _locate_pclntab(pe: pefile.PE) -> Tuple[int, bytes]:
    """
    Locate pclntab data inside pe

    Strategy:
    1. named section .gopclntab/gopclntab
    2. magic byte scan across all sections, most-recent magic first

    Returns (pclntab_va, bytes_starting_at_pclntab)
    """
    # 1)named section (non-obfuscated binary)
    for section in pe.sections:
        sec_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        if sec_name in (".gopclntab", "gopclntab"):
            va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            data = section.get_data()
            if data and data[:6] in ALL_MAGICS:
                logger.debug("found pclntab via section name '%s'", sec_name)
                return va, data

    # 2)magicbyte scan (stripped / obfuscated binary)
    for magic in ALL_MAGICS:
        for section in pe.sections:
            sec_data = section.get_data()
            idx = sec_data.find(magic)
            if idx == -1:
                continue
            # quantum and ptrsize must be valid
            if len(sec_data) <= idx + 7:
                continue
            quantum = sec_data[idx + 6]
            ptrsize = sec_data[idx + 7]
            if quantum in _VALID_QUANTUM and ptrsize in _VALID_PTRSIZE:
                va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + idx
                logger.debug("found pclntab via magic scan at VA=0x%x", va)
                return va, sec_data[idx:]

    raise ValueError("pclntab not found in any PE section")


### header helpers


def _magic_to_version(magic):
    return {
        MAGIC_V12: "1.2",
        MAGIC_V116: "1.16",
        MAGIC_V118: "1.18",
        MAGIC_V120: "1.20",
    }.get(magic, "unknown")


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _uptr(data, offset, ptrsize):
    fmt = "<I" if ptrsize == 4 else "<Q"
    return struct.unpack_from(fmt, data, offset)[0]


def _cstring(data, offset):
    """Read nullterminated UTF-8 string from data at offset"""
    if offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end == -1:
        return None
    try:
        return data[offset:end].decode("utf-8", errors="replace") or None
    except Exception:
        return None


### Version-specific parsers


def _parse_v12(data, ptrsize) -> Dict[str, int]:
    """
    Parse Go 1.2 1.15 pclntab

    Layout after the 8-byte header:
        nfunctab : uint(ptrsize)
        functab  : nfunctab * 2 * ptrsize   [(va, offset_in_pclntab), ...]
        sentinel : 1 * 2 * ptrsize
        fileoff  : uint32
        filetab  : ...

    Each funcc struct at pclntab[offset]:
        entry   : uintptr
        nameoff : int32     offset into whole pclntab for null-term name
        ...
    """
    if len(data) < 8 + ptrsize:
        return {}

    nfunctab = _uptr(data, 8, ptrsize)
    if nfunctab == 0 or nfunctab > 1_000_000:
        logger.debug("v12: suspicious nfunctab=%d", nfunctab)
        return {}

    functab_start = 8 + ptrsize  # right after nfunctab
    entry_size = 2 * ptrsize  # (va, offset)

    funcs: Dict[str, int] = {}

    for i in range(nfunctab):
        base = functab_start + i * entry_size
        if base + entry_size > len(data):
            break

        func_va = _uptr(data, base, ptrsize)
        funcdata_off = _uptr(data, base + ptrsize, ptrsize)

        # Func struct: [entry:ptrsize][nameoff:uint32]
        nameoff_pos = funcdata_off + ptrsize
        if nameoff_pos + 4 > len(data):
            continue

        nameoff = _u32(data, nameoff_pos)
        name = _cstring(data, nameoff)  # nameoff is into whole pclntab for v12
        if name:
            funcs[name] = func_va

    logger.debug("v12: extracted %d functions", len(funcs))
    return funcs


def _parse_v116(data: bytes, ptrsize: int) -> Dict[str, int]:
    """
    Parse Go 1.16 1.17 pclntab.

    pcHeader layout after the 8-byte magic/quantum/ptrsize bytes:
        nfunctab        : int   (ptrsize bytes)
        nfiletab        : uint  (ptrsize bytes)
        funcnameOffset  : uintptr   offset from pclntab[0] to funcnametab
        cuOffset        : uintptr
        filetabOffset   : uintptr
        pctabOffset     : uintptr
        pclnOffset      : uintptr   offset from pclntab[0] to functab/funcdata

    functab entries (at pclntab[pclnOffset]):
        va              : uintptr
        funcdata_off    : uintptr offset within funcdata region

    Func struct at funcdata[funcdata_off]:
        entry  : uintptr
        nameoff: uint32  offset into funcnametab
    """
    # Minimum header: 8 + 7 * ptrsize
    if len(data) < 8 + 7 * ptrsize:
        return {}

    nfunctab = _uptr(data, 8, ptrsize)
    if nfunctab == 0 or nfunctab > 1_000_000:
        logger.debug("v116: suspicious nfunctab=%d", nfunctab)
        return {}

    # Section offsets (all relative to pclntab start)
    # index: 0=nfunc 1=nfile 2=funcname 3=cu 4=filetab 5=pctab 6=pcln(functab)
    funcname_off = _uptr(data, 8 + 2 * ptrsize, ptrsize)
    pcln_off = _uptr(data, 8 + 6 * ptrsize, ptrsize)  # start of functab/funcdata

    if funcname_off >= len(data) or pcln_off >= len(data):
        return {}

    ffs = ptrsize  # functab field size for 1.16
    entry_size = 2 * ffs
    functabsize = (nfunctab * 2 + 1) * ffs  # includes sentinel

    funcdata = data[pcln_off:]
    functab = funcdata[:functabsize]
    funcnametab = data[funcname_off:]

    funcs: Dict[str, int] = {}

    for i in range(nfunctab):
        base = i * entry_size
        if base + entry_size > len(functab):
            break

        func_va = _uptr(functab, base, ffs)
        funcdata_rel = _uptr(functab, base + ffs, ffs)  # offset within funcdata

        # Func struct: [entry:ptrsize][nameoff:uint32]
        nameoff_pos = funcdata_rel + ptrsize
        if nameoff_pos + 4 > len(funcdata):
            continue

        nameoff = _u32(funcdata, nameoff_pos)
        name = _cstring(funcnametab, nameoff)
        if name:
            funcs[name] = func_va

    logger.debug("v116: extracted %d functions", len(funcs))
    return funcs


def _parse_v118(data: bytes, ptrsize: int) -> Dict[str, int]:
    """
    Parse Go 1.18 1.20+ pclntab.

    Go 1.18 adds a textStart field to pcHeader and changes functab entries
    from pointer-sized to uint32; PC values become textStart + uint32_offset

    pcHeader layout after the 8-byte magic/quantum/ptrsize bytes:
        nfunctab        : uint  (ptrsize bytes)
        nfiletab        : uint  (ptrsize bytes)
        textStart       : uintptr  base VA for PC offsets
        funcnameOffset  : uintptr
        cuOffset        : uintptr
        filetabOffset   : uintptr
        pctabOffset     : uintptr
        pclnOffset      : uintptr  offset from pclntab[0] to functab/funcdata

    functab entries (at pclntab[pclnOffset]) all uint32:
        pc_off      : uint32   <- func_va = textStart + pc_off
        funcdata_off: uint32   <- offset within funcdata region

    Func struct at funcdata[funcdata_off]:
        entry  : uint32
        nameoff: uint32 offset into funcnametab
    """
    # Minimum header: 8 + 8 * ptrsize
    if len(data) < 8 + 8 * ptrsize:
        return {}

    nfunctab = _uptr(data, 8, ptrsize)
    text_start = _uptr(data, 8 + 2 * ptrsize, ptrsize)

    if nfunctab == 0 or nfunctab > 1_000_000:
        logger.debug("v118: suspicious nfunctab=%d", nfunctab)
        return {}

    # index: 0=nfunc 1=nfile 2=textStart 3=funcname 4=cu 5=filetab 6=pctab 7=pcln(functab)
    funcname_off = _uptr(data, 8 + 3 * ptrsize, ptrsize)
    pcln_off = _uptr(data, 8 + 7 * ptrsize, ptrsize)

    if funcname_off >= len(data) or pcln_off >= len(data):
        return {}

    ffs = 4  # uint32 for 1.18+
    entry_size = 2 * ffs
    functabsize = (nfunctab * 2 + 1) * ffs

    funcdata = data[pcln_off:]
    functab = funcdata[:functabsize]
    funcnametab = data[funcname_off:]

    funcs: Dict[str, int] = {}

    for i in range(nfunctab):
        base = i * entry_size
        if base + entry_size > len(functab):
            break

        pc_off = _u32(functab, base)
        funcdata_rel = _u32(functab, base + ffs)

        func_va = text_start + pc_off

        # Func struct: [entry:uint32][nameoff:uint32]
        nameoff_pos = funcdata_rel + ffs  # skip entry field (uint32)
        if nameoff_pos + 4 > len(funcdata):
            continue

        nameoff = _u32(funcdata, nameoff_pos)
        name = _cstring(funcnametab, nameoff)
        if name:
            funcs[name] = func_va

    logger.debug("v118: extracted %d functions", len(funcs))
    return funcs

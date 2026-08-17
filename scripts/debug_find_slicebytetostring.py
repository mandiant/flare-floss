"""
Debug script to tesst/locate runtime.slicebytetostring call sites in a Go binary

Usage:
    python scripts/debug_find_slicebytetostring.py /path/to/binary.exe

Flags:
    --pclntab-only   skip vivisect analysis; only show pclntab symbol table
    --all-funcs      dump every function name recovered from pclntab
    --max N          max callsites to print per callee  (default: 20)
"""

import sys
import logging
import argparse

import pefile
import viv_utils

from floss.language.go.extract import find_slicebytetostring_callsites
from floss.language.go.pclntab import parse_pclntab, find_runtime_functions


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _print_pclntab_info(path: str, all_funcs: bool) -> None:
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception as exc:
        print(f"[pclntab] could not open PE: {exc}")
        return

    funcs = parse_pclntab(pe)
    if not funcs:
        print("[pclntab] no functions recovered (pclntab not found or unparseable)")
        return

    print(f"[pclntab] recovered {len(funcs)} function names from pclntab")

    hits = find_runtime_functions(pe, ("slicebytetostring",))
    if hits:
        print(f"\n[pclntab] slicebytetostring candidates ({len(hits)}):")
        for name, va in sorted(hits.items(), key=lambda x: x[1]):
            print(f"  0x{va:x}  {name}")
    else:
        print("[pclntab] no slicebytetostring symbol found in pclntab")

    if all_funcs:
        print(f"\n[pclntab] all {len(funcs)} recovered functions:")
        for name, va in sorted(funcs.items(), key=lambda x: x[1]):
            print(f"  0x{va:x}  {name}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Locate runtime.slicebytetostring call sites in a Go binary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", help="Path to Go PE binary")
    parser.add_argument(
        "--pclntab-only", action="store_true", help="Only show pclntab symbol table, skip vivisect analysis"
    )
    parser.add_argument("--all-funcs", action="store_true", help="Dump every function name recovered from pclntab")
    parser.add_argument(
        "--max", dest="max_callers", type=int, default=20, help="Max callsites to print per callee (default: 20)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    # Always show pclntab summary first (fast, no vivisect needed)
    _print_pclntab_info(args.path, args.all_funcs)

    if args.pclntab_only:
        return 0

    # Full vivisect analysis
    print(f"\n[vivisect] loading workspace for {args.path} ...")
    try:
        vw = viv_utils.getWorkspace(args.path, should_save=False)
    except Exception as exc:
        print(f"[vivisect] failed to load workspace: {exc}")
        return 1

    try:
        pe = pefile.PE(args.path, fast_load=True)
    except Exception:
        pe = None

    out = find_slicebytetostring_callsites(vw, pe=pe)

    if not out:
        print("[vivisect] no slicebytetostring callsites found")
        return 0

    total = sum(len(v) for v in out.values())
    print(f"\n[vivisect] found {len(out)} callee(s), {total} total callsite(s)\n")

    for callee, callers in sorted(out.items()):
        name = vw.getName(callee) or "<unnamed>"
        print(f"callee: 0x{callee:x}  name={name}  callers={len(callers)}")
        shown = callers[: args.max_callers]
        for va in shown:
            print(f"  0x{va:x}")
        if len(callers) > args.max_callers:
            print(f"  ... and {len(callers) - args.max_callers} more")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())

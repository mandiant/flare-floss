# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

import io
import sys
import textwrap
import collections
from typing import Dict, List, Tuple, Union

from rich import box
from rich.table import Table
from rich.markup import escape
from rich.console import Console

import floss.utils as util
import floss.logging_
from floss.render import Verbosity
from floss.results import AddressType, StackString, TightString, DecodedString, ResultDocument, StringEncoding
from floss.render.sanitize import sanitize

MIN_WIDTH_LEFT_COL = 22
MIN_WIDTH_RIGHT_COL = 82

DISABLED = "Disabled"

logger = floss.logging_.getLogger(__name__)


def heading_style(s: str):
    colored_string = "[cyan]" + escape(s) + "[/cyan]"
    return colored_string


def string_style(s: str):
    colored_string = "[green]" + escape(s) + " [/green]"
    return colored_string


def width(s: str, character_count: int) -> str:
    """pad the given string to at least `character_count`"""
    if len(s) < character_count:
        return s + " " * (character_count - len(s))
    else:
        return s


def render_meta(results: ResultDocument, console, verbose):
    rows: List[Tuple[str, str]] = list()
    if verbose == Verbosity.DEFAULT:
        rows.append((width("file path", MIN_WIDTH_LEFT_COL), width(results.metadata.file_path, MIN_WIDTH_RIGHT_COL)))
    else:
        rows.extend(
            [
                (width("file path", MIN_WIDTH_LEFT_COL), width(results.metadata.file_path, MIN_WIDTH_RIGHT_COL)),
                ("start date", results.metadata.runtime.start_date.strftime("%Y-%m-%d %H:%M:%S")),
                ("runtime", strtime(results.metadata.runtime.total)),
                ("version", results.metadata.version),
                ("imagebase", f"0x{results.metadata.imagebase:x}"),
                ("min string length", f"{results.metadata.min_length}"),
            ]
        )
    rows.append(("extracted strings", ""))
    rows.extend(render_string_type_rows(results))
    if verbose > Verbosity.DEFAULT:
        rows.extend(render_function_analysis_rows(results))

    table = Table(box=box.ASCII2, show_header=False)
    for row in rows:
        table.add_row(str(row[0]), str(row[1]))

    console.print(table)


def render_string_type_rows(results: ResultDocument) -> List[Tuple[str, str]]:
    return [
        (
            " static strings",
            str(len(results.strings.static_strings)) if results.analysis.enable_static_strings else DISABLED,
        ),
        (
            " stack strings",
            str(len(results.strings.stack_strings)) if results.analysis.enable_stack_strings else DISABLED,
        ),
        (
            " tight strings",
            str(len(results.strings.tight_strings)) if results.analysis.enable_tight_strings else DISABLED,
        ),
        (
            " decoded strings",
            str(len(results.strings.decoded_strings)) if results.analysis.enable_decoded_strings else DISABLED,
        ),
    ]


def render_function_analysis_rows(results) -> List[Tuple[str, str]]:
    if results.metadata.runtime.vivisect == 0:
        return [("analyzed functions", DISABLED)]

    rows = [
        ("analyzed functions", ""),
        (" discovered", results.analysis.functions.discovered),
        (" library", results.analysis.functions.library),
    ]
    if results.analysis.enable_stack_strings:
        rows.append((" stack strings", str(results.analysis.functions.analyzed_stack_strings)))
    if results.analysis.enable_tight_strings:
        rows.append((" tight strings", str(results.analysis.functions.analyzed_tight_strings)))
    if results.analysis.enable_decoded_strings:
        rows.append((" decoded strings", str(results.analysis.functions.analyzed_decoded_strings)))
    if results.analysis.functions.decoding_function_scores:
        rows.append(
            (
                "  identified decoding functions\n  (offset and score)",
                textwrap.fill(
                    ", ".join(
                        [
                            f"0x{fva:x} ({d:.3f})"
                            for fva, d in results.analysis.functions.decoding_function_scores.items()
                        ]
                    ),
                    max(len(results.metadata.file_path), MIN_WIDTH_RIGHT_COL),
                ),
            )
        )
    return rows


def strtime(seconds):
    m, s = divmod(seconds, 60)
    return f"{m:02.0f}:{s:02.0f}"


def render_static_substrings(strings, encoding, offset_len, console, verbose, disable_headers):
    if verbose != Verbosity.DEFAULT:
        encoding = heading_style(encoding)
    render_sub_heading(f"FLOSS STATIC STRINGS: {encoding}", len(strings), console, disable_headers)
    for s in strings:
        if verbose == Verbosity.DEFAULT:
            console.print(s.string, markup=False)
        else:
            colored_string = string_style(s.string)
            console.print(f"0x{s.offset:>0{offset_len}x} {colored_string}")
    console.print("\n")


def render_staticstrings(strings, console, verbose, disable_headers):
    render_heading("FLOSS STATIC STRINGS", len(strings), console, verbose, disable_headers)

    ascii_strings = list(filter(lambda s: s.encoding == StringEncoding.ASCII, strings))
    unicode_strings = list(filter(lambda s: s.encoding == StringEncoding.UTF16LE, strings))

    ascii_offset_len = 0
    unicode_offset_len = 0
    if ascii_strings:
        ascii_offset_len = len(f"{ascii_strings[-1].offset}")
    if unicode_strings:
        unicode_offset_len = len(f"{unicode_strings[-1].offset}")
    offset_len = max(ascii_offset_len, unicode_offset_len)

    render_static_substrings(ascii_strings, "ASCII", offset_len, console, verbose, disable_headers)
    render_static_substrings(unicode_strings, "UTF-16LE", offset_len, console, verbose, disable_headers)


def render_stackstrings(
    strings: Union[List[StackString], List[TightString]], console, verbose: bool, disable_headers: bool
):
    if verbose == Verbosity.DEFAULT:
        for s in strings:
            console.print(sanitize(s.string), markup=False)
    else:
        if strings:
            table = Table(
                "Function",
                "Function Offset",
                "Frame Offset",
                "String",
                show_header=not (disable_headers),
                box=box.ASCII2,
                show_edge=False,
            )
            for s in strings:
                table.add_row(
                    util.hex(s.function),
                    util.hex(s.program_counter),
                    util.hex(s.frame_offset),
                    string_style(sanitize(s.string)),
                )

            console.print(table)


def render_decoded_strings(decoded_strings: List[DecodedString], console, verbose, disable_headers):
    """
    Render results of string decoding phase.
    """
    if verbose == Verbosity.DEFAULT:
        for ds in decoded_strings:
            console.print(sanitize(ds.string), markup=False)
    else:
        strings_by_functions: Dict[int, list] = collections.defaultdict(list)
        for ds in decoded_strings:
            strings_by_functions[ds.decoding_routine].append(ds)

        for fva, data in strings_by_functions.items():
            render_sub_heading(" FUNCTION at " + heading_style(f"0x{fva:x}"), len(data), console, disable_headers)
            rows = []
            for ds in data:
                if ds.address_type == AddressType.STACK:
                    offset_string = escape("[stack]")
                elif ds.address_type == AddressType.HEAP:
                    offset_string = escape("[heap]")
                else:
                    offset_string = hex(ds.address or 0)
                rows.append((offset_string, hex(ds.decoded_at), string_style(ds.string)))

            if rows:
                table = Table(
                    "Offset", "Called At", "String", show_header=not (disable_headers), box=box.ASCII2, show_edge=False
                )
                for row in rows:
                    table.add_row(row[0], row[1], row[2])
                console.print(table)
                console.print("\n")


def render_heading(heading, n, console, verbose, disable_headers):
    """
    example::

        ===========================
        ‖ FLOSS TIGHT STRINGS (0) ‖
        ===========================
    """
    if disable_headers:
        return
    style = ""
    if verbose != Verbosity.DEFAULT:
        style = "cyan"
    table = Table(box=box.HORIZONTALS, style=style, show_header=False)
    table.add_row(heading, style=style)
    if verbose == Verbosity.DEFAULT:
        console.print(table)
    else:
        console.print(table)
    console.print()


def render_sub_heading(heading, n, console, disable_headers):
    """
    example::

        +-----------------------------------+
        | FLOSS STATIC STRINGS: ASCII (862) |
        +-----------------------------------+
    """
    if disable_headers:
        return
    table = Table(box=box.ASCII2, show_header=False)
    table.add_row(heading + f" ({n})")
    console.print(table)
    console.print()


def get_color(color):
    if color == "always":
        color_system = "256"
    elif color == "auto":
        color_system = "windows"
    elif color == "never":
        color_system = None
    else:
        raise RuntimeError("unexpected --color value: " + color)

    return color_system


def render(results, verbose, disable_headers, color):
    sys.__stdout__.reconfigure(encoding="utf-8")
    console = Console(file=io.StringIO(), color_system=get_color(color), highlight=False)

    if not disable_headers:
        console.print("\n")
        if verbose == Verbosity.DEFAULT:
            console.print(f"FLARE FLOSS RESULTS (version {results.metadata.version})\n")
        else:
            colored_str = heading_style(f"FLARE FLOSS RESULTS (version {results.metadata.version})\n")
            console.print(colored_str)
        render_meta(results, console, verbose)
        console.print("\n")

    if results.analysis.enable_static_strings:
        render_staticstrings(results.strings.static_strings, console, verbose, disable_headers)
        console.print("\n")

    if results.analysis.enable_stack_strings:
        render_heading("FLOSS STACK STRINGS", len(results.strings.stack_strings), console, verbose, disable_headers)
        render_stackstrings(results.strings.stack_strings, console, verbose, disable_headers)
        console.print("\n")

    if results.analysis.enable_tight_strings:
        render_heading("FLOSS TIGHT STRINGS", len(results.strings.tight_strings), console, verbose, disable_headers)
        render_stackstrings(results.strings.tight_strings, console, verbose, disable_headers)
        console.print("\n")

    if results.analysis.enable_decoded_strings:
        render_heading("FLOSS DECODED STRINGS", len(results.strings.decoded_strings), console, verbose, disable_headers)
        render_decoded_strings(results.strings.decoded_strings, console, verbose, disable_headers)

    console.file.seek(0)
    return console.file.read()

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
import floss.language.identify
from floss.render import Verbosity
from floss.results import (
    AddressType,
    StackString,
    TightString,
    DecodedString,
    ResultDocument,
    StringEncoding,
)
from floss.render.sanitize import sanitize

MIN_WIDTH_LEFT_COL = 22
MIN_WIDTH_RIGHT_COL = 82

DISABLED = "Disabled"

logger = floss.logging_.getLogger(__name__)


def heading_style(s: str):
    """Adds cyan color formatting to a string (likely for headings).

    Args:
        s: The string to be formatted.

    Returns:
        str: The formatted string with color markup.
    """
    colored_string = "[cyan]" + escape(s) + "[/cyan]"
    return colored_string


def string_style(s: str):
    """Adds green color formatting to a string (likely for strings).

    Args:
        s: The string to be formatted.

    Returns:
        str: The formatted string with color markup.
    """
    colored_string = "[green]" + escape(s) + " [/green]"
    return colored_string


def width(s: str, character_count: int) -> str:
    """Pads a string with spaces to a specified length.

    Args:
        s: The string to be padded.
        character_count: The desired length of the string.

    Returns:
        str: The padded string.
    """
    if len(s) < character_count:
        return s + " " * (character_count - len(s))
    else:
        return s


def render_meta(results: ResultDocument, console, verbose):
    """Formats analysis results and metadata for display.

    Prepares metadata extracted from a file and analysis statistics into a structured table-like format. It adjusts the level of detail based on the provided verbosity setting.

    Args:
        results:  A ResultDocument object containing analysis metadata and results.
        console:  An object used for output to the terminal (likely a wrapper).
        verbose: Verbosity level influencing the amount of detail displayed.
    """
    rows: List[Tuple[str, str]] = list()

    lang = f"{results.metadata.language}" if results.metadata.language else ""
    lang_v = (
        f" ({results.metadata.language_version})"
        if results.metadata.language != "unknown" and results.metadata.language_version
        else ""
    )
    lang_s = (
        f" - selected: {results.metadata.language_selected}"
        if results.metadata.language_selected
        else ""
    )
    language_value = f"{lang}{lang_v}{lang_s}"

    if verbose == Verbosity.DEFAULT:
        rows.append(
            (
                width("file path", MIN_WIDTH_LEFT_COL),
                width(results.metadata.file_path, MIN_WIDTH_RIGHT_COL),
            )
        )
        rows.append(("identified language", language_value))
    else:
        rows.extend(
            [
                (
                    width("file path", MIN_WIDTH_LEFT_COL),
                    width(results.metadata.file_path, MIN_WIDTH_RIGHT_COL),
                ),
                (
                    "start date",
                    results.metadata.runtime.start_date.strftime("%Y-%m-%d %H:%M:%S"),
                ),
                ("runtime", strtime(results.metadata.runtime.total)),
                ("version", results.metadata.version),
                ("identified language", language_value),
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
    """Formats analysis results for display.

    Prepares analysis statistics into a structured table-like format.

    Args:
        results: A ResultDocument object containing analysis metadata and results.

    Returns:
        List[Tuple[str, str]]: A list of tuples containing the analysis statistics.
    """
    len_ss = len(results.strings.static_strings)
    len_ls = len(results.strings.language_strings)
    len_chars_ss = sum([len(s.string) for s in results.strings.static_strings])
    len_chars_ls = sum([len(s.string) for s in results.strings.language_strings])
    return [
        (
            " static strings",
            (
                f"{len_ss:>{len(str(len_ss))}} ({len_chars_ss:>{len(str(len_chars_ss))}d} characters)"
                if results.analysis.enable_static_strings
                else DISABLED
            ),
        ),
        (
            "  language strings",
            (
                f"{len_ls:>{len(str(len_ss))}} ({len_chars_ls:>{len(str(len_chars_ss))}d} characters)"
                if results.metadata.language
                else DISABLED
            ),
        ),
        (
            " stack strings",
            (
                str(len(results.strings.stack_strings))
                if results.analysis.enable_stack_strings
                else DISABLED
            ),
        ),
        (
            " tight strings",
            (
                str(len(results.strings.tight_strings))
                if results.analysis.enable_tight_strings
                else DISABLED
            ),
        ),
        (
            " decoded strings",
            (
                str(len(results.strings.decoded_strings))
                if results.analysis.enable_decoded_strings
                else DISABLED
            ),
        ),
    ]


def render_function_analysis_rows(results) -> List[Tuple[str, str]]:
    """Formats function analysis results for display.

    Prepares function analysis statistics into a structured table-like format.

    Args:
        results: A ResultDocument object containing analysis metadata and results.

    Returns:
        List[Tuple[str, str]]: A list of tuples containing the function analysis statistics.
    """
    if results.metadata.runtime.vivisect == 0:
        return [("analyzed functions", DISABLED)]

    rows = [
        ("analyzed functions", ""),
        (" discovered", results.analysis.functions.discovered),
        (" library", results.analysis.functions.library),
    ]
    if results.analysis.enable_stack_strings:
        rows.append(
            (" stack strings", str(results.analysis.functions.analyzed_stack_strings))
        )
    if results.analysis.enable_tight_strings:
        rows.append(
            (" tight strings", str(results.analysis.functions.analyzed_tight_strings))
        )
    if results.analysis.enable_decoded_strings:
        rows.append(
            (
                " decoded strings",
                str(results.analysis.functions.analyzed_decoded_strings),
            )
        )
    if results.analysis.functions.decoding_function_scores:
        rows.append(
            (
                "  identified decoding functions\n  (offset, score, and number of xrefs to)",
                textwrap.fill(
                    ", ".join(
                        [
                            f"0x{fva:x} ({d['score']:.3f}, xrefs_to: {d['xrefs_to']})"
                            for fva, d in results.analysis.functions.decoding_function_scores.items()
                        ]
                    ),
                    max(len(results.metadata.file_path), MIN_WIDTH_RIGHT_COL),
                ),
            )
        )
    return rows


def strtime(seconds):
    """Converts seconds to a human-readable time format.

    Args:
        seconds: The number of seconds to be converted.

    Returns:
        str: The human-readable time format.
    """
    m, s = divmod(seconds, 60)
    return f"{m:02.0f}:{s:02.0f}"


def render_language_strings(
    language,
    language_strings,
    language_strings_missed,
    console,
    verbose,
    disable_headers,
):
    """Displays language-specific strings to the console.

    Sorts the provided strings, optionally displays a heading, and then prints each string to the console. Formatting (e.g., colors) and string sanitation are controlled by verbosity settings.

    Args:
        language:  The programming language the strings are associated with.
        language_strings: A list of extracted strings.
        language_strings_missed:  Potentially a list of strings that were not fully extracted.
        console: An object used for output to the terminal.
        verbose: Verbosity level influencing formatting.
        disable_headers: A flag to suppress the display of headers.
    """
    strings = sorted(language_strings + language_strings_missed, key=lambda s: s.offset)
    render_heading(
        f"FLOSS {language.upper()} STRINGS ({len(strings)})",
        console,
        verbose,
        disable_headers,
    )
    offset_len = len(f"{strings[-1].offset}")
    for s in strings:
        if verbose == Verbosity.DEFAULT:
            console.print(sanitize(s.string, is_ascii_only=False), markup=False)
        else:
            colored_string = string_style(sanitize(s.string, is_ascii_only=False))
            console.print(f"0x{s.offset:>0{offset_len}x} {colored_string}")


def render_static_substrings(
    strings, encoding, offset_len, console, verbose, disable_headers
):
    """Displays static strings with their encoding information to the console.

    Optionally displays a heading, and then prints each string with its offset to the console. Formatting of strings is influenced by verbosity settings.

    Args:
        strings: A list of static strings.
        encoding: The encoding type of the strings.
        offset_len:  The length of the offset field for formatting.
        console: An object used for output to the terminal.
        verbose: Verbosity level influencing formatting.
        disable_headers: A flag to suppress the display of headers.
    """
    if verbose != Verbosity.DEFAULT:
        encoding = heading_style(encoding)
    render_sub_heading(
        f"FLOSS STATIC STRINGS: {encoding}", len(strings), console, disable_headers
    )
    for s in strings:
        if verbose == Verbosity.DEFAULT:
            console.print(sanitize(s.string), markup=False)
        else:
            colored_string = string_style(sanitize(s.string))
            console.print(f"0x{s.offset:>0{offset_len}x} {colored_string}")


def render_staticstrings(strings, console, verbose, disable_headers):
    """Displays static strings to the console.

    Sorts the provided strings, optionally displays a heading, and then prints each string to the console. Formatting (e.g., colors) and string sanitation are controlled by verbosity settings.

    Args:
        strings: A list of extracted strings.
        console: An object used for output to the terminal.
        verbose: Verbosity level influencing formatting.
        disable_headers: A flag to suppress the display of headers.
    """
    render_heading(
        f"FLOSS STATIC STRINGS ({len(strings)})", console, verbose, disable_headers
    )

    ascii_strings = list(filter(lambda s: s.encoding == StringEncoding.ASCII, strings))
    unicode_strings = list(
        filter(lambda s: s.encoding == StringEncoding.UTF16LE, strings)
    )

    ascii_offset_len = 0
    unicode_offset_len = 0
    if ascii_strings:
        ascii_offset_len = len(f"{ascii_strings[-1].offset}")
    if unicode_strings:
        unicode_offset_len = len(f"{unicode_strings[-1].offset}")
    offset_len = max(ascii_offset_len, unicode_offset_len)

    render_static_substrings(
        ascii_strings, "ASCII", offset_len, console, verbose, disable_headers
    )
    console.print("\n")
    render_static_substrings(
        unicode_strings, "UTF-16LE", offset_len, console, verbose, disable_headers
    )


def render_stackstrings(
    strings: Union[List[StackString], List[TightString]],
    console,
    verbose: bool,
    disable_headers: bool,
):
    """Renders the results of the stack string extraction phase.

    Optionally displays a heading, and then prints each string with its offset to the console. Formatting of strings is influenced by verbosity settings.

    Args:
        strings: A list of extracted strings.
        console: An object used for output to the terminal.
        verbose: Verbosity level influencing formatting.
        disable_headers: A flag to suppress the display of headers.
    """
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


def render_decoded_strings(
    decoded_strings: List[DecodedString], console, verbose, disable_headers
):
    """Renders the results of the string decoding phase.

    Optionally displays a heading, and then prints each string with its offset to the console. Formatting of strings is influenced by verbosity settings.

    Args:
        decoded_strings: A list of extracted strings.
        console: An object used for output to the terminal.
        verbose: Verbosity level influencing formatting.
        disable_headers: A flag to suppress the display of headers.
    """
    if verbose == Verbosity.DEFAULT:
        for ds in decoded_strings:
            console.print(sanitize(ds.string), markup=False)
    else:
        strings_by_functions: Dict[int, list] = collections.defaultdict(list)
        for ds in decoded_strings:
            strings_by_functions[ds.decoding_routine].append(ds)

        for fva, data in strings_by_functions.items():
            render_sub_heading(
                " FUNCTION at " + heading_style(f"0x{fva:x}"),
                len(data),
                console,
                disable_headers,
            )
            rows = []
            for ds in data:
                if ds.address_type == AddressType.STACK:
                    offset_string = escape("[stack]")
                elif ds.address_type == AddressType.HEAP:
                    offset_string = escape("[heap]")
                else:
                    offset_string = hex(ds.address or 0)
                rows.append(
                    (
                        offset_string,
                        hex(ds.decoded_at),
                        string_style(sanitize(ds.string)),
                    )
                )

            if rows:
                table = Table(
                    "Offset",
                    "Called At",
                    "String",
                    show_header=not (disable_headers),
                    box=box.ASCII2,
                    show_edge=False,
                )
                for row in rows:
                    table.add_row(row[0], row[1], row[2])
                console.print(table)
                console.print("\n")


def render_heading(heading, console, verbose, disable_headers):
    """example::

         ─────────────────────────
          FLOSS TIGHT STRINGS (0)
         ─────────────────────────
    Displays a prominent heading for a section of the report.

    Constructs a single-row table with horizontal borders to visually distinguish a heading.  Formatting (e.g., color) is influenced by the verbosity setting.

    Args:
        heading: The text of the heading.
        console: An object used for output to the terminal.
        verbose: Verbosity level influencing formatting.
        disable_headers: A flag to suppress the display of the heading entirely.
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
    """example::

        +-----------------------------------+
        | FLOSS STATIC STRINGS: ASCII (862) |
        +-----------------------------------+

    Displays a subheading with a count for a section of the report.

    Constructs a single-row table with more prominent borders than the primary heading, visually differentiating a subheading.  Includes a count associated with the section.

    Args:
        heading: The text of the subheading.
        n: The count associated with the section.
        console: An object used for output to the terminal.
        disable_headers: A flag to suppress the display of the subheading entirely.
    """
    if disable_headers:
        return
    table = Table(box=box.ASCII2, show_header=False)
    table.add_row(heading + f" ({n})")
    console.print(table)
    console.print()


def get_color(color):
    """Converts a string color setting to a rich color system.

    Args:
        color: A string representing a color setting.

    Returns:
        str: A string representing a rich color system.
    """
    if color == "always":
        color_system = "256"
    elif color == "auto":
        color_system = "windows"
    elif color == "never":
        color_system = None
    else:
        raise RuntimeError("unexpected --color value: " + color)

    return color_system


def render(results: floss.results.ResultDocument, verbose, disable_headers, color):
    """Renders analysis results to a string.

    Args:
        results: A ResultDocument object containing analysis metadata and results.
        verbose: Verbosity level influencing the amount of detail displayed.
        disable_headers: A flag to suppress the display of headers.
        color: A string representing a color setting.

    Returns:
        str: A string containing the formatted analysis results.
    """
    sys.__stdout__.reconfigure(encoding="utf-8")
    console = Console(
        file=io.StringIO(),
        color_system=get_color(color),
        highlight=False,
        soft_wrap=True,
    )

    if not disable_headers:
        console.print("\n")
        if verbose == Verbosity.DEFAULT:
            console.print(f"FLARE FLOSS RESULTS (version {results.metadata.version})\n")
        else:
            colored_str = heading_style(
                f"FLARE FLOSS RESULTS (version {results.metadata.version})\n"
            )
            console.print(colored_str)
        render_meta(results, console, verbose)
        console.print("\n")

    if results.analysis.enable_static_strings:
        render_staticstrings(
            results.strings.static_strings, console, verbose, disable_headers
        )
        console.print("\n")

    if results.metadata.language in (
        floss.language.identify.Language.GO.value,
        floss.language.identify.Language.RUST.value,
    ):
        render_language_strings(
            results.metadata.language,
            results.strings.language_strings,
            results.strings.language_strings_missed,
            console,
            verbose,
            disable_headers,
        )
        console.print("\n")

    if results.analysis.enable_stack_strings:
        render_heading(
            f"FLOSS STACK STRINGS ({len(results.strings.stack_strings)})",
            console,
            verbose,
            disable_headers,
        )
        render_stackstrings(
            results.strings.stack_strings, console, verbose, disable_headers
        )
        console.print("\n")

    if results.analysis.enable_tight_strings:
        render_heading(
            f"FLOSS TIGHT STRINGS ({len(results.strings.tight_strings)})",
            console,
            verbose,
            disable_headers,
        )
        render_stackstrings(
            results.strings.tight_strings, console, verbose, disable_headers
        )
        console.print("\n")

    if results.analysis.enable_decoded_strings:
        render_heading(
            f"FLOSS DECODED STRINGS ({len(results.strings.decoded_strings)})",
            console,
            verbose,
            disable_headers,
        )
        render_decoded_strings(
            results.strings.decoded_strings, console, verbose, disable_headers
        )

    console.file.seek(0)
    return console.file.read()

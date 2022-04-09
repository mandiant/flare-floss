import io
import textwrap
import collections
from enum import Enum
from typing import List, Tuple, Union

import tabulate

import floss.logging_
from floss.utils import hex
from floss.results import AddressType, StackString, TightString, DecodedString, ResultDocument, StringEncoding
from floss.render.sanitize import sanitize

MIN_WIDTH_LEFT_COL = 22
MIN_WIDTH_RIGHT_COL = 82

DISABLED = "Disabled"

tabulate.PRESERVE_WHITESPACE = True

logger = floss.logging_.getLogger(__name__)


class Verbosity(int, Enum):
    DEFAULT = 0
    VERBOSE = 1


class StringIO(io.StringIO):
    def writeln(self, s):
        self.write(s)
        self.write("\n")


def width(s: str, character_count: int) -> str:
    """pad the given string to at least `character_count`"""
    if len(s) < character_count:
        return s + " " * (character_count - len(s))
    else:
        return s


def render_meta(results: ResultDocument, ostream, verbose):
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
            ]
        )
    rows.append(("extracted strings", ""))
    rows.extend(render_string_type_rows(results))
    if verbose > Verbosity.DEFAULT:
        rows.extend(render_function_analysis_rows(results))
    ostream.write(tabulate.tabulate(rows, tablefmt="psql"))

    ostream.write("\n")


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


def render_staticstrings(strings, ostream, verbose, disable_headers):
    render_heading("FLOSS STATIC STRINGS", len(strings), ostream, disable_headers)

    ascii_strings = list(filter(lambda s: s.encoding == StringEncoding.ASCII, strings))
    unicode_strings = list(filter(lambda s: s.encoding == StringEncoding.UTF16LE, strings))

    ascii_offset_len = 0
    unicode_offset_len = 0
    if ascii_strings:
        ascii_offset_len = len(f"{ascii_strings[-1].offset}")
    if unicode_strings:
        unicode_offset_len = len(f"{unicode_strings[-1].offset}")
    offset_len = max(ascii_offset_len, unicode_offset_len)

    render_heading("FLOSS ASCII STRINGS", len(ascii_strings), ostream, disable_headers)
    for s in ascii_strings:
        if verbose == Verbosity.DEFAULT:
            ostream.writeln(s.string)
        else:
            ostream.writeln(f"0x{s.offset:>0{offset_len}x} {s.string}")
    ostream.writeln("")

    render_heading("FLOSS UTF-16LE STRINGS", len(unicode_strings), ostream, disable_headers)
    for s in unicode_strings:
        if verbose == Verbosity.DEFAULT:
            ostream.writeln(s.string)
        else:
            ostream.writeln(f"0x{s.offset:>0{offset_len}x} {s.string}")


def render_stackstrings(
    strings: Union[List[StackString], List[TightString]], ostream, verbose: bool, disable_headers: bool
):
    if verbose == Verbosity.DEFAULT:
        for s in strings:
            ostream.writeln(sanitize(s.string))
    else:
        if strings:
            ostream.write(
                tabulate.tabulate(
                    [
                        (hex(s.function), hex(s.program_counter), hex(s.frame_offset), sanitize(s.string))
                        for s in strings
                    ],
                    headers=("Function", "Function Offset", "Frame Offset", "String") if not disable_headers else (),
                )
            )
            ostream.write("\n")


def render_decoded_strings(decoded_strings: List[DecodedString], ostream, verbose, disable_headers):
    """
    Render results of string decoding phase.
    """
    if verbose == Verbosity.DEFAULT:
        for ds in decoded_strings:
            ostream.writeln(sanitize(ds.string))
    else:
        strings_by_functions = collections.defaultdict(list)
        for ds in decoded_strings:
            strings_by_functions[ds.decoding_routine].append(ds)

        for fva, data in strings_by_functions.items():
            render_heading(f" FUNCTION at 0x{fva:x}", len(data), ostream, disable_headers)
            rows = []
            for ds in data:
                if ds.address_type in (AddressType.HEAP, AddressType.STACK):
                    offset_string = f"({ds.address_type})"
                else:
                    offset_string = hex(ds.address or 0)
                rows.append((offset_string, hex(ds.decoded_at), sanitize(ds.string)))

            if rows:
                ostream.write(
                    tabulate.tabulate(rows, headers=("Offset", "Called At", "String") if not disable_headers else ())
                )
                ostream.writeln("\n")


def render_heading(heading, n, ostream, disable_headers):
    """
    example::

        -------------------------------
        | FLOSS STATIC STRINGS (1337) |
        -------------------------------
    """
    if disable_headers:
        return
    heading = f"| {heading} ({n}) |"
    ostream.write(tabulate.tabulate([[heading]]))
    ostream.write("\n")


def render(results, verbose, disable_headers):
    ostream = StringIO()

    if not disable_headers:
        ostream.writeln("")
        ostream.write(f"FLARE FLOSS RESULTS (version {results.metadata.version})\n")
        render_meta(results, ostream, verbose)
        ostream.writeln("")

    if results.analysis.enable_static_strings:
        render_staticstrings(results.strings.static_strings, ostream, verbose, disable_headers)
        ostream.writeln("")

    if results.analysis.enable_stack_strings:
        render_heading("FLOSS STACK STRINGS", len(results.strings.stack_strings), ostream, disable_headers)
        render_stackstrings(results.strings.stack_strings, ostream, verbose, disable_headers)
        ostream.writeln("")

    if results.analysis.enable_tight_strings:
        render_heading("FLOSS TIGHT STRINGS", len(results.strings.tight_strings), ostream, disable_headers)
        render_stackstrings(results.strings.tight_strings, ostream, verbose, disable_headers)
        ostream.writeln("")

    if results.analysis.enable_decoded_strings:
        render_heading("FLOSS DECODED STRINGS", len(results.strings.decoded_strings), ostream, disable_headers)
        render_decoded_strings(results.strings.decoded_strings, ostream, verbose, disable_headers)

    return ostream.getvalue()

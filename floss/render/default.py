# Copyright 2022 Google LLC
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


import io
import sys
import json
import textwrap
import collections
from typing import Dict, List, Tuple, Union, Optional, Sequence

from rich import box
from rich.text import Text
from rich.style import Style
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
    ResultLayout,
    ResultString,
    DecodedString,
    ResultDocument,
    StringEncoding,
)
from floss.tags.filter import TagRules, hide_strings_by_rules
from floss.render.filter import LayoutFilter
from floss.render.sanitize import sanitize

MIN_WIDTH_LEFT_COL = 22
MIN_WIDTH_RIGHT_COL = 82

DISABLED = "Disabled"

logger = floss.logging_.getLogger(__name__)

DEFAULT_TAG_RULES: TagRules = {
    "#capa": "highlight",
    "#common": "mute",
    "#duplicate": "mute",
    "#code": "hide",
    "#reloc": "hide",
}

# columns available in the layout view; controlled by --columns
COLUMN_CHOICES = ("tags", "offset", "structure", "encoding")
DEFAULT_COLUMNS = ("tags", "offset")

# layout-text rendering constants
MUTED_STYLE = Style(color="gray50")
DEFAULT_STYLE = Style()
HIGHLIGHT_STYLE = Style(color="yellow")

PADDING_WIDTH = 2
OFFSET_WIDTH = 8
STRUCTURE_WIDTH = 20


def Span(text: str, style: Style = DEFAULT_STYLE) -> Text:
    """convenience function for single-line, styled text region"""
    return Text(text, style=style, no_wrap=True, overflow="ellipsis", end="")


def render_string_padding():
    return Span(" " * PADDING_WIDTH)


def compute_string_style(s: ResultString, tag_rules: TagRules) -> Optional[Style]:
    """compute the style for a string based on its tags

    returns: Style, or None if the string should be hidden.
    """
    styles = set(tag_rules.get(tag, "mute") for tag in s.tags)

    # precedence:
    #
    #  1. highlight
    #  2. hide
    #  3. mute
    #  4. default
    if "highlight" in styles:
        return HIGHLIGHT_STYLE
    elif "hide" in styles:
        return None
    elif "mute" in styles:
        return MUTED_STYLE
    else:
        return DEFAULT_STYLE


def render_string_string(s: ResultString, tag_rules: TagRules) -> Text:
    string_style = compute_string_style(s, tag_rules)
    if string_style is None:
        raise ValueError("string should be hidden")

    # render like json, but strip the leading/trailing quote marks.
    # this means that whitespace characters like \t and \n will be rendered as such,
    # which ensures that the rendered string will be a single line.
    rendered_string = json.dumps(s.string)[1:-1]
    if "\\t" in rendered_string:
        rendered_string = rendered_string.replace("\\t", "    ")
    return Span(rendered_string, style=string_style)


def get_visible_tags(s: ResultString) -> tuple:
    """compute the tuple of visible tag names for a string, in sorted order.

    this applies the same filtering as render_string_tags
    (e.g. removing #common when there are other tags).
    the result can be compared across strings to detect tag groups.
    """
    tags = list(s.tags)
    if len(tags) != 1 and "#common" in tags:
        tags.remove("#common")
    return tuple(sorted(tags))


def render_string_tags(s: ResultString, tag_rules: TagRules, is_group_start: bool = False):
    ret = Text()

    tags = list(s.tags)
    if len(tags) != 1 and "#common" in tags:
        # don't show #common if there are other tags,
        # because the other tags will be more specific (like library names).
        tags.remove("#common")

    for i, tag in enumerate(sorted(tags)):
        tag_style = DEFAULT_STYLE
        rule = tag_rules.get(tag, "mute")
        if rule == "highlight":
            tag_style = HIGHLIGHT_STYLE
        elif rule == "mute":
            tag_style = MUTED_STYLE
        elif rule == "default":
            tag_style = DEFAULT_STYLE
        else:
            raise ValueError(f"unknown tag rule: {rule}")

        ret.append_text(Span(tag, style=tag_style))
        if i < len(tags) - 1:
            ret.append_text(Span(" "))

    if is_group_start:
        ret.append_text(Span(" ┓", style=MUTED_STYLE))
    else:
        # reserve same width as " ┓" so tags stay aligned
        ret.append_text(Span("  "))

    return ret


def render_string_tags_continuation(tags_width: int, is_group_end: bool = False) -> Text:
    """render a continuation indicator instead of repeating tag text.

    the character is right-aligned in the given width to line up with the ┓.
    on the last line of a group, render ┛ as a terminator.
    """
    if tags_width == 0:
        return Span("")
    if is_group_end:
        left_pad = tags_width - 1
        bar = Span(" " * left_pad + "┛", style=MUTED_STYLE)
    else:
        left_pad = tags_width - 1
        bar = Span(" " * left_pad + "┃", style=MUTED_STYLE)
    return bar


def render_string_offset(s: ResultString):
    # render the 000 prefix of the 8-digit offset in muted gray
    # and the non-zero suffix as blue.
    offset_chars = f"{s.offset:08x}"
    unpadded = offset_chars.lstrip("0")
    padding_width = len(offset_chars) - len(unpadded)

    offset = Span("")
    offset.append_text(Span("0" * padding_width, style=MUTED_STYLE))
    offset.append_text(Span(unpadded, style=DEFAULT_STYLE))

    return offset


def render_string_structure(s: ResultString):
    ret = Text()

    if s.structure:
        structure = Span(s.structure, style=Style(color="blue"))
        structure.align("left", STRUCTURE_WIDTH - 1)
        ret.append(Span("/", style=MUTED_STYLE))
        ret.append(structure)
    else:
        ret.append_text(Span(" " * STRUCTURE_WIDTH))

    return ret


def render_string(
    width: int,
    s: ResultString,
    tag_rules: TagRules,
    columns: Sequence[str] = DEFAULT_COLUMNS,
    prev_tags: Optional[tuple] = None,
    prev_tags_width: int = 0,
    is_group_end: bool = False,
    is_group_start: bool = False,
) -> Text:
    #
    #  | stringstringstring              #tag #tag #tag  00000001 |
    #  | stringstring                              #tag  0000004A |
    #  | string                                       │  00000050 |
    #  | stringstringstringstringstringst...  #tag #tag  0000005E |
    #    ^                                  ^ ^        ^ ^
    #    |                                  | |        | offset
    #    |                                  | |        padding
    #    |                                  | tags (or │ continuation)
    #    |                                  padding
    #    string
    #
    #    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^
    #    left column                       right column
    #
    # fields are basically laid out from right to left,
    # which means that the metadata may cause a string to be clipped.
    #
    # field sizes:
    #   structure: 8
    #   padding: 2
    #   offset: 8
    #   padding: 2
    #   tags: variable, or 0
    #   padding: 2
    #   string: variable

    left = render_string_string(s, tag_rules)

    visible_tags = get_visible_tags(s)
    use_continuation = (
        "tags" in columns and prev_tags is not None and visible_tags == prev_tags and len(visible_tags) > 0
    )

    right = Span("")
    if "tags" in columns:
        right.append_text(render_string_padding())
        if use_continuation:
            right.append_text(render_string_tags_continuation(prev_tags_width, is_group_end=is_group_end))
        else:
            right.append_text(render_string_tags(s, tag_rules, is_group_start=is_group_start))
    if "offset" in columns:
        right.append_text(render_string_padding())
        # indicate encoding: ascii implicit default
        if "encoding" in columns:
            right.append_text(Span("U " if s.encoding == "unicode" else "  "))
        right.append_text(render_string_offset(s))
    if "structure" in columns:
        right.append_text(render_string_structure(s))

    # this alignment clips the string if it's too long,
    # leaving an ellipsis at the end when it would collide with a tag/offset.
    # this is bad for showing all data verbatim,
    # but is good for the common case of triage analysis.
    left.align("left", width - len(right))

    line = Text()
    line.append_text(left)
    line.append_text(right)

    return line


def has_visible_children(layout: ResultLayout) -> bool:
    return any(map(is_visible, layout.children))


def is_visible(layout: ResultLayout) -> bool:
    "a layout is visible if it has any strings (or its children do)"
    return bool(layout.strings) or has_visible_children(layout)


def has_visible_predecessors(parent: ResultLayout | None, child_index: int | None) -> bool:
    if parent is None or child_index is None:
        # root node
        return False

    for i in range(child_index):
        if is_visible(parent.children[i]):
            return True
    return False


def has_visible_successors(parent: ResultLayout | None, child_index: int | None) -> bool:
    if parent is None or child_index is None:
        # root node
        return False

    for i in range(child_index + 1, len(parent.children)):
        if is_visible(parent.children[i]):
            return True
    return False


def render_strings(
    console: Console,
    layout: ResultLayout,
    tag_rules: TagRules,
    depth: int = 0,
    name_hint: Optional[str] = None,
    parent: Optional[ResultLayout] = None,
    child_index: Optional[int] = None,
    columns: Sequence[str] = DEFAULT_COLUMNS,
):
    if not is_visible(layout):
        return

    if (
        len(layout.children) == 1
        and layout.offset == layout.children[0].offset
        and layout.length == layout.children[0].length
    ):
        # when a layout is completely dominated by its single child
        # then we can directly render the child,
        # retaining just a hint of the parent's name.
        #
        # for example:
        #
        #     rsrc: BINARY/102/0 (pe)
        return render_strings(
            console,
            layout.children[0],
            tag_rules,
            depth,
            name_hint=layout.name,
            parent=parent,
            child_index=child_index,
            columns=columns,
        )

    BORDER_STYLE = MUTED_STYLE

    name = layout.name
    if name_hint:
        name = f"{name_hint} ({name})"

    header = Span(name, style=BORDER_STYLE)
    header.pad(1)
    header.align("center", width=console.width, character="─")

    # box is muted color
    # name of section is blue
    name_offset = header.plain.index(" ") + 1
    header.stylize(Style(color="blue"), name_offset, name_offset + len(name))

    if not has_visible_predecessors(parent, child_index):
        header_shape = "┐"
    else:
        header_shape = "┤"

    header.remove_suffix("─" * (depth + 1))
    header.append_text(Span(header_shape, style=BORDER_STYLE))
    header.append_text(Span("│" * depth, style=BORDER_STYLE))

    console.print(header)

    def render_string_lines(console: Console, tag_rules: TagRules, strings: list, depth: int):
        """render a batch of strings, grouping consecutive strings with the same tags."""
        prev_tags = None
        prev_tags_width = 0
        for idx, string in enumerate(strings):
            visible_tags = get_visible_tags(string)

            # lookahead: is this the last line in a continuation group?
            is_group_end = False
            if prev_tags is not None and visible_tags == prev_tags and len(visible_tags) > 0:
                # we are in a continuation — check if the next string breaks the group
                if idx + 1 >= len(strings):
                    is_group_end = True
                else:
                    next_tags = get_visible_tags(strings[idx + 1])
                    if next_tags != visible_tags:
                        is_group_end = True

            # lookahead: is this the first line of a continuation group?
            is_group_start = False
            if (prev_tags is None or visible_tags != prev_tags) and len(visible_tags) > 0:
                if idx + 1 < len(strings):
                    next_tags = get_visible_tags(strings[idx + 1])
                    if next_tags == visible_tags:
                        is_group_start = True

            line = render_string(
                console.width,
                string,
                tag_rules,
                columns=columns,
                prev_tags=prev_tags,
                prev_tags_width=prev_tags_width,
                is_group_end=is_group_end,
                is_group_start=is_group_start,
            )
            # TODO: this truncates the structure column
            line = line[: -depth - 1]
            line.append_text(Span("│" * (depth + 1), style=BORDER_STYLE))
            console.print(line)

            # track for next iteration
            if visible_tags != prev_tags:
                # tags changed — compute the rendered width for continuation bars
                prev_tags = visible_tags
                prev_tags_width = (
                    len(render_string_tags(string, tag_rules, is_group_start=is_group_start))
                    if "tags" in columns
                    else 0
                )

    if not layout.children:
        # for string in layout.strings[:4]:
        render_string_lines(console, tag_rules, layout.strings, depth)

    else:
        for i, child in enumerate(layout.children):
            if i == 0:
                # render strings before first child
                strings_before_child = list(filter(lambda s: layout.offset <= s.offset < child.offset, layout.strings))
            else:
                # render strings between children
                last_child = layout.children[i - 1]
                strings_before_child = list(filter(lambda s: last_child.end < s.offset < child.offset, layout.strings))

            # for string in strings_before_child[:4]:
            render_string_lines(console, tag_rules, strings_before_child, depth)

            render_strings(console, child, tag_rules, depth + 1, parent=layout, child_index=i, columns=columns)

        # render strings after last child
        strings_after_children = list(filter(lambda s: child.end < s.offset < layout.end, layout.strings))
        # for string in strings_after_children[:4]:
        render_string_lines(console, tag_rules, strings_after_children, depth)

    if not has_visible_successors(parent, child_index):
        footer = Span("", style=BORDER_STYLE)
        footer.align("center", width=console.width, character="─")

        footer.remove_suffix("─" * (depth + 1))
        footer.append_text(Span("┘", style=BORDER_STYLE))
        footer.append_text(Span("│" * depth, style=BORDER_STYLE))

        console.print(footer)


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

    lang = f"{results.metadata.language}" if results.metadata.language else ""
    lang_v = (
        f" ({results.metadata.language_version})"
        if results.metadata.language != "unknown" and results.metadata.language_version
        else ""
    )
    lang_s = f" - selected: {results.metadata.language_selected}" if results.metadata.language_selected else ""
    language_value = f"{lang}{lang_v}{lang_s}"

    if verbose == Verbosity.DEFAULT:
        rows.append((width("file path", MIN_WIDTH_LEFT_COL), width(results.metadata.file_path, MIN_WIDTH_RIGHT_COL)))
        if results.metadata.sha256:
            rows.append(("sha256", results.metadata.sha256))
        rows.append(("identified language", language_value))
    else:
        rows.extend(
            [
                (width("file path", MIN_WIDTH_LEFT_COL), width(results.metadata.file_path, MIN_WIDTH_RIGHT_COL)),
            ]
        )
        if results.metadata.md5:
            rows.append(("md5", results.metadata.md5))
        if results.metadata.sha1:
            rows.append(("sha1", results.metadata.sha1))
        if results.metadata.sha256:
            rows.append(("sha256", results.metadata.sha256))
        rows.extend(
            [
                ("start date", results.metadata.runtime.start_date.strftime("%Y-%m-%d %H:%M:%S")),
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
    len_ss = len(results.strings.static_strings)
    len_ls = len(results.strings.language_strings)
    len_chars_ss = sum(len(s.string) for s in results.strings.static_strings)
    len_chars_ls = sum(len(s.string) for s in results.strings.language_strings)
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
    m, s = divmod(seconds, 60)
    return f"{m:02.0f}:{s:02.0f}"


def render_language_strings(language, language_strings, language_strings_missed, console, verbose, disable_headers):
    strings = sorted(language_strings + language_strings_missed, key=lambda s: s.offset)
    render_heading(f"FLOSS {language.upper()} STRINGS ({len(strings)})", console, verbose, disable_headers)
    if not strings:
        logger.info("no %s strings found", language)
        return

    offset_len = len(f"{strings[-1].offset}")
    for s in strings:
        if verbose == Verbosity.DEFAULT:
            console.print(sanitize(s.string, is_ascii_only=False), markup=False)
        else:
            colored_string = string_style(sanitize(s.string, is_ascii_only=False))
            console.print(f"0x{s.offset:>0{offset_len}x} {colored_string}")


def render_static_substrings(strings, encoding, offset_len, console, verbose, disable_headers):
    if verbose != Verbosity.DEFAULT:
        encoding = heading_style(encoding)
    render_sub_heading(f"FLOSS STATIC STRINGS: {encoding}", len(strings), console, disable_headers)
    for s in strings:
        if verbose == Verbosity.DEFAULT:
            console.print(sanitize(s.string), markup=False)
        else:
            colored_string = string_style(sanitize(s.string))
            console.print(f"0x{s.offset:>0{offset_len}x} {colored_string}")


def render_staticstrings(strings, console, verbose, disable_headers):
    render_heading(f"FLOSS STATIC STRINGS ({len(strings)})", console, verbose, disable_headers)

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
    console.print("\n")
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
                rows.append((offset_string, hex(ds.decoded_at), string_style(sanitize(ds.string))))

            if rows:
                table = Table(
                    "Offset", "Called At", "String", show_header=not (disable_headers), box=box.ASCII2, show_edge=False
                )
                for row in rows:
                    table.add_row(row[0], row[1], row[2])
                console.print(table)
                console.print("\n")


def render_heading(heading, console, verbose, disable_headers):
    """
    example::

         ─────────────────────────
          FLOSS TIGHT STRINGS (0)
         ─────────────────────────
    """
    if disable_headers:
        return
    style = ""
    if verbose != Verbosity.DEFAULT:
        style = "cyan"
    table = Table(box=box.HORIZONTALS, style=style, show_header=False)
    table.add_row(heading, style=style)
    console.print(table)
    console.print()


def render_section_heading(name, console, verbose, disable_headers):
    """centered lowercase heading for recovered-string sections, in the same
    style as the layout section headings: a horizontal line above and below.

    example::

         ─────────────────────
               stack strings
         ─────────────────────
    """
    if disable_headers:
        return
    style = ""
    if verbose != Verbosity.DEFAULT:
        style = "cyan"

    line = Text("─" * console.width, style=style)
    heading = Text(name.center(console.width), style=style)
    console.print(line)
    console.print(heading)
    console.print(line)
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


def render(
    results: floss.results.ResultDocument,
    verbose,
    disable_headers,
    color,
    columns: Sequence[str] = DEFAULT_COLUMNS,
    layout_filter: Optional[LayoutFilter] = None,
):
    sys.__stdout__.reconfigure(encoding="utf-8")  # type: ignore [union-attr]
    console = Console(file=io.StringIO(), color_system=get_color(color), highlight=False, soft_wrap=True)

    # layout-aware path: no classic meta table
    if results.layout is not None and results.analysis.enable_static_strings:
        layout = results.layout
        if layout_filter is not None and layout_filter.active:
            filtered = layout_filter.apply(layout)
            if filtered is None:
                # filters removed every string; render nothing for statics
                layout = ResultLayout(name=layout.name, offset=layout.offset, length=layout.length)
            else:
                layout = filtered
        layout_view = hide_strings_by_rules(layout, DEFAULT_TAG_RULES)
        render_strings(console, layout_view, DEFAULT_TAG_RULES, columns=columns)
        console.print()
    else:
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

    # recovered strings always after static/language (classic blocks).
    # show the section whenever the mode is enabled, including count 0.
    if results.analysis.enable_stack_strings:
        render_section_heading(
            f"stack strings ({len(results.strings.stack_strings)})", console, verbose, disable_headers
        )
        render_stackstrings(results.strings.stack_strings, console, verbose, disable_headers)
        console.print("\n")

    if results.analysis.enable_tight_strings:
        render_section_heading(
            f"tight strings ({len(results.strings.tight_strings)})", console, verbose, disable_headers
        )
        render_stackstrings(results.strings.tight_strings, console, verbose, disable_headers)
        console.print("\n")

    if results.analysis.enable_decoded_strings:
        render_section_heading(
            f"decoded strings ({len(results.strings.decoded_strings)})", console, verbose, disable_headers
        )
        render_decoded_strings(results.strings.decoded_strings, console, verbose, disable_headers)

    console.file.seek(0)
    return console.file.read()

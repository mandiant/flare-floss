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

"""Rich text rendering of layout-aware string results.

This module renders the serializable ``ResultLayout`` tree produced by the
layout-aware static analysis, including tags, offsets, structures, and the
tree headers/footers.
"""

from __future__ import annotations

import json
from typing import Optional, Sequence

from rich.text import Text
from rich.style import Style
from rich.console import Console

from floss.results import ResultLayout, ResultString
from floss.tags.filter import TagRules

# columns available in the layout view; controlled by --columns
COLUMN_CHOICES = ("tags", "offset", "structure", "encoding")
DEFAULT_COLUMNS = ("tags", "offset")

MUTED_STYLE = Style(color="gray50")
DEFAULT_STYLE = Style()
HIGHLIGHT_STYLE = Style(color="yellow")

PADDING_WIDTH = 2
STRUCTURE_WIDTH = 20


def make_span(text: str, style: Style = DEFAULT_STYLE) -> Text:
    """convenience function for single-line, styled text region"""
    return Text(text, style=style, no_wrap=True, overflow="ellipsis", end="")


def render_string_padding():
    return make_span(" " * PADDING_WIDTH)


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
    # this means that whitespace characters like \t, \n, and \r are rendered as
    # literal escape sequences, which keeps the rendered string on a single line
    # and matches the escaping done by sanitize() in the classic views.
    rendered_string = json.dumps(s.string)[1:-1]
    return make_span(rendered_string, style=string_style)


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

    # don't show #common if there are other tags,
    # because the other tags will be more specific (like library names).
    tags = list(get_visible_tags(s))

    for i, tag in enumerate(tags):
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

        ret.append_text(make_span(tag, style=tag_style))
        if i < len(tags) - 1:
            ret.append_text(make_span(" "))

    if is_group_start:
        ret.append_text(make_span(" ┓", style=MUTED_STYLE))
    else:
        # reserve same width as " ┓" so tags stay aligned
        ret.append_text(make_span("  "))

    return ret


def render_string_tags_continuation(tags_width: int, is_group_end: bool = False) -> Text:
    """render a continuation indicator instead of repeating tag text.

    the character is right-aligned in the given width to line up with the ┓.
    on the last line of a group, render ┛ as a terminator.
    """
    if tags_width == 0:
        return make_span("")
    if is_group_end:
        left_pad = tags_width - 1
        bar = make_span(" " * left_pad + "┛", style=MUTED_STYLE)
    else:
        left_pad = tags_width - 1
        bar = make_span(" " * left_pad + "┃", style=MUTED_STYLE)
    return bar


def render_string_offset(s: ResultString):
    # render the 000 prefix of the 8-digit offset in muted gray
    # and the non-zero suffix as blue.
    offset_chars = f"{s.offset:08x}"
    unpadded = offset_chars.lstrip("0")
    padding_width = len(offset_chars) - len(unpadded)

    offset = make_span("")
    offset.append_text(make_span("0" * padding_width, style=MUTED_STYLE))
    offset.append_text(make_span(unpadded, style=DEFAULT_STYLE))

    return offset


def render_string_structure(s: ResultString):
    ret = Text()

    if s.structure:
        structure = make_span(s.structure, style=Style(color="blue"))
        structure.align("left", STRUCTURE_WIDTH - 1)
        ret.append(make_span("/", style=MUTED_STYLE))
        ret.append(structure)
    else:
        ret.append_text(make_span(" " * STRUCTURE_WIDTH))

    return ret


def render_string(
    line_width: int,
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

    right = make_span("")
    if "tags" in columns:
        right.append_text(render_string_padding())
        if use_continuation:
            right.append_text(render_string_tags_continuation(prev_tags_width, is_group_end=is_group_end))
        else:
            right.append_text(render_string_tags(s, tag_rules, is_group_start=is_group_start))
    if "offset" in columns:
        right.append_text(render_string_padding())
        right.append_text(render_string_offset(s))
    if "encoding" in columns:
        right.append_text(render_string_padding())
        # indicate encoding: ascii is the implicit default
        right.append_text(make_span("U " if s.encoding == "unicode" else "  "))
    if "structure" in columns:
        right.append_text(render_string_structure(s))

    # this alignment clips the string if it's too long,
    # leaving an ellipsis at the end when it would collide with a tag/offset.
    # this is bad for showing all data verbatim,
    # but is good for the common case of triage analysis.
    left.align("left", line_width - len(right))

    line = Text()
    line.append_text(left)
    line.append_text(right)

    return line


def is_visible(layout: ResultLayout) -> bool:
    "a layout is visible if it has any strings (or its children do)"
    return bool(layout.strings) or any(map(is_visible, layout.children))


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
        and not layout.strings
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

    name = layout.name
    if name_hint:
        name = f"{name_hint} ({name})"

    header = make_span(name, style=MUTED_STYLE)
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
    header.append_text(make_span(header_shape, style=MUTED_STYLE))
    header.append_text(make_span("│" * depth, style=MUTED_STYLE))

    console.print(header)

    def render_string_lines(console: Console, tag_rules: TagRules, strings: list, depth: int):
        """render a batch of strings, grouping consecutive strings with the same tags."""
        visible_tags_by_index = [get_visible_tags(string) for string in strings]
        prev_tags = None
        prev_tags_width = 0
        for idx, string in enumerate(strings):
            visible_tags = visible_tags_by_index[idx]
            next_tags = visible_tags_by_index[idx + 1] if idx + 1 < len(strings) else None

            # lookahead: is this the last line in a continuation group?
            is_group_end = False
            if prev_tags is not None and visible_tags == prev_tags and len(visible_tags) > 0:
                # we are in a continuation — check if the next string breaks the group
                if next_tags is None or next_tags != visible_tags:
                    is_group_end = True

            # lookahead: is this the first line of a continuation group?
            is_group_start = False
            if (prev_tags is None or visible_tags != prev_tags) and len(visible_tags) > 0:
                if next_tags is not None and next_tags == visible_tags:
                    is_group_start = True

            line = render_string(
                console.width - (depth + 1),
                string,
                tag_rules,
                columns=columns,
                prev_tags=prev_tags,
                prev_tags_width=prev_tags_width,
                is_group_end=is_group_end,
                is_group_start=is_group_start,
            )
            line.append_text(make_span("│" * (depth + 1), style=MUTED_STYLE))
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
        render_string_lines(console, tag_rules, layout.strings, depth)

    else:
        for i, child in enumerate(layout.children):
            if i == 0:
                # render strings before first child
                strings_before_child = list(filter(lambda s: layout.offset <= s.offset < child.offset, layout.strings))
            else:
                # render strings between children
                last_child = layout.children[i - 1]
                strings_before_child = list(filter(lambda s: last_child.end <= s.offset < child.offset, layout.strings))

            render_string_lines(console, tag_rules, strings_before_child, depth)

            render_strings(console, child, tag_rules, depth + 1, parent=layout, child_index=i, columns=columns)

        # render strings after last child
        strings_after_children = list(filter(lambda s: child.end <= s.offset < layout.end, layout.strings))
        render_string_lines(console, tag_rules, strings_after_children, depth)

    if not has_visible_successors(parent, child_index):
        footer = make_span("", style=MUTED_STYLE)
        footer.align("center", width=console.width, character="─")

        footer.remove_suffix("─" * (depth + 1))
        footer.append_text(make_span("┘", style=MUTED_STYLE))
        footer.append_text(make_span("│" * depth, style=MUTED_STYLE))

        console.print(footer)

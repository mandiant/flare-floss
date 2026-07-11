# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Visibility rules and false-positive library tag cleanup."""

from __future__ import annotations

from typing import Dict, Literal

from floss.layout.base import Layout
from floss.layout.extract import collect_strings
from floss.layout.types import Tag
from floss.document import ResultLayout, ResultString
from floss.tags.oss import DEFAULT_FILENAMES

TagRules = Dict[Tag, Literal["mute"] | Literal["highlight"] | Literal["default"] | Literal["hide"]]


def remove_false_positive_lib_strings(layout: Layout):
    # list of references to all the tagged strings across the layout.
    # we can (carefully) manipulate the tags here.
    tagged_strings = collect_strings(layout)

    # open source libraries should have at least 5 strings,
    # or don't show their tag, since the couple hits are probably false positives.
    #
    # hack: assume the libname is embedded in the filename.
    # otherwise, we don't have an easy way to recover the library tag names.
    for filename in DEFAULT_FILENAMES:
        libname = filename.partition(".")[0]
        tagname = f"#{libname}"

        count = 0
        for string in tagged_strings:
            if tagname in string.tags:
                count += 1

        if 0 < count < 5:
            # I picked 5 as a reasonable threshold.
            # we could research what a better value is.
            #
            # also note that large binaries with many strings have
            # a higher chance of false positives, even with this threshold.
            # this is still a useful filter, though.
            for string in tagged_strings:
                if tagname in string.tags:
                    string.tags.remove(tagname)


def should_hide_string(s: ResultString, tag_rules: TagRules) -> bool:
    return any(map(lambda tag: tag_rules.get(tag) == "hide", s.tags))


def hide_strings_by_rules(layout: ResultLayout, tag_rules: TagRules):
    layout.strings = list(filter(lambda s: not should_hide_string(s, tag_rules), layout.strings))

    for child in layout.children:
        hide_strings_by_rules(child, tag_rules)

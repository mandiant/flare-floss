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

"""Render-time filters for layout-aware static strings.

Implements the ``--section``/``--no-section``, ``--structure``/``--no-structure``,
``--tag``/``--no-tag``, ``--interesting``, ``--query``, and ``--max-strings``
options. Filters operate on the serializable ``ResultLayout`` tree and return a
new pruned tree, so the original result document is never mutated.
"""

from __future__ import annotations

import re
from typing import Set, List, Tuple, Optional, Sequence

from floss.results import ResultLayout, ResultString
from floss.tags.oss import DEFAULT_FILENAMES
from floss.tags.filter import TagRules

# noisy tags that the --interesting shortcut excludes
NOISY_TAGS: Set[str] = {"#common", "#duplicate", "#code", "#reloc", "#code-junk"}

# tag names produced by the OSS string database, e.g. #openssl, #zlib
OSS_TAG_NAMES: Set[str] = {f"#{name.partition('.')[0]}" for name in DEFAULT_FILENAMES}


def normalize_tag(tag: str) -> str:
    """normalize a user-supplied tag so it can be compared with stored tags.

    strips a leading ``#`` and lowercases, so ``winapi`` and ``#WinAPI`` both
    match the stored tag ``#winapi``.
    """
    return tag.lstrip("#").lower()


def normalize_structure(name: str) -> str:
    """normalize a structure name so slugs match the stored names.

    ``import-table``, ``import_table``, and ``import table`` all compare equal.
    """
    return name.strip().lower().replace("_", "-").replace(" ", "-")


def tag_matches(user_tag: str, string_tags: Sequence[str]) -> bool:
    """true if ``user_tag`` matches any of ``string_tags``.

    ``oss`` is a meta tag that matches any OSS library tag.
    """
    normalized = normalize_tag(user_tag)
    if normalized == "oss":
        return any(tag in OSS_TAG_NAMES for tag in string_tags)
    wanted = f"#{normalized}"
    return any(normalize_tag(tag) == normalized or tag == wanted for tag in string_tags)


class LayoutFilter:
    """Build and apply render-time filters to a ``ResultLayout`` tree.

    Attributes:
        include_sections: keep strings whose containing layout node name is in
            this list. Empty list means no section include filter.
        exclude_sections: drop strings whose containing layout node name is in
            this list. Empty list means no section exclude filter.
        include_structures: keep strings whose structure field is in this list.
        exclude_structures: drop strings whose structure field is in this list.
        include_tags: keep strings with any matching tag.
        exclude_tags: drop strings with any matching tag.
        interesting: drop strings that carry only noisy tags; strings with at
            least one non-noisy tag are kept.
        queries: regex patterns ORed against string content.
        max_strings: cap emitted strings per layout node to the top N by
            relevance.
        tag_rules: tag rules used to compute the relevance order.
    """

    def __init__(
        self,
        *,
        include_sections: Optional[Sequence[str]] = None,
        exclude_sections: Optional[Sequence[str]] = None,
        include_structures: Optional[Sequence[str]] = None,
        exclude_structures: Optional[Sequence[str]] = None,
        include_tags: Optional[Sequence[str]] = None,
        exclude_tags: Optional[Sequence[str]] = None,
        interesting: bool = False,
        queries: Optional[Sequence[str]] = None,
        max_strings: Optional[int] = None,
        tag_rules: Optional[TagRules] = None,
    ):
        self.include_sections = list(include_sections or [])
        self.exclude_sections = list(exclude_sections or [])
        self.include_structures = list(include_structures or [])
        self.exclude_structures = list(exclude_structures or [])
        self.include_tags = list(include_tags or [])
        self.exclude_tags = list(exclude_tags or [])
        self.interesting = interesting
        self.queries = [re.compile(q) for q in (queries or [])]
        self.max_strings = max_strings
        self.tag_rules = tag_rules or {}

    @property
    def active(self) -> bool:
        return bool(
            self.include_sections
            or self.exclude_sections
            or self.include_structures
            or self.exclude_structures
            or self.include_tags
            or self.exclude_tags
            or self.interesting
            or self.queries
            or self.max_strings is not None
        )

    def _string_matches(self, section: str, s: ResultString) -> bool:
        if self.include_sections and section not in self.include_sections:
            return False
        if self.exclude_sections and section in self.exclude_sections:
            return False

        structure = normalize_structure(s.structure)
        if self.include_structures and structure not in {normalize_structure(x) for x in self.include_structures}:
            return False
        if self.exclude_structures and structure in {normalize_structure(x) for x in self.exclude_structures}:
            return False

        if self.include_tags and not any(tag_matches(t, s.tags) for t in self.include_tags):
            return False
        if self.exclude_tags and any(tag_matches(t, s.tags) for t in self.exclude_tags):
            return False
        if self.interesting and s.tags and not any(tag not in NOISY_TAGS for tag in s.tags):
            # drop strings that carry only noisy tags; keep strings that have
            # at least one non-noisy tag (e.g. #winapi #common)
            return False

        if self.queries and not any(pattern.search(s.string) for pattern in self.queries):
            return False

        return True

    @staticmethod
    def _relevance_key(s: ResultString, tag_rules: TagRules) -> Tuple[int, int]:
        """sort key for --max-strings.

        relevance order within a section:
          1. strings with a highlighted tag first
          2. then untagged strings
          3. then strings with any non-noisy tag
          4. then the rest (only noisy tags)
        within each group, ascending by offset.
        """
        has_highlight = any(tag_rules.get(tag) == "highlight" for tag in s.tags)
        has_non_noisy = any(tag not in NOISY_TAGS for tag in s.tags)
        if has_highlight:
            group = 0
        elif not s.tags:
            group = 1
        elif has_non_noisy:
            group = 2
        else:
            group = 3
        return (group, s.offset)

    def _apply_node(self, layout: ResultLayout, section: str, depth: int) -> Optional[ResultLayout]:
        """filter one layout node, recursing into children.

        The ``section`` name is threaded down the tree: the root node is the
        file itself (its own strings carry the root name), each child of the
        root is a binary section, and deeper nodes inherit their containing
        section. This way ``--section .rdata`` also matches strings that live
        in nested structure nodes under ``.rdata``.

        returns None when the node has no matching strings and no matching
        children, so empty branches are pruned but headers that still contain
        matches are kept.
        """
        if depth == 0:
            section = layout.name

        strings = [s for s in layout.strings if self._string_matches(section, s)]

        children: List[ResultLayout] = []
        for child in layout.children:
            # children of the root are the sections themselves; deeper nodes inherit
            child_section = child.name if depth == 0 else section
            filtered = self._apply_node(child, child_section, depth + 1)
            if filtered is not None:
                children.append(filtered)

        if not strings and not children:
            return None

        return ResultLayout(
            name=layout.name,
            offset=layout.offset,
            length=layout.length,
            strings=strings,
            children=children,
        )

    def _collect_strings(self, layout: ResultLayout) -> List[ResultString]:
        """flatten all strings in a layout subtree, in render order."""
        strings = list(layout.strings)
        for child in layout.children:
            strings.extend(self._collect_strings(child))
        return strings

    def _prune(self, layout: ResultLayout, keep: set) -> Optional[ResultLayout]:
        """rebuild a layout subtree keeping only strings in ``keep`` (by id).

        kept strings within a node are emitted in relevance order.
        """
        strings = [s for s in layout.strings if id(s) in keep]
        strings.sort(key=lambda s: self._relevance_key(s, self.tag_rules))
        children: List[ResultLayout] = []
        for child in layout.children:
            pruned = self._prune(child, keep)
            if pruned is not None:
                children.append(pruned)
        if not strings and not children:
            return None
        return ResultLayout(
            name=layout.name,
            offset=layout.offset,
            length=layout.length,
            strings=strings,
            children=children,
        )

    def _cap_node(self, layout: ResultLayout) -> Optional[ResultLayout]:
        """cap a top-level section subtree to the top N strings by relevance."""
        all_strings = self._collect_strings(layout)
        if self.max_strings is None or len(all_strings) <= self.max_strings:
            return layout
        ranked = sorted(all_strings, key=lambda s: self._relevance_key(s, self.tag_rules))
        keep = {id(s) for s in ranked[: self.max_strings]}
        return self._prune(layout, keep)

    def apply(self, layout: ResultLayout) -> Optional[ResultLayout]:
        """return a filtered copy of ``layout``, or None when nothing matches."""
        filtered = self._apply_node(layout, "", 0)
        if filtered is None:
            return None

        if self.max_strings is None:
            return filtered

        # cap each top-level section (child of the root) as a unit, plus the
        # root's own strings, so a section never emits more than N strings.
        children: List[ResultLayout] = []
        for child in filtered.children:
            capped = self._cap_node(child)
            if capped is not None:
                children.append(capped)
        ranked_root = sorted(filtered.strings, key=lambda s: self._relevance_key(s, self.tag_rules))
        strings = ranked_root[: self.max_strings]

        if not strings and not children:
            return None

        return ResultLayout(
            name=filtered.name,
            offset=filtered.offset,
            length=filtered.length,
            strings=strings,
            children=children,
        )

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

"""Recursive layout tree nodes for binary structure."""

from __future__ import annotations

import abc
import bisect
from typing import Any, Set, Dict, List, Tuple, Callable, Iterable, Optional, Sequence
from collections import defaultdict

import pefile
from pydantic import Field, BaseModel, ConfigDict

from floss.ranges import Range, Slice, OffsetRanges
from floss.tags.engine import check_is_xor, check_is_code, check_is_reloc
from floss.layout.types import Tag, TaggedString, ExtractedString

Tagger = Callable[[ExtractedString], Sequence[Tag]]


class Structure(BaseModel):
    slice: Slice
    name: str


class Layout(BaseModel, abc.ABC):
    """
    recursively describe a region of a data, as a tree.
    the compute_layout routines construct this tree.

    each node in the tree (Layout), describes a range of the data.
    it may have children, which describes sub-ranges of the data.
    children don't overlap nor extend before/beyond the parent range.
    children are ordered by their offset in the data.
    children don't have to be contiguous - there can be gaps, or none at all.
    there are routines for traversing to the prior/next sibling, if any,
    and accessor properties for the parent and children.

    each node has a nice human readable name.
    each node has a list of strings that are contained by the node;
    these strings don't overlap with any children strings, they're only found in the gaps.

    note that `Layout` is the abstract base class for nodes in the tree.
    subclasses are used to represent different types of regions,
    such as a PE file, a section, a segment, or a resource.
    subclasses can provide more specific behavior when it comes to tagging strings.
    """

    slice: Slice

    # human readable name
    name: str

    parent: Optional["Layout"] = Field(default=None, init=False)

    # ordered by address
    # non-overlapping
    # may not cover the entire range (non-contiguous)
    children: Sequence["Layout"] = Field(default_factory=list, init=False)

    # this is populated by the call to extract_strings.
    # only strings not contained by the children are in this list.
    # so they come from before/between/after the children ranges.
    strings: List[TaggedString] = Field(default_factory=list, init=False)

    @property
    def predecessors(self) -> Iterable["Layout"]:
        """traverse to the prior siblings`"""
        if self.parent is None:
            return

        index = self.parent.children.index(self)
        if index == 0:
            return

        for i in range(index - 1, -1, -1):
            yield self.parent.children[i]

    @property
    def predecessor(self) -> Optional["Layout"]:
        """traverse to the prior sibling"""
        return next(iter(self.predecessors), None)

    @property
    def successors(self) -> Iterable["Layout"]:
        """traverse to the next siblings"""
        if self.parent is None:
            return

        index = self.parent.children.index(self)
        if index == len(self.parent.children) - 1:
            return

        for i in range(index + 1, len(self.parent.children)):
            yield self.parent.children[i]

    @property
    def successor(self) -> Optional["Layout"]:
        """traverse to the next sibling"""
        return next(iter(self.successors), None)

    def add_child(self, child: "Layout"):
        # this works in py3.11, though mypy gets confused,
        # maybe due to the use of the key function.
        bisect.insort(self.children, child, key=lambda c: c.slice.range.offset)  # type: ignore
        child.parent = self

    @property
    def offset(self) -> int:
        "convenience"
        return self.slice.range.offset

    @property
    def end(self) -> int:
        "convenience"
        return self.slice.range.end

    def extract_strings(self, min_len: int) -> None:
        """
        find the strings in this layout and its children, recursively.

        this finds strings in the gaps between the children (and before the
        first and after the last child), so this method must run before
        ``tag_strings``.
        """
        # imported here to avoid a circular import with floss.layout.extract
        from floss.layout.extract import extract_strings as extract_gap_strings

        if not self.children:
            # at this moment, self.strings contains only ExtractedStrings
            # after tag_strings, it will contain TaggedStrings.
            self.strings = extract_gap_strings(self.slice, min_len)  # type: ignore
            return

        # we have children, so we need to recurse to find their strings,
        # and also find strings in the gaps between children.
        # lets find the gap strings first:
        for i, child in enumerate(self.children):
            if i == 0:
                # find the strings before the first child
                offset = 0
                size = self.children[0].offset - self.offset

            else:
                # find strings between children
                prior = self.children[i - 1]
                offset = prior.end - self.offset
                size = child.offset - prior.end

            if size == 0:
                # there is no gap here.
                continue

            gap = self.slice.slice(offset, size)
            self.strings.extend(extract_gap_strings(gap, min_len))  # type: ignore

        # finally, find strings after the last child
        last_child = self.children[-1]
        offset = last_child.end - self.offset
        size = self.end - last_child.end

        if size > 0:
            gap = self.slice.slice(offset, size)
            self.strings.extend(extract_gap_strings(gap, min_len))  # type: ignore

        # now recurse to find the strings in the children.
        for child in self.children:
            child.extract_strings(min_len)

        if self.strings:
            child_ranges = [(child.offset, child.end) for child in self.children]
            filtered = []
            for string in self.strings:
                if isinstance(string, TaggedString):
                    offset = string.offset
                else:
                    offset = string.slice.range.offset
                if any(start <= offset < end for start, end in child_ranges):
                    continue
                filtered.append(string)
            self.strings = filtered

    def tag_strings(self, taggers: Sequence[Tagger]):
        """
        tag the strings in this layout and its children, recursively.
        this means that the .strings field will contain TaggedStrings now
        (it used to contain ExtractedStrings).

        this can be overridden, if a subclass has more ways of tagging strings,
        such as a PE file and code/reloc regions.
        """
        string_counts: Dict[str, int] = defaultdict(int)

        tagged_strings: List[TaggedString] = []

        for string in self.strings:
            # at this moment, the list of strings contains only ExtractedStrings.
            # this routine will transform them into TaggedStrings.
            assert isinstance(string, ExtractedString)
            tags: Set[Tag] = set()

            string_counts[string.string] += 1

            if string_counts[string.string] > 1:
                tags.add("#duplicate")

            for tagger in taggers:
                tags.update(tagger(string))

            tagged_strings.append(TaggedString(string=string, tags=tags))
        self.strings = tagged_strings

        for child in self.children:
            child.tag_strings(taggers)

    def mark_structures(self, structures: Optional[Tuple[Dict[int, Structure], ...]] = (), **kwargs):
        """
        mark the structures that might be associated with each string, recursively.
        this means that the TaggedStrings may now have a non-empty .structure field.

        this can be overridden, if a subclass has a way of parsing structures,
        such as a PE file and all its data.
        """
        if structures:
            self._mark_string_structures(structures)

        for child in self.children:
            child.mark_structures(structures=structures, **kwargs)

    def _mark_string_structures(self, structures) -> None:
        """attach the first matching structure name to this node's own strings."""
        for string in self.strings:
            for structures_by_address in structures:
                structure = structures_by_address.get(string.offset)
                if structure:
                    string.structure = structure.name
                    break


class SectionLayout(Layout):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    section: Optional[pefile.SectionStructure] = None


class SegmentLayout(Layout):
    """region not covered by any section, such as PE header or overlay"""

    pass


class PELayout(Layout):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # xor key if the file was xor decoded
    xor_key: Optional[int]

    # file offsets of bytes that are part of the relocation table
    reloc_offsets: OffsetRanges

    # file offsets of bytes that are recognized as code
    code_offsets: OffsetRanges

    structures_by_address: Dict[int, Structure]

    def tag_strings(self, taggers: Sequence[Tagger]):
        def check_is_xor_tagger(s: ExtractedString) -> Sequence[Tag]:
            return check_is_xor(self.xor_key)

        def check_is_reloc_tagger(s: ExtractedString) -> Sequence[Tag]:
            return check_is_reloc(self.reloc_offsets, s)

        def check_is_code_tagger(s: ExtractedString) -> Sequence[Tag]:
            return check_is_code(self.code_offsets, s)

        taggers = tuple(taggers) + (
            check_is_xor_tagger,
            check_is_reloc_tagger,
            check_is_code_tagger,
        )

        super().tag_strings(taggers)

    def mark_structures(self, structures=(), **kwargs):
        # apply the PE structures to this node's own strings too (e.g. strings
        # in the header gap that are attached to the root layout node)
        self._mark_string_structures((structures or ()) + (self.structures_by_address,))
        for child in self.children:
            if isinstance(child, (SectionLayout, SegmentLayout)):
                # expected child of a PE
                child.mark_structures(structures=structures + (self.structures_by_address,), **kwargs)
            else:
                # unexpected child of a PE
                # maybe like a resource or overlay, etc.
                # which is fine - but we don't expect it to know about the PE structures.
                child.mark_structures(structures=structures, **kwargs)


class ELFLayout(Layout):
    xor_key: Optional[int]

    # file offsets of bytes that are part of relocation sections
    relocation_offsets: OffsetRanges

    # file offsets of bytes that are recognized as code
    code_offsets: OffsetRanges

    structures_by_address: Dict[int, Structure]

    def tag_strings(self, taggers: Sequence[Tagger]):
        def check_is_xor_tagger(s: ExtractedString) -> Sequence[Tag]:
            return check_is_xor(self.xor_key)

        def check_is_reloc_tagger(s: ExtractedString) -> Sequence[Tag]:
            return check_is_reloc(self.relocation_offsets, s)

        def check_is_code_tagger(s: ExtractedString) -> Sequence[Tag]:
            return check_is_code(self.code_offsets, s)

        taggers = tuple(taggers) + (
            check_is_xor_tagger,
            check_is_reloc_tagger,
            check_is_code_tagger,
        )

        super().tag_strings(taggers)

    def mark_structures(self, structures: Optional[Tuple[Dict[int, Structure], ...]] = (), **kwargs):
        # apply the ELF structures to this node's own strings too (the ELF
        # header/program-header gap strings attach to the root layout node)
        self._mark_string_structures((structures or ()) + (self.structures_by_address,))
        for child in self.children:
            if isinstance(child, (SectionLayout, SegmentLayout)):
                child.mark_structures(structures=(structures or ()) + (self.structures_by_address,), **kwargs)
            else:
                child.mark_structures(structures=structures, **kwargs)


class ResourceLayout(Layout):
    pass


class MachOLayout(Layout):
    arch: str
    structures_by_address: Dict[int, Structure] = Field(default_factory=dict)

    def mark_structures(self, structures=(), **kwargs):
        if self.structures_by_address:
            structures = structures + (self.structures_by_address,)
        super().mark_structures(structures=structures, **kwargs)

    def tag_strings(self, taggers: Sequence[Tagger]):
        super().tag_strings(taggers)


class MachOFatLayout(Layout):
    pass

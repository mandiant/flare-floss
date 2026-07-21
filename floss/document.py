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

"""Interim layout-aware result document for static string analysis.

This module holds the layout-tree JSON schema produced by ``floss.quantum``.
It will be merged into ``floss.results`` in iteration 2 so deobfuscated strings,
layout, tags, and section context share one ``ResultDocument``.
"""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, List, Optional

from pydantic import BaseModel

from floss.layout.types import TaggedString

if TYPE_CHECKING:
    from floss.layout.base import Layout


class ResultString(BaseModel):
    string: str
    offset: int
    size: int
    encoding: str
    tags: List[str]
    structure: str


class ResultLayout(BaseModel):
    name: str
    offset: int
    length: int
    strings: List[ResultString]
    children: List["ResultLayout"]

    @property
    def end(self) -> int:
        return self.offset + self.length

    @classmethod
    def from_layout(cls, layout: "Layout") -> "ResultLayout":
        """
        Recursively converts a Layout object and its contents to the serializable format.
        """
        result_strings = []
        for s in layout.strings:
            result_strings.append(
                ResultString(
                    string=s.string.string,
                    offset=s.string.slice.range.offset,
                    size=s.string.slice.range.length,
                    encoding=s.string.encoding,
                    tags=sorted(list(s.tags)),
                    structure=s.structure,
                )
            )

        result_children = []
        if layout.children:
            for child in layout.children:
                result_children.append(cls.from_layout(child))

        return ResultLayout(
            name=layout.name,
            offset=layout.slice.range.offset,
            length=layout.slice.range.length,
            strings=result_strings,
            children=result_children,
        )


class Sample(BaseModel):
    md5: str
    sha1: str
    sha256: str
    path: str


class Metadata(BaseModel):
    version: str
    timestamp: datetime.datetime
    sample: Sample
    min_str_len: int


class ResultDocument(BaseModel):
    meta: Metadata
    layout: ResultLayout

    @classmethod
    def from_layout(cls, meta: Metadata, layout: "Layout") -> "ResultDocument":
        results = ResultLayout.from_layout(layout)
        return ResultDocument(meta=meta, layout=results)

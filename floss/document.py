# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Serializable analysis document for layout-aware string extraction."""

from __future__ import annotations

import datetime
from typing import List, Optional

from pydantic import BaseModel

from floss.layout.base import Layout
from floss.layout.types import TaggedString


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
    def from_qs(cls, meta: Metadata, layout: "Layout") -> "ResultDocument":
        results = ResultLayout.from_layout(layout)
        return ResultDocument(meta=meta, layout=results)


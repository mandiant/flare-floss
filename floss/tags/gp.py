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

"""Global-prevalence tag source: strings common across many binaries (#common, #code-junk).

Tag sources load on-disk databases and answer whether a string should receive a tag.
See ``floss.tags.engine`` for wiring into the analysis pipeline.
"""

import gzip
import hashlib
import pathlib
import datetime
from typing import Set, Dict, List, Literal, Optional, Sequence
from collections import defaultdict
from dataclasses import dataclass

import msgspec

from floss.tags import data_root

Encoding = Literal["ascii"] | Literal["utf-16le"] | Literal["unknown"]
# header | gap | overlay
# or section name
Location = Literal["header"] | Literal["gap"] | Literal["overlay"] | str


class Metadata(msgspec.Struct):
    note: str | None
    timestamp: str | None
    type: str = "global_prevalence"
    version: str = "1.0"


class StringGlobalPrevalence(msgspec.Struct):
    string: str
    encoding: Encoding
    global_count: int
    location: Location | None


@dataclass
class StringGlobalPrevalenceDatabase:
    meta: Metadata
    metadata_by_string: Dict[str, List[StringGlobalPrevalence]]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    def insert(self, str_gp: StringGlobalPrevalence):
        # TODO combine if existing data
        self.metadata_by_string[str_gp.string].append(str_gp)

    def query(self, string):
        return self.metadata_by_string.get(string, [])

    def update(self, other: "StringGlobalPrevalenceDatabase"):
        # TODO combine if existing data
        self.metadata_by_string.update(other.metadata_by_string)

    @classmethod
    def new_db(cls, note: Optional[str] = None):
        return cls(
            meta=Metadata(timestamp=datetime.datetime.now().isoformat(), note=note),
            metadata_by_string=defaultdict(list),
        )

    @classmethod
    def from_file(cls, path: pathlib.Path, compress: bool = True) -> "StringGlobalPrevalenceDatabase":
        metadata_by_string: Dict[str, List[StringGlobalPrevalence]] = defaultdict(list)

        if compress:
            lines = gzip.decompress(path.read_bytes()).split(b"\n")
        else:
            lines = path.read_bytes().split(b"\n")

        decoder = msgspec.json.Decoder(type=StringGlobalPrevalence)
        for line in lines[1:]:
            if not line:
                continue
            s = decoder.decode(line)

            metadata_by_string[s.string].append(s)

        return cls(
            meta=msgspec.json.Decoder(type=Metadata).decode(lines[0]),
            metadata_by_string=metadata_by_string,
        )

    def to_file(self, outfile: str, compress: bool = True):
        if compress:
            with gzip.open(outfile, "w") as f:
                f.write(msgspec.json.encode(self.meta) + b"\n")
                for k, v in sorted(self.metadata_by_string.items(), key=lambda x: x[1][0].global_count, reverse=True):
                    # TODO needs fixing to write most common to least common
                    for e in v:
                        f.write(msgspec.json.encode(e) + b"\n")
        else:
            with open(outfile, "w", encoding="utf-8") as f:
                f.write(msgspec.json.encode(self.meta).decode("utf-8") + "\n")
                for k, v in sorted(self.metadata_by_string.items(), key=lambda x: x[1][0].global_count, reverse=True):
                    for e in v:
                        f.write(msgspec.json.encode(e).decode("utf-8") + "\n")


@dataclass
class StringHashDatabase:
    string_hashes: Set[bytes]

    def __len__(self) -> int:
        return len(self.string_hashes)

    def __contains__(self, other: bytes | str) -> bool:
        if isinstance(other, bytes):
            return other in self.string_hashes
        elif isinstance(other, str):
            m = hashlib.md5()
            m.update(other.encode("utf-8"))
            return m.digest()[:8] in self.string_hashes
        else:
            raise ValueError("other must be bytes or str")

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "StringHashDatabase":
        string_hashes: Set[bytes] = set()

        buf = path.read_bytes()

        for i in range(0, len(buf), 8):
            string_hashes.add(buf[i : i + 8])

        return cls(
            string_hashes=string_hashes,
        )


DEFAULT_PATHS = (
    data_root() / "gp" / "gp.jsonl.gz",
    data_root() / "gp" / "cwindb-native.jsonl.gz",
    data_root() / "gp" / "cwindb-dotnet.jsonl.gz",
    data_root() / "gp" / "xaa-hashes.bin",
    data_root() / "gp" / "yaa-hashes.bin",
)


def get_default_databases() -> Sequence[StringGlobalPrevalenceDatabase | StringHashDatabase]:
    return [
        (
            StringGlobalPrevalenceDatabase.from_file(path)
            if path.name.endswith(".jsonl.gz")
            else StringHashDatabase.from_file(path)
        )
        for path in DEFAULT_PATHS
    ]

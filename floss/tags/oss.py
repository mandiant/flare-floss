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

import gzip
import pathlib
from typing import Dict, Sequence
from dataclasses import dataclass

import msgspec


def _data_root() -> pathlib.Path:
    """Legacy DB location: floss/qs/db/data."""
    return pathlib.Path(__file__).resolve().parents[1] / "qs" / "db" / "data"


class OpenSourceString(msgspec.Struct):
    string: str
    library_name: str
    library_version: str
    file_path: str | None = None
    function_name: str | None = None
    line_number: int | None = None


@dataclass
class OpenSourceStringDatabase:
    metadata_by_string: Dict[str, OpenSourceString]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "OpenSourceStringDatabase":
        metadata_by_string: Dict[str, OpenSourceString] = {}
        decoder = msgspec.json.Decoder(type=OpenSourceString)
        for line in gzip.decompress(path.read_bytes()).split(b"\n"):
            if not line:
                continue
            s = decoder.decode(line)
            metadata_by_string[s.string] = s

        return cls(metadata_by_string=metadata_by_string)


DEFAULT_FILENAMES = (
    "brotli.jsonl.gz",
    "bzip2.jsonl.gz",
    "cryptopp.jsonl.gz",
    "curl.jsonl.gz",
    "detours.jsonl.gz",
    "jemalloc.jsonl.gz",
    "jsoncpp.jsonl.gz",
    "kcp.jsonl.gz",
    "liblzma.jsonl.gz",
    "libsodium.jsonl.gz",
    "libpcap.jsonl.gz",
    "mbedtls.jsonl.gz",
    "openssl.jsonl.gz",
    "sqlite3.jsonl.gz",
    "tomcrypt.jsonl.gz",
    "wolfssl.jsonl.gz",
    "zlib.jsonl.gz",
)

DEFAULT_PATHS = tuple(_data_root() / "oss" / filename for filename in DEFAULT_FILENAMES) + (
    _data_root() / "crt" / "msvc_v143.jsonl.gz",
)


def get_default_databases() -> Sequence[OpenSourceStringDatabase]:
    return [OpenSourceStringDatabase.from_file(path) for path in DEFAULT_PATHS]

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

"""Windows API tag source: known DLL and API name strings (#winapi).

Tag sources load on-disk databases and answer whether a string should receive a tag.
See ``floss.tags.engine`` for wiring into the analysis pipeline.
"""

import gzip
import pathlib
from typing import Set, Sequence
from dataclasses import dataclass

from floss.tags import data_root


@dataclass
class WindowsApiStringDatabase:
    dll_names: Set[str]
    api_names: Set[str]

    def __len__(self) -> int:
        return len(self.dll_names) + len(self.api_names)

    @classmethod
    def from_dir(cls, path: pathlib.Path) -> "WindowsApiStringDatabase":
        dll_names: Set[str] = set()
        api_names: Set[str] = set()

        for line in gzip.decompress((path / "dlls.txt.gz").read_bytes()).decode("utf-8").splitlines():
            if not line:
                continue
            dll_names.add(line)

        for line in gzip.decompress((path / "apis.txt.gz").read_bytes()).decode("utf-8").splitlines():
            if not line:
                continue
            api_names.add(line)

        return cls(dll_names=dll_names, api_names=api_names)


DEFAULT_PATHS = (data_root() / "winapi",)


def get_default_databases() -> Sequence[WindowsApiStringDatabase]:
    return [WindowsApiStringDatabase.from_dir(path) for path in DEFAULT_PATHS]

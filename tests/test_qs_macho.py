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

from pathlib import Path

from floss.layout import compute_layout
from floss.ranges import Slice

CD = Path(__file__).resolve().parent
MACHO_DIR = CD / "data" / "macho"


def _load_layout(name: str):
    path = MACHO_DIR / name
    data = path.read_bytes()
    return compute_layout(Slice.from_bytes(data))


def test_thin_macho_layout():
    layout = _load_layout("ls")
    assert layout.name.startswith("macho:")
    assert layout.children


def test_thin_macho_segment_names():
    layout = _load_layout("regdmp")
    names = {child.name for child in layout.children}
    assert "__TEXT" in names
    assert "__LINKEDIT" in names


def test_macho_structures_present():
    layout = _load_layout("ls")
    assert getattr(layout, "structures_by_address", None)


def test_fat_macho_layout():
    layout = _load_layout("true")
    assert layout.name == "macho (fat)"
    assert len(layout.children) == 2
    assert {child.name for child in layout.children} == {"macho: x86_64", "macho: arm64e"}


def test_entitlements_plist_layout():
    layout = _load_layout("true")
    found = []
    for arch in layout.children:
        for child in arch.children:
            if child.name == "__LINKEDIT":
                for code_sig in child.children:
                    if code_sig.name != "code signature":
                        continue
                    for cert in code_sig.children:
                        if any(sub.name == "plist: entitlements" for sub in cert.children):
                            found.append(arch.name)
    assert set(found) == {"macho: x86_64", "macho: arm64e"}


def test_entitlements_plist_parse():
    import plistlib

    path = MACHO_DIR / "true"
    data = path.read_bytes()
    layout = compute_layout(Slice.from_bytes(data))

    parsed = 0
    for arch in layout.children:
        for child in arch.children:
            if child.name == "__LINKEDIT":
                for code_sig in child.children:
                    if code_sig.name != "code signature":
                        continue
                    for cert in code_sig.children:
                        for subchild in cert.children:
                            if subchild.name == "plist: entitlements":
                                blob = data[subchild.offset : subchild.end]
                                plistlib.loads(blob)
                                parsed += 1

    assert parsed == 2

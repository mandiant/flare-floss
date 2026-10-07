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

import pefile

from floss.layout.pe import (
    IMAGE_SCN_MEM_EXECUTE,
    MAX_CODE_VIRTUAL_EXTENT,
    MAX_CODE_EXECUTABLE_EXTENT,
    get_code_analysis_skip_reason,
)

CD = Path(__file__).resolve().parent
DOTNET_HELLO = CD / "data" / "language" / "dotnet" / "dotnet-hello" / "bin" / "dotnet-hello.exe"


def load_pe(**text_fields) -> pefile.PE:
    """dotnet-hello.exe (SectionAlignment 0x2000, .text at RVA 0x2000) with .text header fields overridden."""
    pe = pefile.PE(data=DOTNET_HELLO.read_bytes())
    for name, value in text_fields.items():
        setattr(pe.sections[0], name, value)
    data = pe.write()
    return pefile.PE(data=data), len(data)


def test_ordinary_image_is_analysed():
    pe, size = load_pe()
    assert get_code_analysis_skip_reason(pe, size) is None


def test_executable_extent_at_cap_is_analysed():
    pe, size = load_pe(Misc_VirtualSize=MAX_CODE_EXECUTABLE_EXTENT, Characteristics=IMAGE_SCN_MEM_EXECUTE)
    assert get_code_analysis_skip_reason(pe, size) is None


def test_executable_extent_over_cap_is_skipped():
    pe, size = load_pe(Misc_VirtualSize=MAX_CODE_EXECUTABLE_EXTENT + 1, Characteristics=IMAGE_SCN_MEM_EXECUTE)
    reason = get_code_analysis_skip_reason(pe, size)
    assert reason is not None and reason.startswith("executable extent 0x1002000 ")


def test_huge_non_executable_section_counts_only_towards_virtual_extent():
    pe, size = load_pe(Misc_VirtualSize=0x10000001, Characteristics=0x40000040)
    assert get_code_analysis_skip_reason(pe, size) is None


def test_virtual_extent_over_cap_is_skipped():
    pe, size = load_pe(VirtualAddress=MAX_CODE_VIRTUAL_EXTENT, Characteristics=0x40000040)
    reason = get_code_analysis_skip_reason(pe, size)
    assert reason is not None and reason.startswith("virtual extent 0x40002000 ")


def test_executable_extent_sums_over_sections():
    pe = pefile.PE(data=DOTNET_HELLO.read_bytes())
    per_section = MAX_CODE_EXECUTABLE_EXTENT // 2
    for section in pe.sections[:2]:
        section.Misc_VirtualSize = per_section
        section.Characteristics = IMAGE_SCN_MEM_EXECUTE
    data = pe.write()
    assert get_code_analysis_skip_reason(pefile.PE(data=data), len(data)) is None

    pe.sections[1].Misc_VirtualSize = per_section + 1
    data = pe.write()
    reason = get_code_analysis_skip_reason(pefile.PE(data=data), len(data))
    assert reason is not None and reason.startswith("executable extent")

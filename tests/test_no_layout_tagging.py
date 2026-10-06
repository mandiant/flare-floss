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

from fixtures import exefile

import floss.pipeline
from floss.enrich import static_strings_from_layout
from floss.results import Analysis

STATIC_ONLY = Analysis(
    enable_static_strings=True,
    enable_stack_strings=False,
    enable_tight_strings=False,
    enable_decoded_strings=False,
    enable_language_strings=False,
)


def analyze_static(path: Path):
    options = floss.pipeline.Options(sample=path, min_length=4, analysis=STATIC_ONLY, language="none")
    results = floss.pipeline.analyze(options)
    assert results is not None
    return results


def test_no_layout_static_strings_are_tagged(tmp_path):
    sample = tmp_path / "blob.bin"
    sample.write_bytes(
        b"\x00" * 16
        + b"This program cannot be run in DOS mode.\x00"
        + b"kernel32.dll\x00\x00"
        + "CreateFileW".encode("utf-16le")
        + b"\x00\x00"
        + b"zzzz-not-in-any-database\x00"
        + b"zzzz-not-in-any-database\x00"
    )

    results = analyze_static(sample)

    assert results.layout is None
    by_string = {s.string: s for s in results.strings.static_strings}

    assert "#capa" in by_string["This program cannot be run in DOS mode."].tags
    assert "#winapi" in by_string["kernel32.dll"].tags
    assert "#common" in by_string["kernel32.dll"].tags
    assert "#liblzma" not in by_string["kernel32.dll"].tags
    assert by_string["CreateFileW"].encoding.value == "UTF-16LE"
    assert "#winapi" in by_string["CreateFileW"].tags

    duplicates = [s for s in results.strings.static_strings if s.string == "zzzz-not-in-any-database"]
    assert [s.tags for s in duplicates] == [[], ["#duplicate"]]

    for s in results.strings.static_strings:
        assert s.section == ""
        assert s.structure == ""
        assert not any(t in s.tags for t in ("#code", "#reloc", "#decoded"))

    assert results.metadata.runtime.tags > 0


def test_pe_static_strings_still_come_from_layout(exefile):
    results = analyze_static(Path(exefile))

    assert results.layout is not None
    assert results.strings.static_strings == static_strings_from_layout(results.layout)
    assert any(s.section for s in results.strings.static_strings)
    assert any("#code" in s.tags for s in results.strings.static_strings)

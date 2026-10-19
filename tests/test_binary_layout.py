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

import struct
from pathlib import Path

import pytest
from fixtures import exefile

import floss.main
import floss.layout
import floss.pipeline
from floss.enrich import static_strings_from_layout
from floss.ranges import Slice
from floss.results import Analysis

STATIC_ONLY = Analysis(
    enable_static_strings=True,
    enable_stack_strings=False,
    enable_tight_strings=False,
    enable_decoded_strings=False,
    enable_language_strings=False,
)

BLOB = (
    b"\x00" * 16
    + b"This program cannot be run in DOS mode.\x00"
    + b"kernel32.dll\x00\x00"
    + "CreateFileW".encode("utf-16le")
    + b"\x00\x00"
    + b"zzzz-not-in-any-database\x00"
    + b"zzzz-not-in-any-database\x00"
)


def analyze_static(path: Path):
    options = floss.pipeline.Options(sample=path, min_length=4, analysis=STATIC_ONLY, language="none")
    results = floss.pipeline.analyze(options)
    assert results is not None
    return results


def assert_binary_layout(results, size: int):
    assert results.layout is not None
    assert results.layout.name == "binary"
    assert results.layout.children == []
    assert results.layout.offset == 0
    assert results.layout.length == size
    assert results.strings.static_strings == static_strings_from_layout(results.layout)
    assert results.strings.static_strings
    for s in results.strings.static_strings:
        assert s.section == "binary"
        assert s.structure == ""
        assert not any(t in s.tags for t in ("#code", "#reloc", "#decoded"))


def test_non_pe_input_gets_single_binary_layout_node(tmp_path):
    sample = tmp_path / "blob.bin"
    sample.write_bytes(BLOB)

    results = analyze_static(sample)

    assert_binary_layout(results, len(BLOB))
    by_string = {s.string: s for s in results.strings.static_strings}

    assert "#capa" in by_string["This program cannot be run in DOS mode."].tags
    assert "#winapi" in by_string["kernel32.dll"].tags
    assert "#common" in by_string["kernel32.dll"].tags
    assert "#liblzma" not in by_string["kernel32.dll"].tags
    assert by_string["CreateFileW"].encoding.value == "UTF-16LE"
    assert "#winapi" in by_string["CreateFileW"].tags

    duplicates = sorted(
        (s for s in results.strings.static_strings if s.string == "zzzz-not-in-any-database"),
        key=lambda s: s.offset,
    )
    assert [s.tags for s in duplicates] == [[], ["#duplicate"]]

    assert results.metadata.runtime.tags > 0


def corrupt_pe(buf: bytes) -> bytes:
    # a SizeOfOptionalHeader of 0xFFFF pushes the section table past the end of
    # the file; pefile then reports no sections and the PE layout parser raises
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    return buf[: e_lfanew + 0x14] + struct.pack("<H", 0xFFFF) + buf[e_lfanew + 0x16 :]


def test_corrupt_pe_layout_parser_raises(exefile):
    buf = corrupt_pe(Path(exefile).read_bytes())
    assert buf.startswith(b"MZ")
    with pytest.raises(Exception):
        floss.layout.compute_layout(Slice.from_bytes(buf))


def test_corrupt_pe_falls_back_to_binary_layout(tmp_path, exefile, caplog):
    buf = corrupt_pe(Path(exefile).read_bytes())
    sample = tmp_path / "corrupt.exe"
    sample.write_bytes(buf)

    with caplog.at_level("WARNING", logger="floss.pipeline"):
        results = analyze_static(sample)

    assert "structured layout analysis failed" in caplog.text
    assert_binary_layout(results, len(buf))
    assert any(s.tags for s in results.strings.static_strings)


def test_pe_static_strings_still_come_from_layout(exefile):
    results = analyze_static(Path(exefile))

    assert results.layout is not None
    assert results.layout.name == "pe"
    assert results.strings.static_strings == static_strings_from_layout(results.layout)
    assert any(s.section for s in results.strings.static_strings)
    assert any("#code" in s.tags for s in results.strings.static_strings)


def run_main(args, capsys):
    assert floss.main.main(["-q", "--string-type", "static", "--language", "none", *args]) == 0
    return capsys.readouterr().out


def test_main_non_pe_tag_filter_applies(tmp_path, capsys, caplog):
    sample = tmp_path / "blob.bin"
    sample.write_bytes(BLOB)

    with caplog.at_level("WARNING"):
        out = run_main(["--tag", "capa", "--", str(sample)], capsys)

    assert "ignored" not in caplog.text
    assert "binary" in out
    assert "This program cannot be run in DOS mode." in out
    assert "kernel32.dll" not in out
    assert "zzzz-not-in-any-database" not in out


def test_main_non_pe_interesting_filter_applies(tmp_path, capsys, caplog):
    sample = tmp_path / "blob.bin"
    sample.write_bytes(BLOB)

    with caplog.at_level("WARNING"):
        out = run_main(["--interesting", "--", str(sample)], capsys)

    assert "ignored" not in caplog.text
    assert "binary" in out
    assert "This program cannot be run in DOS mode." in out
    assert "kernel32.dll" not in out
    assert out.count("zzzz-not-in-any-database") == 1
    assert "#duplicate" not in out


def test_main_non_pe_plain_is_flat(tmp_path, capsys):
    sample = tmp_path / "blob.bin"
    sample.write_bytes(BLOB)

    out = run_main(["--plain", "--", str(sample)], capsys)

    lines = out.splitlines()
    assert "kernel32.dll" in lines
    assert "zzzz-not-in-any-database" in lines
    assert not any(line.startswith("binary") for line in lines)

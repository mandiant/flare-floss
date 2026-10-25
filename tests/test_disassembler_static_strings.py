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

"""Render scripts must include static and language strings, not just recovered ones."""

import sys
import json
import subprocess
from pathlib import Path

import pefile
import pytest
from pydantic import TypeAdapter

from floss.results import Strings, Metadata, StaticString, ResultDocument, StringEncoding

CD = Path(__file__).resolve().parent
SAMPLE = CD / "data" / "test-decode-to-stack.exe"
ELF_SAMPLE = CD / "data" / "elf" / "ls"

STATIC_OFFSET = 0x10
LANGUAGE_OFFSET = 0x20


def get_script_path(name: str) -> Path:
    return CD / ".." / "scripts" / "disassemblers" / name


def get_rdata() -> tuple[int, int, int]:
    """return imagebase, section VA, and section file offset for .rdata"""
    pe = pefile.PE(str(SAMPLE))
    section = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".rdata")
    return pe.OPTIONAL_HEADER.ImageBase, section.VirtualAddress, section.PointerToRawData


def write_results(
    tmp_path: Path,
    file_path: Path,
    imagebase: int,
    static_strings: list[StaticString] | None = None,
    language_strings: list[StaticString] | None = None,
) -> Path:
    _, _, raw = get_rdata()
    if static_strings is None:
        static_strings = [
            StaticString(string="STATIC_MARKER", offset=raw + STATIC_OFFSET, encoding=StringEncoding.ASCII)
        ]
    if language_strings is None:
        language_strings = [
            StaticString(string="LANG_MARKER", offset=raw + LANGUAGE_OFFSET, encoding=StringEncoding.UTF8)
        ]

    doc = ResultDocument(
        metadata=Metadata(file_path=str(file_path), imagebase=imagebase, min_length=4),
        strings=Strings(static_strings=static_strings, language_strings=language_strings),
    )
    results_path = tmp_path / "results.json"
    results_path.write_bytes(TypeAdapter(ResultDocument).dump_json(doc))
    return results_path


def run_script_process(script: str, results_path: Path, sample: Path | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(get_script_path(script)), str(results_path)]
    if sample is not None:
        cmd += ["--sample", str(sample)]
    return subprocess.run(cmd, capture_output=True)


def run_script(script: str, results_path: Path, sample: Path | None = None) -> str:
    p = run_script_process(script, results_path, sample)
    assert p.returncode == 0, p.stderr.decode()
    return p.stdout.decode("utf-8")


@pytest.fixture
def expected_addresses() -> tuple[int, int, int, int]:
    """return static VA, language VA, static RVA, language RVA"""
    imagebase, section_va, _ = get_rdata()
    return (
        imagebase + section_va + STATIC_OFFSET,
        imagebase + section_va + LANGUAGE_OFFSET,
        section_va + STATIC_OFFSET,
        section_va + LANGUAGE_OFFSET,
    )


@pytest.mark.parametrize(
    "script,annotation_format",
    [
        pytest.param("render-ida-import-script.py", "AppendComment({address:d},", id="ida"),
        pytest.param("render-binja-import-script.py", "AppendComment({address:d},", id="binja"),
        pytest.param("render-ghidra-import-script.py", "append_comment(0x{address:x},", id="ghidra"),
        pytest.param("render-r2-import-script.py", "@ {address:d}", id="r2"),
    ],
)
def test_render_scripts_include_static_and_language_strings(
    tmp_path: Path,
    expected_addresses: tuple[int, int, int, int],
    script: str,
    annotation_format: str,
):
    imagebase, _, _ = get_rdata()
    results_path = write_results(tmp_path, SAMPLE, imagebase)
    out = run_script(script, results_path)

    static_va, language_va, _, _ = expected_addresses
    assert annotation_format.format(address=static_va) in out
    assert annotation_format.format(address=language_va) in out


def test_x64dbg_includes_static_and_language_strings(tmp_path: Path, expected_addresses: tuple[int, int, int, int]):
    imagebase, _, _ = get_rdata()
    results_path = write_results(tmp_path, SAMPLE, imagebase)
    out = run_script("render-x64dbg-database.py", results_path)

    export = json.loads(out)
    addresses = {comment["address"] for comment in export["comments"]}
    texts = "\n".join(comment["text"] for comment in export["comments"])

    _, _, static_rva, language_rva = expected_addresses
    assert hex(static_rva) in addresses
    assert hex(language_rva) in addresses
    assert "STATIC_MARKER" in texts
    assert "LANG_MARKER" in texts


def test_render_uses_pe_imagebase_when_metadata_is_zero(tmp_path: Path, expected_addresses: tuple[int, int, int, int]):
    """static-only FLOSS runs leave metadata.imagebase at zero."""
    results_path = write_results(tmp_path, SAMPLE, imagebase=0)
    out = run_script("render-ida-import-script.py", results_path)

    static_va, language_va, _, _ = expected_addresses
    assert "AppendComment(%d," % static_va in out
    assert "AppendComment(%d," % language_va in out


def test_render_warns_for_non_pe_sample(tmp_path: Path):
    results_path = write_results(tmp_path, ELF_SAMPLE, imagebase=0)
    out = run_script("render-ida-import-script.py", results_path)

    assert "2 static and language strings could not be translated to VAs" in out
    assert "STATIC_MARKER" not in out


def test_render_warns_for_missing_sample(tmp_path: Path):
    results_path = write_results(tmp_path, tmp_path / "missing.exe", imagebase=0)
    out = run_script("render-ida-import-script.py", results_path)

    assert "2 static and language strings could not be translated to VAs" in out


def test_sample_override_maps_when_recorded_path_is_missing(
    tmp_path: Path, expected_addresses: tuple[int, int, int, int]
):
    """--sample overrides the (unavailable) path recorded in the JSON."""
    results_path = write_results(tmp_path, tmp_path / "missing.exe", imagebase=0)
    out = run_script("render-ida-import-script.py", results_path, sample=SAMPLE)

    static_va, language_va, _, _ = expected_addresses
    assert "AppendComment(%d," % static_va in out
    assert "AppendComment(%d," % language_va in out


def test_sample_override_warns_when_override_itself_is_missing(tmp_path: Path):
    results_path = write_results(tmp_path, SAMPLE, imagebase=0)
    out = run_script("render-ida-import-script.py", results_path, sample=tmp_path / "also-missing.exe")

    assert "2 static and language strings could not be translated to VAs" in out
    # nothing mapped: only the AppendComment function definition remains
    assert out.count("AppendComment(") == 1


def test_render_maps_header_strings(tmp_path: Path):
    imagebase, _, _ = get_rdata()
    results_path = write_results(
        tmp_path,
        SAMPLE,
        imagebase,
        static_strings=[StaticString(string="HEADER_MARKER", offset=0x4D, encoding=StringEncoding.ASCII)],
        language_strings=[],
    )
    out = run_script("render-ida-import-script.py", results_path)

    assert "AppendComment(%d," % (imagebase + 0x4D) in out


def test_render_skips_overlay_strings(tmp_path: Path):
    pe = pefile.PE(str(SAMPLE))
    last_mapped = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections if s.SizeOfRawData)
    offset = SAMPLE.stat().st_size - 1
    assert offset >= last_mapped

    imagebase, _, _ = get_rdata()
    results_path = write_results(
        tmp_path,
        SAMPLE,
        imagebase,
        static_strings=[StaticString(string="OVERLAY_MARKER", offset=offset, encoding=StringEncoding.ASCII)],
        language_strings=[],
    )
    out = run_script("render-ida-import-script.py", results_path)

    assert "1 static and language strings could not be translated to VAs" in out
    assert "AppendComment" in out  # function definition is still present
    assert "OVERLAY_MARKER" not in out


def test_no_missing_sample_warning_without_static_strings(tmp_path: Path):
    results_path = write_results(
        tmp_path,
        tmp_path / "missing.exe",
        imagebase=0,
        static_strings=[],
        language_strings=[],
    )
    p = run_script_process("render-ida-import-script.py", results_path)

    assert p.returncode == 0, p.stderr.decode()
    assert b"sample file not found" not in p.stderr


def test_duplicate_static_strings_are_emitted_once(tmp_path: Path):
    _, _, raw = get_rdata()
    duplicate = StaticString(string="DUPLICATE_MARKER", offset=raw + STATIC_OFFSET, encoding=StringEncoding.ASCII)
    imagebase, _, _ = get_rdata()
    results_path = write_results(
        tmp_path,
        SAMPLE,
        imagebase,
        static_strings=[duplicate, duplicate],
        language_strings=[],
    )
    out = run_script("render-r2-import-script.py", results_path)

    assert out.count("CCu") == 1


def test_ida_generated_script_has_annotation_fallback(tmp_path: Path):
    imagebase, _, _ = get_rdata()
    results_path = write_results(tmp_path, SAMPLE, imagebase)
    out = run_script("render-ida-import-script.py", results_path)

    assert "create_data(ea, FF_BYTE" in out
    assert "ida_mark.put_bookmark" in out


def test_ghidra_uses_static_bookmark_category(tmp_path: Path):
    imagebase, _, _ = get_rdata()
    results_path = write_results(tmp_path, SAMPLE, imagebase)
    out = run_script("render-ghidra-import-script.py", results_path)

    assert '"static_string"' in out

# Copyright 2021 Google LLC
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

import pytest
from fixtures import scfile, exefile

import floss.main
from floss.cli import StringType


def test_functions(exefile):
    # 0x1111111 is not a function
    assert floss.main.main([exefile, "--analyze-functions", "0x1111111"]) == -1

    # ok
    assert floss.main.main([exefile, "--analyze-functions", "0x401560"]) == 0
    assert floss.main.main([exefile, "--analyze-functions", "0x401560", "0x401000"]) == 0

    # --string-type static only cannot be combined with --analyze-functions
    assert floss.main.main([exefile, "--analyze-functions", "0x401560", "--string-type", "static"]) == -1


def test_shellcode(scfile):
    # ok
    assert floss.main.main([scfile, "-f", "sc32"]) == 0
    assert floss.main.main([scfile, "--format", "sc64"]) == 0

    # fail
    assert floss.main.main([scfile, "--format", "pe"]) == -1


@pytest.mark.parametrize("type_", [t.value for t in StringType])
@pytest.mark.parametrize("analysis", ("--string-type", "--no-string-type"))
def test_args_analysis_type(exefile, analysis, type_):
    assert (
        floss.main.main(
            [
                exefile,
                analysis,
                type_,
            ]
        )
        == 0
    )


def test_args_analysis_type_conflict(exefile):
    assert floss.main.main([exefile, "--string-type", "stack", "--no-string-type", "tight"]) == -1


def test_language_extraction_independent_of_static(capsys):
    """language strings are extracted even when static strings are disabled.

    uses --string-type language (so only language extraction runs) and -y so the
    deobfuscation prompt is skipped, on a Go sample whose language is detectable.
    """
    import json

    sample = Path(__file__).parent / "data" / "language" / "go" / "go-hello" / "bin" / "go-hello64.exe"

    assert floss.main.main([str(sample), "--string-type", "language", "-y", "-j"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["metadata"]["language"] == "go"
    assert len(doc["strings"]["language_strings"]) > 0
    assert doc["strings"]["static_strings"] == []


def test_manual_language_override_wins_over_auto_detect(capsys):
    """--language go must be honored even when auto-detection returns unknown."""
    import json

    # a C binary, so auto-detection yields unknown; forcing go must stick
    sample = Path(__file__).parent / "data" / "src" / "decode-in-place" / "bin" / "test-decode-in-place.exe"

    assert floss.main.main([str(sample), "--language", "go", "--string-type", "language", "-y", "-j"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["metadata"]["language"] == "go"
    assert doc["metadata"]["language_selected"] == "go"


def test_manual_language_override_beats_wrong_auto_detect(monkeypatch, capsys):
    """--language go must win even when auto-detection wrongly says rust."""
    import json

    import floss.language.identify

    def fake_identify(sample, static_strings):
        from floss.language.identify import Language

        return Language.RUST, "1.75.0"

    monkeypatch.setattr(floss.language.identify, "identify_language_and_version", fake_identify)

    sample = Path(__file__).parent / "data" / "src" / "decode-in-place" / "bin" / "test-decode-in-place.exe"
    assert floss.main.main([str(sample), "--language", "go", "--string-type", "language", "-y", "-j"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["metadata"]["language"] == "go"
    assert doc["metadata"]["language_version"] == ""
    assert doc["metadata"]["language_selected"] == "go"


def test_expand_string_types():
    from floss.utils import expand_string_types

    assert set(expand_string_types(["all"])) == {"static", "stack", "tight", "decoded", "language"}
    assert expand_string_types(["static", "stack"]) == ["static", "stack"]


def test_no_layout_yields_classic_static(exefile):
    """enable_layout=False: no layout tree; classic static strings still present."""
    from pathlib import Path

    from floss.results import Analysis
    from floss.pipeline import Options, analyze

    results = analyze(
        Options(
            sample=Path(exefile),
            min_length=4,
            analysis=Analysis(
                enable_static_strings=True,
                enable_stack_strings=False,
                enable_tight_strings=False,
                enable_decoded_strings=False,
                enable_layout=False,
                enable_tags=True,
            ),
            prompt_deobfuscation=False,
        )
    )
    assert results is not None
    assert results.layout is None
    assert len(results.strings.static_strings) > 0


def test_no_tags_skips_tag_databases(exefile):
    """enable_tags=False: layout present; no DB tags (#common, #winapi, …).

    Layout-intrinsic tags such as #code / #duplicate may still appear.
    """
    from pathlib import Path

    from floss.results import Analysis, ResultLayout
    from floss.pipeline import Options, analyze

    results = analyze(
        Options(
            sample=Path(exefile),
            min_length=4,
            analysis=Analysis(
                enable_static_strings=True,
                enable_stack_strings=False,
                enable_tight_strings=False,
                enable_decoded_strings=False,
                enable_layout=True,
                enable_tags=False,
            ),
            prompt_deobfuscation=False,
        )
    )
    assert results is not None
    assert results.layout is not None
    assert isinstance(results.layout, ResultLayout)

    def all_tags(layout):
        tags = set()
        for s in layout.strings:
            tags.update(s.tags)
        for child in layout.children:
            tags.update(all_tags(child))
        return tags

    tags = all_tags(results.layout)
    # database-backed tags must be absent when tag DBs are disabled
    for db_tag in ("#common", "#winapi", "#capa", "#msvc", "#openssl"):
        assert db_tag not in tags
    for s in results.strings.static_strings:
        for db_tag in ("#common", "#winapi", "#capa", "#msvc", "#openssl"):
            assert db_tag not in s.tags


def test_yes_skips_deobfuscation_for_go(capsys):
    """-y/--yes on a Go sample defaults to not running deobfuscation."""
    import json

    sample = Path(__file__).parent / "data" / "language" / "go" / "go-hello" / "bin" / "go-hello64.exe"

    assert floss.main.main([str(sample), "-y", "-j"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["metadata"]["language"] == "go"
    assert doc["analysis"]["enable_stack_strings"] is False
    assert doc["analysis"]["enable_tight_strings"] is False
    assert doc["analysis"]["enable_decoded_strings"] is False

# Copyright 2020 Google LLC
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


import json
import hashlib

import pytest
import fixtures
from fixtures import scfile, exefile

import floss.main
from floss.results import Analysis, read
from floss.version import __version__
from floss.pipeline import Options, analyze


@pytest.mark.parametrize("arg", ["-h", "--help"])
def test_main_help(capsys, arg):
    with pytest.raises(SystemExit) as e:
        floss.main.main([arg])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert "usage: floss" in out
    assert "--json" in out
    assert "FLOSS_CACHE_DIR" in out


def test_main_no_args_prints_short_help(capsys):
    assert floss.main.main([]) == 1
    short = capsys.readouterr().out
    with pytest.raises(SystemExit):
        floss.main.main(["-h"])
    full = capsys.readouterr().out

    assert "usage: floss" in short
    assert "floss -h" in short
    assert "--json" not in short
    examples = [line.strip() for line in short.splitlines() if line.startswith("  floss ")]
    assert examples
    assert all(example in full for example in examples)


def test_main_version(capsys):
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        floss.main.main(["--version"])
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out


def test_main(exefile):
    assert floss.main.main([exefile]) == 0


@pytest.fixture
def empty_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"")
    return sample


def test_main_json_empty_file_emits_empty_document(empty_file, capsys):
    assert floss.main.main([str(empty_file), "-j"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["metadata"]["sha256"] == hashlib.sha256(b"").hexdigest()
    assert not any(doc["strings"].values())
    assert not doc["analysis"]["enable_stack_strings"]
    assert not doc["analysis"]["enable_tight_strings"]
    assert not doc["analysis"]["enable_decoded_strings"]
    assert doc["layout"]["length"] == 0
    assert doc["layout"]["strings"] == []
    assert doc["layout"]["children"] == []


def test_main_empty_file_document_round_trips(empty_file, tmp_path, capsys):
    assert floss.main.main([str(empty_file), "-j"]) == 0
    out = capsys.readouterr().out
    results = tmp_path / "sample.json"
    results.write_text(out)
    assert read(results).metadata.sha256 == hashlib.sha256(b"").hexdigest()

    assert floss.main.main([str(results), "-j"]) == 0
    reloaded = json.loads(capsys.readouterr().out)
    original = json.loads(out)
    for key in ("strings", "layout"):
        assert reloaded[key] == original[key]
    assert reloaded["metadata"]["sha256"] == original["metadata"]["sha256"]
    assert floss.main.main([str(results)]) == 0


@pytest.mark.parametrize("language", ["go", "rust"])
def test_main_empty_file_with_forced_language(empty_file, language, capsys):
    assert floss.main.main([str(empty_file), "-j", "--language", language]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["metadata"]["language"] == language
    assert doc["strings"]["language_strings"] == []


def test_main_without_static_strings_still_deobfuscates(scfile, capsys):
    # no static string reaches -n 6, but the shellcode builds nine longer stack strings
    assert floss.main.main([scfile, "-j", "-q", "--format", "sc32", "-n", "6"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["strings"]["static_strings"] == []
    assert doc["analysis"]["enable_stack_strings"]
    assert "Invalid data received!" in {s["string"] for s in doc["strings"]["stack_strings"]}


def test_analyze_does_not_mutate_caller_analysis(empty_file):
    analysis = Analysis()
    analyze(Options(sample=empty_file, min_length=4, analysis=analysis))
    assert analysis == Analysis()

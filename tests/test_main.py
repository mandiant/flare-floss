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


import pytest
import fixtures
from fixtures import exefile

import floss.main
from floss.version import __version__


def test_main_help(capsys):
    for help_str in ("-h", "--help"):
        # via https://medium.com/python-pandemonium/testing-sys-exit-with-pytest-10c6e5f7726f
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            floss.main.main([help_str])
        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == 0
        out = capsys.readouterr().out
        assert "usage:" in out
        assert "--json" in out

    # running without arguments prints the same help and exits with code 1
    assert floss.main.main([]) == 1
    out = capsys.readouterr().out
    assert "usage:" in out
    assert "--json" in out


def test_main_version(capsys):
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        floss.main.main(["--version"])
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out


def test_main(exefile):
    assert floss.main.main([exefile]) == 0


@pytest.mark.parametrize("content", [b"", b"\x01\x02\x03abc"], ids=["empty", "no-strings"])
def test_main_json_without_strings_emits_empty_document(tmp_path, capsys, content):
    import json
    import hashlib

    from floss.results import ResultDocument

    sample = tmp_path / "sample.bin"
    sample.write_bytes(content)

    assert floss.main.main([str(sample), "-j"]) == 0
    out = capsys.readouterr().out
    results = tmp_path / "sample.json"
    results.write_text(out)
    doc = ResultDocument.parse_file(results)
    assert doc.metadata.sha256 == hashlib.sha256(content).hexdigest()
    assert doc.strings.static_strings == []
    assert doc.strings.stack_strings == []
    assert not doc.analysis.enable_stack_strings
    assert not doc.analysis.enable_tight_strings
    assert not doc.analysis.enable_decoded_strings
    assert doc.layout is not None
    assert (doc.layout.name, doc.layout.offset, doc.layout.length) == ("binary", 0, len(content))
    assert doc.layout.strings == []
    assert doc.layout.children == []

    assert floss.main.main([str(results), "-j"]) == 0
    reloaded = json.loads(capsys.readouterr().out)
    original = json.loads(out)
    for key in ("strings", "layout"):
        assert reloaded[key] == original[key]
    assert reloaded["metadata"]["sha256"] == original["metadata"]["sha256"]
    assert floss.main.main([str(results)]) == 0

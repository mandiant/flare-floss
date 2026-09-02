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

"""Standalone HTML report renderer and --html CLI."""

from pathlib import Path

import pytest
from fixtures import exefile

import floss.main
import floss.render.html
import floss.render.json
from floss.results import (
    Strings,
    Analysis,
    Metadata,
    ResultLayout,
    ResultString,
    ResultDocument,
)

MINIMAL_TEMPLATE = """<!doctype html>
<html>
<body>
<script>
  window.flossResults = null; /* FLOSS_RESULTS */
</script>
</body>
</html>
"""


def _doc_with_string(text: str) -> ResultDocument:
    return ResultDocument(
        metadata=Metadata(file_path="sample.exe", min_length=4),
        analysis=Analysis(),
        strings=Strings(),
        layout=ResultLayout(
            name="pe",
            offset=0,
            length=0x1000,
            strings=[
                ResultString(
                    string=text,
                    offset=0x100,
                    size=len(text),
                    encoding="ascii",
                    tags=["#winapi"],
                    structure="import table",
                )
            ],
            children=[],
        ),
    )


def test_html_render_injects_json():
    html = floss.render.html.render(_doc_with_string("kernel32.dll"), template=MINIMAL_TEMPLATE)
    assert "window.flossResults = " in html
    assert "null; /* FLOSS_RESULTS */" not in html
    assert "/* FLOSS_RESULTS */" in html
    assert "kernel32.dll" in html
    assert '"file_path": "sample.exe"' in html


def test_html_escapes_script_breaker():
    html = floss.render.html.render(_doc_with_string("</script>"), template=MINIMAL_TEMPLATE)
    assert html.count("</script>") == 1
    assigned = html.split("window.flossResults = ", 1)[1].split("; /* FLOSS_RESULTS */", 1)[0]
    assert "</script>" not in assigned
    assert "\\u003c/script\\u003e" in assigned


def test_html_escapes_angle_brackets():
    html = floss.render.html.render(_doc_with_string("<hello>"), template=MINIMAL_TEMPLATE)
    assigned = html.split("window.flossResults = ", 1)[1].split("; /* FLOSS_RESULTS */", 1)[0]
    assert "<hello>" not in assigned
    assert "\\u003chello\\u003e" in assigned


def test_html_missing_placeholder():
    with pytest.raises(floss.render.html.HtmlTemplateError, match="placeholder"):
        floss.render.html.render(_doc_with_string("x"), template="<html></html>")


def test_html_require_rejects_missing_placeholder(tmp_path, monkeypatch):
    path = tmp_path / "index.html"
    path.write_text("<html></html>", encoding="utf-8")
    monkeypatch.setattr(floss.render.html, "get_html_template_path", lambda: path)
    with pytest.raises(floss.render.html.HtmlTemplateError, match="placeholder"):
        floss.render.html.require_html_template()


def test_html_missing_template_file(tmp_path, monkeypatch):
    missing = tmp_path / "viewer" / "dist" / "index.html"
    monkeypatch.setattr(floss.render.html, "get_html_template_path", lambda: missing)
    with pytest.raises(floss.render.html.HtmlTemplateError, match="not found"):
        floss.render.html.require_html_template()
    with pytest.raises(floss.render.html.HtmlTemplateError, match="not found"):
        floss.render.html.render(_doc_with_string("x"))


def test_html_and_json_conflict(exefile, capsys):
    assert floss.main.main([exefile, "--html", "-j"]) == -1
    captured = capsys.readouterr()
    assert "cannot be combined" in captured.out + captured.err


def test_html_missing_template_cli(exefile, tmp_path, monkeypatch, capsys):
    missing = tmp_path / "no-such-index.html"
    monkeypatch.setattr(floss.render.html, "get_html_template_path", lambda: missing)
    assert floss.main.main([exefile, "--html"]) == -1
    captured = capsys.readouterr()
    assert "HTML template not found" in captured.out + captured.err


def test_html_template_path_is_next_to_renderer():
    """pip, source, and the standalone exe all use floss/render/templates/index.html."""
    path = floss.render.html.get_html_template_path()
    assert path == Path(floss.render.html.__file__).resolve().parent / "templates" / "index.html"


def test_html_from_sample(exefile, tmp_path, monkeypatch, capsys):
    """end-to-end --html using a fixture template so CI does not need npm."""
    template_path = tmp_path / "index.html"
    template_path.write_text(MINIMAL_TEMPLATE, encoding="utf-8")
    monkeypatch.setattr(floss.render.html, "get_html_template_path", lambda: template_path)
    assert floss.main.main([exefile, "--html", "--string-type", "static"]) == 0
    out = capsys.readouterr().out
    assert "window.flossResults =" in out
    assigned = out.split("window.flossResults = ", 1)[1].split("; /* FLOSS_RESULTS */", 1)[0]
    assert assigned.startswith("{")
    assert "test-decode-in-place.exe" in out
    assert floss.render.html.RESULTS_PLACEHOLDER not in out


def test_html_from_results_json(tmp_path, monkeypatch, capsys):
    doc = _doc_with_string("kernel32.dll")
    json_path = tmp_path / "results.json"
    json_path.write_text(floss.render.json.render(doc), encoding="utf-8")
    template_path = tmp_path / "index.html"
    template_path.write_text(MINIMAL_TEMPLATE, encoding="utf-8")
    monkeypatch.setattr(floss.render.html, "get_html_template_path", lambda: template_path)

    assert floss.main.main([str(json_path), "--html"]) == 0
    out = capsys.readouterr().out
    assert "window.flossResults =" in out
    assert "kernel32.dll" in out
    assigned = out.split("window.flossResults = ", 1)[1].split("; /* FLOSS_RESULTS */", 1)[0]
    assert assigned.startswith("{")

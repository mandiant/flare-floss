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

"""Render a ResultDocument as a standalone HTML report.

The report is the pre-built web viewer (``viewer/dist/index.html``) with the
result document assigned to ``window.flossResults``. Open the file in a browser;
no local server is required.
"""

from __future__ import annotations

import sys
from pathlib import Path

import floss.render.json
from floss.results import ResultDocument

# must match the inline script in viewer/index.html
RESULTS_PLACEHOLDER = "window.flossResults = null; /* FLOSS_RESULTS */"


class HtmlTemplateError(ValueError):
    """the viewer HTML template is missing or does not contain the results placeholder."""


def get_html_template_path() -> Path:
    """path to the pre-built viewer HTML.

    under PyInstaller this is ``_MEIPASS/viewer/dist/index.html``.
    in a source checkout it is ``<repo>/viewer/dist/index.html``.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        root = Path(getattr(sys, "_MEIPASS"))
        return root / "viewer" / "dist" / "index.html"
    repo_root = Path(__file__).resolve().parent.parent.parent
    return repo_root / "viewer" / "dist" / "index.html"


def require_html_template() -> Path:
    """return the template path, or raise if the built viewer is not present."""
    path = get_html_template_path()
    if not path.is_file():
        raise HtmlTemplateError(
            "HTML template not found at %s. Build the viewer:\n  cd viewer && npm install && npm run build" % path
        )
    return path


def _escape_json_for_script(payload: str) -> str:
    """make a JSON payload safe to embed inside a ``<script>`` tag."""
    return (
        payload.replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def render(doc: ResultDocument, template: str | None = None) -> str:
    """return the viewer HTML with ``doc`` assigned to ``window.flossResults``.

    ``template`` is the viewer HTML string. when omitted, the pre-built file
    from :func:`get_html_template_path` is read.
    """
    if template is None:
        template = require_html_template().read_text(encoding="utf-8")
    if RESULTS_PLACEHOLDER not in template:
        raise HtmlTemplateError("HTML template is missing the FLOSS_RESULTS placeholder")
    payload = _escape_json_for_script(floss.render.json.render(doc))
    return template.replace(RESULTS_PLACEHOLDER, "window.flossResults = %s; /* FLOSS_RESULTS */" % payload, 1)

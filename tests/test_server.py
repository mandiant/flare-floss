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


import json
import errno
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import floss.main
import floss.server
import floss.render.json
from floss.results import Analysis, Metadata, ResultDocument

VIEWER_HTML = b"<html><body>floss viewer</body></html>"


def start_server(results=None, viewer_html=None, port=0):
    httpd = floss.server.create_server(results, viewer_html, port)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def fetch(httpd, path):
    url = f"http://127.0.0.1:{httpd.server_address[1]}{path}"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read(), r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type")


@pytest.fixture
def minimal_results():
    return ResultDocument(metadata=Metadata(file_path="test.exe", min_length=4), analysis=Analysis())


def test_viewer_page_200_when_built():
    httpd = start_server(results=None, viewer_html=VIEWER_HTML)
    try:
        status, body, content_type = fetch(httpd, "/")
        assert status == 200
        assert body == VIEWER_HTML
        assert "text/html" in content_type
    finally:
        httpd.shutdown()


def test_viewer_page_clear_404_when_not_built():
    httpd = start_server(results=None, viewer_html=None)
    try:
        status, body, _ = fetch(httpd, "/")
        assert status == 404
        assert b"not bundled" in body
    finally:
        httpd.shutdown()


def test_results_endpoint_404_without_results():
    httpd = start_server(results=None, viewer_html=VIEWER_HTML)
    try:
        status, body, _ = fetch(httpd, floss.server.RESULTS_ENDPOINT)
        assert status == 404
        assert b"no results" in body
    finally:
        httpd.shutdown()


def test_results_endpoint_200_with_results(minimal_results):
    httpd = start_server(results=minimal_results, viewer_html=VIEWER_HTML)
    try:
        status, body, content_type = fetch(httpd, floss.server.RESULTS_ENDPOINT)
        assert status == 200
        assert content_type == "application/json"
        doc = json.loads(body)
        assert doc["metadata"]["file_path"] == "test.exe"
        assert "layout" in doc
    finally:
        httpd.shutdown()


def test_unknown_path_404():
    httpd = start_server(results=None, viewer_html=VIEWER_HTML)
    try:
        status, _, _ = fetch(httpd, "/does-not-exist")
        assert status == 404
    finally:
        httpd.shutdown()


def test_serve_bind_permission_denied(monkeypatch, caplog):
    """a privileged port that cannot be bound fails with a clear message, not a traceback."""

    def boom(*args, **kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(floss.server, "create_server", boom)
    with caplog.at_level("ERROR", logger="floss.server"):
        rc = floss.server.serve(None, 128)
    assert rc == 1
    assert "128" in caplog.text
    assert "privileged" in caplog.text


def test_serve_bind_port_in_use(monkeypatch, caplog):
    """an occupied port fails with a clear message, not a traceback."""

    def boom(*args, **kwargs):
        raise OSError(errno.EADDRINUSE, "Address already in use")

    monkeypatch.setattr(floss.server, "create_server", boom)
    with caplog.at_level("ERROR", logger="floss.server"):
        rc = floss.server.serve(None, 8080)
    assert rc == 1
    assert "8080" in caplog.text
    assert "in use" in caplog.text


def test_get_viewer_path_missing(monkeypatch):
    """without a built viewer, the source path resolves to nothing."""
    monkeypatch.setattr(floss.server, "VIEWER_SOURCE_REL", Path("does-not-exist") / "index.html")
    assert floss.server.get_viewer_path() is None
    assert floss.server.load_viewer_html() is None


def test_cli_server_flag_without_sample(monkeypatch):
    """--server without a sample starts the viewer alone; no render is printed."""
    calls = []

    def fake_serve(results, port):
        calls.append((results, port))
        return 0

    monkeypatch.setattr(floss.server, "serve", fake_serve)
    assert floss.main.main(["--server"]) == 0
    assert len(calls) == 1
    results, port = calls[0]
    assert results is None
    assert port == 8080


def test_cli_server_flag_with_port(monkeypatch):
    """--server PORT starts the viewer on the given port."""
    calls = []

    def fake_serve(results, port):
        calls.append((results, port))
        return 0

    monkeypatch.setattr(floss.server, "serve", fake_serve)
    assert floss.main.main(["--server", "12345"]) == 0
    assert calls[0][1] == 12345


def test_cli_server_flag_value_is_sample(monkeypatch, tmp_path):
    """--server <sample> treats the value as the sample, not the port."""
    results_file = tmp_path / "results.json"
    doc = ResultDocument(metadata=Metadata(file_path="test.exe", min_length=4), analysis=Analysis())
    results_file.write_text(floss.render.json.render(doc), encoding="utf-8")

    served = []

    def fake_serve(results, port):
        served.append((results, port))
        return 0

    monkeypatch.setattr(floss.server, "serve", fake_serve)
    assert floss.main.main(["--server", str(results_file)]) == 0
    assert len(served) == 1
    results, port = served[0]
    assert port == 8080
    assert results is not None
    assert results.metadata.file_path.splitlines()[-1] == "test.exe"


def test_cli_server_flag_value_is_port_and_sample(monkeypatch, tmp_path):
    """--server PORT <sample> works with both."""
    results_file = tmp_path / "results.json"
    doc = ResultDocument(metadata=Metadata(file_path="test.exe", min_length=4), analysis=Analysis())
    results_file.write_text(floss.render.json.render(doc), encoding="utf-8")

    served = []

    def fake_serve(results, port):
        served.append((results, port))
        return 0

    monkeypatch.setattr(floss.server, "serve", fake_serve)
    assert floss.main.main(["--server", "12345", str(results_file)]) == 0
    assert served[0][1] == 12345
    assert served[0][0].metadata.file_path.splitlines()[-1] == "test.exe"


def test_cli_server_numeric_sample(monkeypatch, tmp_path):
    """a numeric filename after --server is a sample, not a port."""
    results_file = tmp_path / "12345"
    doc = ResultDocument(metadata=Metadata(file_path="test.exe", min_length=4), analysis=Analysis())
    results_file.write_text(floss.render.json.render(doc), encoding="utf-8")

    served = []

    def fake_serve(results, port):
        served.append((results, port))
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(floss.server, "serve", fake_serve)
    assert floss.main.main(["--server", "12345"]) == 0
    assert len(served) == 1
    results, port = served[0]
    assert port == 8080
    assert results is not None
    assert results.metadata.file_path.splitlines()[-1] == "test.exe"


def test_cli_port_out_of_range():
    assert floss.main.main(["--server", "70000"]) == -1


def test_cli_requires_sample_without_server():
    # sample is only optional when --server is set
    assert floss.main.main(["--json"]) == -1


def test_cli_server_with_results_file(monkeypatch, tmp_path, capsys):
    """--server with a results document serves it instead of printing it."""
    doc = ResultDocument(metadata=Metadata(file_path="test.exe", min_length=4), analysis=Analysis())
    results_file = tmp_path / "results.json"
    results_file.write_text(floss.render.json.render(doc), encoding="utf-8")

    served = []

    def fake_serve(results, port):
        served.append(results)
        return 0

    monkeypatch.setattr(floss.server, "serve", fake_serve)
    assert floss.main.main(["--server", str(results_file)]) == 0
    assert len(served) == 1
    assert served[0].metadata.file_path.splitlines()[-1] == "test.exe"

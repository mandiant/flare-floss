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
import time
import errno
import socket
import struct
import threading
import http.client
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
            return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


def fetch_with_host(httpd, path, host):
    """issue a GET with full control over the Host header (None omits it)."""
    conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
    try:
        conn.putrequest("GET", path, skip_host=True)
        if host is not None:
            conn.putheader("Host", host)
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


@pytest.fixture
def minimal_results():
    return ResultDocument(metadata=Metadata(file_path="test.exe", min_length=4), analysis=Analysis())


def test_viewer_page_200_when_built():
    httpd = start_server(results=None, viewer_html=VIEWER_HTML)
    try:
        status, body, headers = fetch(httpd, "/")
        assert status == 200
        assert body == VIEWER_HTML
        assert "text/html" in headers.get("Content-Type")
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
        status, body, headers = fetch(httpd, floss.server.RESULTS_ENDPOINT)
        assert status == 200
        assert headers.get("Content-Type") == "application/json"
        # BaseHTTPRequestHandler appends an OWS space after the version; strip it
        assert headers.get("Server", "").strip() == "FLOSSViewer/1.0"
        doc = json.loads(body)
        assert doc["metadata"]["file_path"] == "test.exe"
        assert "layout" in doc
    finally:
        httpd.shutdown()


def test_results_body_cached_across_requests(minimal_results):
    """the document is rendered once at startup; every GET serves identical bytes."""
    httpd = start_server(results=minimal_results, viewer_html=VIEWER_HTML)
    try:
        status1, body1, _ = fetch(httpd, floss.server.RESULTS_ENDPOINT)
        status2, body2, _ = fetch(httpd, floss.server.RESULTS_ENDPOINT)
        assert status1 == 200
        assert status2 == 200
        assert body1 == body2
        doc = json.loads(body1)
        assert doc["metadata"]["file_path"] == "test.exe"
    finally:
        httpd.shutdown()


def test_unknown_path_404():
    httpd = start_server(results=None, viewer_html=VIEWER_HTML)
    try:
        status, _, _ = fetch(httpd, "/does-not-exist")
        assert status == 404
    finally:
        httpd.shutdown()


def test_foreign_host_header_rejected(minimal_results):
    """a DNS-rebinding request (foreign Host) must not be able to read results."""
    httpd = start_server(results=minimal_results, viewer_html=VIEWER_HTML)
    try:
        port = httpd.server_address[1]
        for host in (f"evil.example:{port}", "evil.example", ""):
            status, _ = fetch_with_host(httpd, floss.server.RESULTS_ENDPOINT, host)
            assert status == 403
            status, _ = fetch_with_host(httpd, "/", host)
            assert status == 403
    finally:
        httpd.shutdown()


def test_local_host_header_accepted(minimal_results):
    httpd = start_server(results=minimal_results, viewer_html=VIEWER_HTML)
    try:
        port = httpd.server_address[1]
        for host in (f"127.0.0.1:{port}", f"localhost:{port}"):
            status, _ = fetch_with_host(httpd, floss.server.RESULTS_ENDPOINT, host)
            assert status == 200
            status, _ = fetch_with_host(httpd, "/", host)
            assert status == 200
    finally:
        httpd.shutdown()


def test_missing_host_header_accepted():
    """HTTP/1.0 clients may omit Host; they cannot be used for DNS rebinding."""
    httpd = start_server(results=None, viewer_html=VIEWER_HTML)
    try:
        status, _ = fetch_with_host(httpd, "/", None)
        assert status == 200
    finally:
        httpd.shutdown()


def test_client_disconnect_early_keeps_server_working(minimal_results, capfd):
    """a client that resets the connection mid-request must not break later requests."""
    httpd = start_server(results=minimal_results, viewer_html=VIEWER_HTML)
    try:
        port = httpd.server_address[1]
        for _ in range(3):
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            request = f"GET {floss.server.RESULTS_ENDPOINT} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
            sock.sendall(request.encode("utf-8"))
            # reset the connection instead of a clean close to force an error server-side
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.close()
        time.sleep(0.25)
        assert "Traceback" not in capfd.readouterr().err
        status, body, _ = fetch(httpd, "/")
        assert status == 200
        assert body == VIEWER_HTML
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

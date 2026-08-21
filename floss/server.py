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

"""Serve the FLOSS viewer and analysis results over a small local HTTP server.

The standalone FLOSS binary bundles the built viewer (a single self-contained
HTML file) and can hand its analysis results to it, so you do not need to
upload a results file by hand.

The server is meant for local use only: it binds to 127.0.0.1 and is not
intended to be exposed to a network.
"""

from __future__ import annotations

import sys
import errno
import urllib.parse
from typing import Optional
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import floss.logging_
import floss.render.json
from floss.results import ResultDocument

logger = floss.logging_.getLogger(__name__)

HOST = "127.0.0.1"
DEFAULT_PORT = 8080

# URL path at which the analysis results are exposed as JSON
RESULTS_ENDPOINT = "/results"

# where the built viewer page lives inside the packaged binary (_MEIPASS)
VIEWER_DEST = "viewer/index.html"

# where the built viewer page lives in a source checkout after `npm run build`
VIEWER_SOURCE_REL = Path("viewer") / "dist" / "index.html"


class ViewerRequestHandler(BaseHTTPRequestHandler):
    """
    Serves the FLOSS viewer page and the analysis results.

    ``results_body`` and ``viewer_html`` are injected on the class before
    serving (see :func:`create_server`).
    """

    server_version = "FLOSSViewer/1.0"

    # do not advertise the Python version alongside the viewer version
    sys_version = ""

    # cap the time spent reading a request so a slow client cannot tie up a
    # worker thread forever (slowloris guard)
    timeout = 30

    # the analysis results document rendered to JSON bytes, or None when there are no results
    results_body: Optional[bytes] = None

    # the bytes of the built viewer page, or None when it was not bundled
    viewer_html: Optional[bytes] = None

    # Host header values this server accepts, computed by create_server once
    # the actual (possibly ephemeral) port is known; None disables the check
    allowed_hosts: Optional[frozenset] = None

    def do_GET(self):
        if not self._host_allowed():
            self._send_bytes(403, "text/plain; charset=utf-8", b"403 Forbidden\n")
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            self._serve_viewer()
        elif path == RESULTS_ENDPOINT:
            self._serve_results()
        else:
            self._send_bytes(404, "text/plain; charset=utf-8", b"404 Not Found\n")

    def _host_allowed(self) -> bool:
        """
        Only serve requests whose Host header points at this server.

        The server binds to the loopback interface, but a web page open in the
        analyst's browser can re-bind its own domain name (DNS rebinding) to
        127.0.0.1 and would then be able to read the analysis results
        cross-origin. Rejecting foreign Host headers closes that hole; browsers
        always send Host, while simple HTTP/1.0 clients may omit it.
        """
        host = self.headers.get("Host")
        if host is None:
            # HTTP/1.0 clients may omit Host; they cannot drive DNS rebinding
            return True
        if self.allowed_hosts is None:
            # direct instantiation without create_server: no restriction known
            return True
        return host in self.allowed_hosts

    def _serve_viewer(self):
        if self.viewer_html is None:
            self._send_bytes(
                404,
                "text/plain; charset=utf-8",
                (
                    "The FLOSS viewer is not bundled with this binary.\n"
                    "Build it from the viewer/ directory (npm run build) and "
                    "repackage the binary, or run FLOSS from a source checkout "
                    "that has the built viewer.\n"
                ).encode("utf-8"),
            )
            return
        self._send_bytes(200, "text/html; charset=utf-8", self.viewer_html)

    def _serve_results(self):
        if self.results_body is None:
            self._send_bytes(404, "application/json", b'{"error": "no results available"}\n')
            return
        self._send_bytes(200, "application/json", self.results_body)

    def _send_bytes(self, code: int, content_type: str, body: bytes):
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            logger.debug("%s - client disconnected before the response was written", self.address_string())

    def log_message(self, format, *args):  # noqa: A002
        logger.debug("%s - %s", self.address_string(), format % args)


def get_viewer_path() -> Optional[Path]:
    """
    Locate the built viewer page.

    Under a PyInstaller binary this is the packaged ``viewer/index.html`` in
    ``sys._MEIPASS``. From a source checkout this is ``viewer/dist/index.html``,
    present after running ``npm run build`` in the viewer directory.
    """
    if hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS"):
        # pylint/mypy don't like `sys._MEIPASS` because it isn't standard,
        # it is injected by PyInstaller, so fetch it dynamically.
        candidate = Path(getattr(sys, "_MEIPASS")) / VIEWER_DEST
        return candidate if candidate.is_file() else None
    candidate = Path(__file__).resolve().parent.parent / VIEWER_SOURCE_REL
    return candidate if candidate.is_file() else None


def load_viewer_html() -> Optional[bytes]:
    """Return the bytes of the built viewer page, or None if it was not built."""
    path = get_viewer_path()
    if path is None:
        return None
    return path.read_bytes()


def create_server(
    results: Optional[ResultDocument],
    viewer_html: Optional[bytes],
    port: int = DEFAULT_PORT,
) -> ThreadingHTTPServer:
    """Create (but do not start) a server bound to 127.0.0.1."""

    class Handler(ViewerRequestHandler):
        pass

    Handler.results_body = None if results is None else floss.render.json.render(results).encode("utf-8")
    Handler.viewer_html = viewer_html
    httpd = ThreadingHTTPServer((HOST, port), Handler)
    Handler.allowed_hosts = frozenset({f"{HOST}:{httpd.server_port}", f"localhost:{httpd.server_port}"})
    return httpd


def serve(results: Optional[ResultDocument], port: int = DEFAULT_PORT) -> int:
    """
    Start the viewer server and block until interrupted.

    Returns the process exit code.
    """
    viewer_html = load_viewer_html()
    try:
        httpd = create_server(results, viewer_html, port)
    except OSError as e:
        hint = ""
        if e.errno in (errno.EACCES, errno.EPERM):
            hint = "; ports below 1024 are privileged and need elevated permissions, pick a higher port"
        elif e.errno == errno.EADDRINUSE:
            hint = "; that port is already in use"
        logger.error("cannot start the viewer server on port %d: %s%s", port, e.strerror or e, hint)
        return 1

    url = f"http://{HOST}:{httpd.server_address[1]}"

    print(f"Serving the FLOSS viewer at {url}  (Ctrl+C to stop)")
    print("This server listens on 127.0.0.1 only and is not meant to be exposed to a network.")
    if results is None:
        print("No analysis results were provided; upload a results file in the viewer.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down the FLOSS viewer server.")
        httpd.server_close()
    return 0

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

import pickle
from pathlib import Path

import pytest
import fixtures

from floss.main import FLOSS_LOAD_VIV_WORKSPACE_ENV, load_vw

EXECUTED: list[bool] = []

SAMPLE = fixtures.CD / "data" / "src" / "decode-in-place" / "bin" / "test-decode-in-place.exe"


def _hit():
    EXECUTED.append(True)


class _Payload:
    def __reduce__(self):
        return (_hit, ())


def _copy_sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe_"
    path.write_bytes(SAMPLE.read_bytes())
    return path


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv(FLOSS_LOAD_VIV_WORKSPACE_ENV, raising=False)
    EXECUTED.clear()


def test_polyglot_pe_named_viv_does_not_unpickle(tmp_path):
    # "M" is BININT2 and consumes "Z0", so a pickle stream can start right after the MZ magic
    payload = b"MZ0c" + _hit.__module__.encode() + b"\n_hit\n(tR."
    buf = bytearray(SAMPLE.read_bytes())
    buf[: len(payload)] = payload
    path = tmp_path / "sample.viv"
    path.write_bytes(buf)

    vw = load_vw(path, "auto", [])
    assert not EXECUTED
    assert vw.getMeta("Format") == "pe"


@pytest.mark.parametrize("value", [None, "0"])
def test_sibling_viv_ignored_unless_opted_in(tmp_path, monkeypatch, value):
    if value is not None:
        monkeypatch.setenv(FLOSS_LOAD_VIV_WORKSPACE_ENV, value)
    path = _copy_sample(tmp_path)
    Path(f"{path}.viv").write_bytes(b"VIV".ljust(8, b"\x00") + pickle.dumps([_Payload()], protocol=2))

    load_vw(path, "auto", [])
    assert not EXECUTED


def test_sibling_viv_loaded_when_allowed(tmp_path, monkeypatch):
    path = _copy_sample(tmp_path)
    vw = load_vw(path, "auto", [])
    vw.setMeta("floss_test_marker", True)
    vw.saveWorkspace()
    monkeypatch.setenv(FLOSS_LOAD_VIV_WORKSPACE_ENV, "1")

    assert load_vw(path, "auto", []).getMeta("floss_test_marker")


def test_pe_with_msgviv_header_loads_as_pe(tmp_path):
    path = _copy_sample(tmp_path)
    buf = bytearray(path.read_bytes())
    buf[2:8] = b"MSGVIV"
    path.write_bytes(buf)

    vw = load_vw(path, "auto", [])
    assert vw.getMeta("Format") == "pe"

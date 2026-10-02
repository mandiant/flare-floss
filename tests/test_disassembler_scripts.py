# Copyright 2022 Google LLC
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

# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import json
import subprocess
from pathlib import Path
from functools import lru_cache

import pytest

CD = Path(__file__).resolve().parent


def get_disassembler_script_path(s) -> Path:
    return CD / ".." / "scripts" / "disassemblers" / s


def get_file_path() -> Path:
    return CD / "data" / "test-decode-to-stack.exe"


def run_program(script_path: Path, args):
    args = [sys.executable] + [str(script_path)] + args
    print("running: '%s'" % args)
    return subprocess.run(args, capture_output=True)


@lru_cache()
def get_results_file_path():
    res_path = Path("results.json")
    p = run_program(Path("floss/main.py"), ["--no-string-type", "static", "-j", str(get_file_path())])
    with res_path.open("w") as f:
        f.write(p.stdout.decode("utf-8"))
    return str(res_path)


@pytest.mark.parametrize(
    "script,args",
    [
        pytest.param("render-binja-import-script.py", [get_results_file_path()]),
        pytest.param("render-ghidra-import-script.py", [get_results_file_path()]),
        pytest.param("render-ida-import-script.py", [get_results_file_path()]),
        pytest.param("render-r2-import-script.py", [get_results_file_path()]),
        pytest.param("render-x64dbg-database.py", [get_results_file_path()]),
    ],
)
def test_disassembler_scripts(script, args):
    script_path = get_disassembler_script_path(script)
    p = run_program(script_path, args)
    assert p.returncode == 0


def make_result_document(path: Path, address_type: str) -> Path:
    """Write a minimal result document holding one decoded string."""
    document = {
        "metadata": {"file_path": "fixture.exe"},
        "strings": {
            "decoded_strings": [
                {
                    "address": 4096,
                    "address_type": address_type,
                    "string": "DECODED_TEST",
                    "encoding": "ASCII",
                    "decoded_at": 4199808,
                    "decoding_routine": 4199654,
                }
            ]
        },
    }
    path.write_text(json.dumps(document))
    return path


@pytest.mark.parametrize("address_type", ["GLOBAL", "STACK"])
def test_ghidra_script_parses(tmp_path, address_type):
    """The generated Ghidra script has to be valid Python, not just render cleanly."""
    results = make_result_document(tmp_path / f"{address_type.lower()}.json", address_type)

    p = run_program(get_disassembler_script_path("render-ghidra-import-script.py"), [str(results)])

    assert p.returncode == 0
    compile(p.stdout.decode("utf-8"), "apply_floss.py", "exec")

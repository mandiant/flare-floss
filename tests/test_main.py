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
        assert "--html" in out

    # running without arguments prints the same help and exits with code 1
    assert floss.main.main([]) == 1
    out = capsys.readouterr().out
    assert "usage:" in out
    assert "--json" in out
    assert "--html" in out


def test_main_version(capsys):
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        floss.main.main(["--version"])
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out


def test_main(exefile):
    assert floss.main.main([exefile]) == 0

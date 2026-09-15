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


import pytest

import floss.main


@pytest.mark.parametrize("shell", ["bash", "zsh", "tcsh", "fish", "powershell"])
def test_print_completion(shell, capsys):
    """--print-completion emits a non-empty completion script and exits cleanly."""
    with pytest.raises(SystemExit) as excinfo:
        floss.main.main(["--print-completion", shell])
    assert excinfo.value.code == 0

    out = capsys.readouterr().out
    assert out.strip()
    # all generated scripts reference the program by name
    assert "floss" in out


def test_print_completion_bash(capsys):
    """the bash script completes flags, choices, and the sample file path."""
    with pytest.raises(SystemExit):
        floss.main.main(["--print-completion", "bash"])

    out = capsys.readouterr().out
    assert "--string-type" in out
    # choice values from argparse are embedded
    assert "static stack tight decoded language all" in out
    # the sample positional completes file paths
    assert "_shtab_compgen_files" in out


def test_print_completion_zsh(capsys):
    """the zsh script uses the #compdef header so compinit registers it."""
    with pytest.raises(SystemExit):
        floss.main.main(["--print-completion", "zsh"])

    out = capsys.readouterr().out
    assert out.startswith("#compdef floss")


def test_print_completion_fish(capsys):
    """the fish script registers completions for the program."""
    with pytest.raises(SystemExit):
        floss.main.main(["--print-completion", "fish"])

    out = capsys.readouterr().out
    assert "complete -c floss" in out


@pytest.mark.parametrize("shell", ["badshell", ""])
def test_print_completion_invalid_shell(shell, capsys):
    """an unknown shell is an argument error, not a crash."""
    assert floss.main.main(["--print-completion", shell]) == -1

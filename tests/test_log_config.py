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

import logging

from floss.cli import set_log_config
from floss.logging_ import DebugLevel


def test_goblin_warnings_are_silenced_by_default():
    set_log_config(DebugLevel.NONE, quiet=False)
    assert not logging.getLogger("goblin.pe.import").isEnabledFor(logging.WARNING)
    assert logging.getLogger("goblin").isEnabledFor(logging.ERROR)


def test_goblin_warnings_are_silenced_with_default_debug():
    set_log_config(DebugLevel.DEFAULT, quiet=False)
    assert not logging.getLogger("goblin.pe.import").isEnabledFor(logging.WARNING)


def test_goblin_warnings_are_enabled_at_trace():
    set_log_config(DebugLevel.TRACE, quiet=False)
    assert logging.getLogger("goblin.pe.import").isEnabledFor(logging.WARNING)

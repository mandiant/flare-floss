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

"""Deprecated entry point.

Layout-aware static analysis is the default for ``floss``. Prefer::

    floss sample.exe
    floss sample.exe -j
    floss --no stack tight decoded sample.exe

This module remains so ``python -m floss.quantum`` and the old console script
forward into the unified CLI with a deprecation warning.
"""

from __future__ import annotations

import sys
import warnings

from floss.layout.extract import MIN_STR_LEN

# re-export for scripts that imported this constant
__all__ = ["MIN_STR_LEN", "main"]


def main(argv=None) -> int:
    warnings.warn(
        "floss.quantum is deprecated; use `floss` (layout+tags are default for PE/ELF/Mach-O)",
        DeprecationWarning,
        stacklevel=2,
    )
    if argv is None:
        argv = sys.argv[1:]
    # rebuild as floss quantum subcommand path handled in floss.main
    from floss.main import main as floss_main

    return floss_main(["quantum", *argv])


if __name__ == "__main__":
    sys.exit(main())

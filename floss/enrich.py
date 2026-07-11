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

"""Apply layout mapping and tags to FLOSS result documents.

Iteration-1 stub: layout-aware static analysis currently lives in
``floss.quantum``. Full unification with deobfuscation results
is planned for iteration 2.
"""

from __future__ import annotations

from floss.quantum import analyze_path
from floss.document import ResultDocument

__all__ = ["analyze_path", "ResultDocument"]

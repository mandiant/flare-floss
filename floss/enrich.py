# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Apply layout mapping and tags to FLOSS result documents.

Iteration-1 stub: layout-aware static analysis currently lives in
``floss.analyze_static``. Full unification with deobfuscation results
is planned for iteration 2.
"""

from __future__ import annotations

from floss.document import ResultDocument
from floss.analyze_static import analyze_path

__all__ = ["analyze_path", "ResultDocument"]

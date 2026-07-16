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

"""String tagging: tag sources, layout-derived checks, and visibility rules.

Modules like ``expert``, ``gp``, ``oss``, and ``winapi`` are *tag sources* — they
load on-disk classification databases and expose query interfaces. ``engine`` wires
those into ``Tagger`` callables, including layout-derived tags (#code, etc.).
"""

from floss.tags.rules import (
    TagRules,
    should_hide_string,
    hide_strings_by_rules,
    remove_false_positive_lib_strings,
)
from floss.tags.engine import (
    Tagger,
    load_databases,
    query_code_string_database,
    query_winapi_name_database,
    query_expert_string_database,
    query_library_string_database,
    query_global_prevalence_database,
    query_global_prevalence_hash_database,
)

load_taggers = load_databases

__all__ = [
    "Tagger",
    "load_databases",
    "load_taggers",
    "TagRules",
    "remove_false_positive_lib_strings",
    "hide_strings_by_rules",
    "should_hide_string",
]

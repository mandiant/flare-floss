# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""String tagging databases and rules."""

from floss.tags.rules import (
    TagRules,
    should_hide_string,
    hide_strings_by_rules,
    remove_false_positive_lib_strings,
)
from floss.tags.engine import (
    Tagger,
    check_is_xor,
    check_is_code,
    check_is_reloc,
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

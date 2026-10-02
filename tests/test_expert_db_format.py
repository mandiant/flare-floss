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

import re
import json

import re2  # type: ignore
import pytest

from floss.tags import data_root
from floss.tags.expert import DEFAULT_PATHS, ExpertStringDatabase

BLOCKLIST_PATH = data_root() / "expert" / "capa_blocklist.json"


def make_rule(type_: str, value: str, **extra):
    rule = {
        "type": type_,
        "value": value,
        "tag": "#test",
        "action": "highlight",
        "note": "",
        "description": "",
        "authors": [],
        "references": [],
    }
    rule.update(extra)
    return rule


def write_db(tmp_path, rules):
    path = tmp_path / "db.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rules), encoding="utf-8")
    return ExpertStringDatabase.from_file(path)


@pytest.fixture(scope="module")
def default_db():
    return ExpertStringDatabase.from_file(DEFAULT_PATHS[0])


def test_modifier_i_makes_regex_case_insensitive(tmp_path):
    db = write_db(tmp_path, [make_rule("regex", "foo.*bar", modifiers="i")])
    assert db.query("FOO-BAR") == {"#test"}
    assert db.query("foo-bar") == {"#test"}


def test_regex_without_modifier_is_case_sensitive(tmp_path):
    db = write_db(tmp_path, [make_rule("regex", "foo.*bar")])
    assert db.query("FOO-BAR") == set()
    assert db.query("foo-bar") == {"#test"}


def test_slashes_are_pattern_characters_not_delimiters(tmp_path):
    db = write_db(tmp_path, [make_rule("regex", "/x/")])
    assert db.query("a/x/b") == {"#test"}
    assert db.query("x") == set()


def test_default_db_loads(default_db):
    assert len(default_db) > 1700
    assert len(default_db.regex_rules) > 0


def test_default_db_has_no_slash_delimited_regex(default_db):
    for rule, _ in default_db.regex_rules:
        assert not (rule.value.startswith("/") and (rule.value.endswith("/") or rule.value.endswith("/i"))), rule.value


def test_default_db_regex_rules_compile_with_re_and_re2(default_db):
    for rule, _ in default_db.regex_rules:
        pattern = ("(?i)" if "i" in rule.modifiers else "") + rule.value
        re.compile(pattern)
        re2.compile(pattern)


def test_blocklist_parses_and_is_applied(default_db):
    entries = json.loads(BLOCKLIST_PATH.read_text(encoding="utf-8"))
    assert len(entries) > 0

    blocked = set()
    for entry in entries:
        assert entry["type"] in ("string", "substring", "regex")
        assert isinstance(entry["value"], str)
        blocked.add((entry["type"], entry["value"], entry.get("modifiers", "")))

    present = list(default_db.string_rules.values())
    present.extend(default_db.substring_rules)
    present.extend(rule for rule, _ in default_db.regex_rules)

    violations = [(r.type, r.value, r.modifiers) for r in present if (r.type, r.value, r.modifiers) in blocked]
    assert violations == []

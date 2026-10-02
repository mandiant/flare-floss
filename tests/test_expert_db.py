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

import json
import pathlib

import pytest

import floss.strings
from floss.tags.expert import ExpertStringDatabase, get_default_databases

CD = pathlib.Path(__file__).resolve().parent


def _rule(type_: str, value: str, tag: str, modifiers: str = "") -> dict:
    return {
        "type": type_,
        "value": value,
        "modifiers": modifiers,
        "tag": tag,
        "action": "highlight",
        "note": "",
        "description": "",
        "authors": [],
        "references": [],
    }


@pytest.fixture
def small_db(tmp_path: pathlib.Path) -> ExpertStringDatabase:
    rules = [
        _rule("string", "exact-match", "t-string"),
        _rule("substring", "needle", "t-substring"),
        _rule("regex", "foo.*bar", "t-regex-icase", modifiers="i"),
        _rule("regex", "^[0-9]{3}-[0-9]{4}$", "t-regex-plain"),
        _rule("regex", "^(?!x)abc", "t-regex-lookahead"),
    ]
    path = tmp_path / "rules.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rules))
    return ExpertStringDatabase.from_file(path)


def test_small_db_partition(small_db: ExpertStringDatabase):
    assert len(small_db) == 5
    assert len(small_db.regex_rules) == 3
    assert [r.tag for r in small_db.re2_rules] == ["t-regex-icase", "t-regex-plain"]
    assert [r.tag for r, _ in small_db.fallback_rules] == ["t-regex-lookahead"]


@pytest.mark.parametrize(
    "s,expected",
    [
        ("exact-match", {"t-string"}),
        ("exact-match ", set()),
        ("hay needle stack", {"t-substring"}),
        ("fooXbar", {"t-regex-icase"}),
        ("FOO then BAR", {"t-regex-icase"}),
        ("barfoo", set()),
        ("555-1234", {"t-regex-plain"}),
        ("5555-1234", set()),
        ("abcdef", {"t-regex-lookahead"}),
        ("xabc", set()),
        ("needle FOObar 555-1234", {"t-substring", "t-regex-icase"}),
        ("", set()),
    ],
)
def test_small_db_query(small_db: ExpertStringDatabase, s: str, expected: set):
    assert small_db.query(s) == expected


def test_default_db_uses_re2_set():
    for db in get_default_databases():
        assert len(db.regex_rules) > 100
        assert db.fallback_rules == []
        assert len(db.re2_rules) == len(db.regex_rules)


def _brute_force_query(db: ExpertStringDatabase, s: str) -> set:
    ret = set()
    if s in db.string_rules:
        ret.add(db.string_rules[s].tag)
    for rule in db.substring_rules:
        if rule.value in s:
            ret.add(rule.tag)
    for rule, regex in db.regex_rules:
        if regex.search(s):
            ret.add(rule.tag)
    return ret


def test_default_db_matches_brute_force():
    buf = (CD / "data" / "test-decode-to-stack.exe").read_bytes()
    strings = [s.string for s in floss.strings.extract_ascii_unicode_strings(buf, 4)]
    assert len(strings) > 1000
    for db in get_default_databases():
        hits = 0
        for s in strings:
            expected = _brute_force_query(db, s)
            assert db.query(s) == expected, s
            hits += bool(expected)
        assert hits > 0

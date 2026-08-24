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

"""Expert-curated tag source: rules authored by analysts (CAPA-derived, etc.).

The ``floss/tags`` package is named for the user-visible outcome (tags on strings),
not for the on-disk JSONL databases. Each module here is a *tag source*: it loads
serialized classification data and exposes a query interface. ``floss.tags.engine``
wraps those queries into ``Tagger`` callables applied during analysis.
"""

import re
import pathlib
import functools
import importlib.resources
from typing import Set, Dict, List, Tuple, Literal, Optional, Sequence
from dataclasses import dataclass

import msgspec

from floss.tags import data_root, ensure_not_lfs_pointer


class ExpertRule(msgspec.Struct):
    type: Literal["string", "substring", "regex"]
    value: str

    tag: str
    action: Literal["mute", "highlight", "hide"]
    note: str
    description: str

    authors: List[str]
    references: List[str]


@dataclass
class ExpertStringDatabase:
    string_rules: Dict[str, ExpertRule]
    substring_rules: List[ExpertRule]
    regex_rules: List[Tuple[ExpertRule, re.Pattern]]

    def __len__(self) -> int:
        return len(self.string_rules) + len(self.substring_rules) + len(self.regex_rules)

    @functools.cached_property
    def combined_substring_pattern(self) -> Optional[re.Pattern]:
        parts = [re.escape(r.value) for r in self.substring_rules if r.value]
        parts.sort(key=len, reverse=True)
        return re.compile("|".join(parts)) if parts else None

    @functools.cached_property
    def re2_prefilter(self):
        import re2  # type: ignore

        valid = []
        fallback = []
        for rule, regex in self.regex_rules:
            val = rule.value
            if val.startswith("/") and val.endswith("/"):
                val = val[1:-1]
            elif val.startswith("/") and val.endswith("/i"):
                val = "(?i)" + val[1:-2]
            try:
                re2.compile(val)
                valid.append(val)
            except Exception:
                fallback.append((rule, regex))

        p = re2.compile("(?:" + ")|(?:".join(valid) + ")") if valid else None
        return (p, fallback)

    def query(self, s: str) -> Set[str]:
        ret = set()

        if s in self.string_rules:
            ret.add(self.string_rules[s].tag)

        if self.combined_substring_pattern is None or self.combined_substring_pattern.search(s):
            for rule in self.substring_rules:
                if rule.value in s:
                    ret.add(rule.tag)

        r2p, fallback_rules = self.re2_prefilter

        # Always evaluate rules that RE2 rejected natively (like lookaheads)
        for rule, regex in fallback_rules:
            if regex.search(s):
                ret.add(rule.tag)

        # If RE2 hit, evaluate the rest of the rules (which RE2 covers) to find WHICH triggered it.
        # If RE2 didn't hit, we skip checking the rules that RE2 covers.
        if r2p is not None and r2p.search(s):
            for rule, regex in self.regex_rules:
                if regex.search(s):
                    ret.add(rule.tag)
        elif r2p is None:
            # Full native fallback if re2 could not compile ANY rules
            for rule, regex in self.regex_rules:
                if regex.search(s):
                    ret.add(rule.tag)

        return ret

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "ExpertStringDatabase":
        string_rules: Dict[str, ExpertRule] = {}
        substring_rules: List[ExpertRule] = []
        regex_rules: List[Tuple[ExpertRule, re.Pattern]] = []

        ensure_not_lfs_pointer(path)
        decoder = msgspec.json.Decoder(type=ExpertRule)
        buf = path.read_bytes()
        for line in buf.split(b"\n"):
            if not line:
                continue

            rule = decoder.decode(line)
            match rule:
                case ExpertRule(type="string"):
                    # no duplicates today
                    string_rules[rule.value] = rule
                case ExpertRule(type="substring"):
                    substring_rules.append(rule)
                case ExpertRule(type="regex"):
                    # TODO: may have to cleanup the //gi from the regex
                    regex_rules.append((rule, re.compile(rule.value)))
                case _:
                    raise ValueError(f"unexpected rule type: {rule.type}")

        return cls(
            string_rules=string_rules,
            substring_rules=substring_rules,
            regex_rules=regex_rules,
        )


DEFAULT_PATHS = (data_root() / "expert" / "capa.jsonl",)


def get_default_databases() -> Sequence[ExpertStringDatabase]:
    return [ExpertStringDatabase.from_file(path) for path in DEFAULT_PATHS]

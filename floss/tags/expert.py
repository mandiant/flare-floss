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
import logging
import pathlib
import functools
import importlib.resources
from typing import Any, Set, Dict, List, Tuple, Literal, Optional, Sequence
from dataclasses import dataclass

import re2  # type: ignore
import msgspec

from floss.tags import data_root, ensure_not_lfs_pointer

logger = logging.getLogger(__name__)

RE2_MAX_MEM = 80 * 1024 * 1024


class ExpertRule(msgspec.Struct):
    type: Literal["string", "substring", "regex"]
    value: str

    tag: str
    action: Literal["mute", "highlight", "hide"]
    note: str
    description: str

    authors: List[str]
    references: List[str]
    modifiers: str = ""


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
    def _regex_engines(self) -> Tuple[Optional[Any], List[ExpertRule], List[Tuple[ExpertRule, re.Pattern]]]:
        """
        Partition the regex rules into one RE2 set and a Python ``re`` fallback list.

        Returns ``(re2_set, re2_rules, fallback_rules)`` where ``re2_rules[i]`` is the rule
        for set index ``i``. ``re2_set`` is None when the set could not be built, in which
        case ``fallback_rules`` holds every regex rule.
        """
        re2_rules: List[ExpertRule] = []
        fallback_rules: List[Tuple[ExpertRule, re.Pattern]] = []

        try:
            opts = re2.Options()
            opts.max_mem = RE2_MAX_MEM
            opts.log_errors = False
            re2_set = re2.Set.SearchSet(opts)
            for rule, regex in self.regex_rules:
                try:
                    re2_set.Add(regex.pattern)
                except re2.error:
                    fallback_rules.append((rule, regex))
                    continue
                re2_rules.append(rule)

            if not re2_rules:
                return None, [], fallback_rules

            re2_set.Compile()
        except Exception as e:
            logger.warning("failed to build RE2 set for expert regex rules, falling back to Python re: %s", e)
            return None, [], list(self.regex_rules)

        return re2_set, re2_rules, fallback_rules

    @property
    def re2_rules(self) -> List[ExpertRule]:
        return self._regex_engines[1]

    @property
    def fallback_rules(self) -> List[Tuple[ExpertRule, re.Pattern]]:
        return self._regex_engines[2]

    def query(self, s: str) -> Set[str]:
        ret = set()

        if s in self.string_rules:
            ret.add(self.string_rules[s].tag)

        if self.combined_substring_pattern is None or self.combined_substring_pattern.search(s):
            for rule in self.substring_rules:
                if rule.value in s:
                    ret.add(rule.tag)

        re2_set, re2_rules, fallback_rules = self._regex_engines

        for rule, regex in fallback_rules:
            if regex.search(s):
                ret.add(rule.tag)

        if re2_set is not None:
            for index in re2_set.Match(s) or ():
                ret.add(re2_rules[index].tag)

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
                    val = rule.value
                    if "i" in rule.modifiers:
                        val = "(?i)" + val
                    regex_rules.append((rule, re.compile(val)))
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

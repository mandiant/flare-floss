import re
import pathlib
from typing import Set, Dict, List, Tuple, Literal, Sequence
from dataclasses import dataclass

import msgspec

import floss.qs.db


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

    def query(self, s: str) -> Tuple[Set[str], List[ExpertRule]]:
        ret_set = set()
        ret_list = list()

        if s in self.string_rules:
            ret_set.add(self.string_rules[s].tag)
            ret_list.append(self.string_rules[s])

        # note that this is O(m * n)
        # #strings * #rules
        for rule in self.substring_rules:
            if rule.value in s:
                ret_set.add(rule.tag)
                ret_list.append(rule)

        # note that this is O(m * n)
        # #strings * #rules
        for rule, regex in self.regex_rules:
            if regex.search(s):
                ret_set.add(rule.tag)
                ret_list.append(rule)

        return ret_set, ret_list

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "ExpertStringDatabase":
        string_rules: Dict[str, ExpertRule] = {}
        substring_rules: List[ExpertRule] = []
        regex_rules: List[Tuple[ExpertRule, re.Pattern]] = []

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


DEFAULT_PATHS = (pathlib.Path(floss.qs.db.__file__).parent / "data" / "expert" / "capa.jsonl",)


def get_default_databases() -> Sequence[ExpertStringDatabase]:
    return [ExpertStringDatabase.from_file(path) for path in DEFAULT_PATHS]

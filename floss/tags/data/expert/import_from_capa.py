"""
Extract string, substring and regex features from a capa rules checkout
into the expert database format (one JSON document per line).

Usage:
    python import_from_capa.py /path/to/capa/rules > capa.jsonl

Requires capa >= 7 (capa.rules.get_rules) and Python >= 3.10 (match statement).

Output ordering is deterministic: rules are visited sorted by rule name and
features within a rule in document order. The first rule that contributes a
given (type, value, modifiers) key wins; later duplicates are dropped, so a
string shared by several rules is attributed to the alphabetically first rule.
Entries listed in capa_blocklist.json (next to this script) are skipped.
"""

import sys
import json
import pathlib
from typing import Set, Tuple

import msgspec
import capa.rules
import capa.engine
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.basicblock

from floss.tags.expert import ExpertRule


def walk_rule_logic(rule: capa.rules.Rule, node: capa.engine.Statement | capa.engine.Feature):
    match node:
        case (
            capa.features.common.Regex(name=type, value=value)
            | capa.features.common.Substring(name=type, value=value)
            | capa.features.common.String(name=type, value=value)
        ):
            # mypy doesn't seem to be very good at narrowing types here,
            # maybe due to the use of `match` above?
            assert type in ("regex", "substring", "string")  # type: ignore
            assert isinstance(value, str)  # type: ignore

            modifiers = ""
            if type == "regex":
                if value.startswith("/") and value.endswith("/"):
                    value = value[1:-1]
                elif value.startswith("/") and value.endswith("/i"):
                    value = value[1:-2]
                    modifiers = "i"

            yield ExpertRule(
                type=type,  # type: ignore
                value=value,  # type: ignore
                modifiers=modifiers,
                tag="#capa",
                action="highlight",
                note=rule.name[:-33] if rule.is_subscope_rule() else rule.name,
                description=rule.meta.get("description", ""),
                authors=rule.meta.get("authors", []),
                references=rule.meta.get("references", []),
            )
        case (
            capa.engine.And(children=[*children])
            | capa.engine.Or(children=[*children])
            | capa.engine.Some(children=[*children])
        ):
            # children: List[Statement | Feature]
            for child in children:  # type: ignore
                yield from walk_rule_logic(rule, child)
        case capa.engine.Not(child=child) | capa.engine.Range(child=child):
            yield from walk_rule_logic(rule, child)
        case (
            capa.features.insn.Mnemonic()
            | capa.features.insn.Number()
            | capa.features.insn.Offset()
            | capa.features.insn.OperandNumber()
            | capa.features.insn.OperandOffset()
            | capa.features.insn.API()
            | capa.features.insn.Property()
        ):
            pass
        case (
            capa.features.common.MatchedRule()
            | capa.features.common.Arch()
            | capa.features.common.OS()
            | capa.features.common.Format()
            | capa.features.common.Namespace()
            | capa.features.common.Class()
            | capa.features.common.Characteristic()
            | capa.features.common.Bytes()
        ):
            pass
        case (
            capa.features.file.Section()
            | capa.features.file.Export()
            | capa.features.file.Import()
            | capa.features.file.FunctionName()
        ):
            pass
        case capa.features.basicblock.BasicBlock():
            pass
        case _:
            raise ValueError(f"unknown node type: {node}")


def walk_rule(rule: capa.rules.Rule):
    yield from walk_rule_logic(rule, rule.statement)


def load_blocklist(path: pathlib.Path) -> Set[Tuple[str, str, str]]:
    entries = json.loads(path.read_text(encoding="utf-8"))
    return {(e["type"], e["value"], e.get("modifiers", "")) for e in entries}


def main():
    blocklist = load_blocklist(pathlib.Path(__file__).parent / "capa_blocklist.json")
    rules = capa.rules.get_rules([pathlib.Path(sys.argv[1])])
    seen: Set[Tuple[str, str, str]] = set()
    for rule in sorted(rules.rules.values(), key=lambda r: r.name):
        for er in walk_rule(rule):
            key = (er.type, er.value, er.modifiers)
            if key in blocklist or key in seen:
                continue
            seen.add(key)
            print(msgspec.json.encode(er).decode("utf-8"))


if __name__ == "__main__":
    main()

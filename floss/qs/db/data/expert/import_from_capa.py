import sys

import msgspec
import capa.main
import capa.rules
import capa.engine
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.basicblock

from floss.qs.db.expert import ExpertRule


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

            yield ExpertRule(
                type=type,  # type: ignore
                value=value,  # type: ignore
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


rules = capa.main.get_rules([sys.argv[1]])
for rule in rules.rules.values():
    for er in walk_rule(rule):
        print(msgspec.json.encode(er).decode("utf-8"))

# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.

import floss.identify

# feature weights
LOW = 0.25
MEDIUM = 0.50
HIGH = 0.75
SEVERE = 1.00


class Feature:
    def __init__(self, value):
        super(Feature, self).__init__()

        self.name = self.__class__.__name__
        self.value = value

    @property
    def weight(self) -> float:
        # feature weight LOW, MEDIUM, ... (less to more important)
        raise NotImplementedError

    def score(self) -> float:
        # returns a value between 0.0 and 1.0 (less likely to almost certain)
        # can be negative to exclude functions based on a feature
        raise NotImplementedError

    def weighted_score(self):
        return self.weight * self.score()

    def __str__(self):
        return (
            f"{self.name.ljust(20)} = {self.value} (score: {self.score():.2f}, weighted: {self.weighted_score():.2f})"
        )

    def __repr__(self):
        return str(self)


class BlockCount(Feature):
    weight = LOW

    def __init__(self, block_count):
        super(BlockCount, self).__init__(block_count)

    def score(self):
        if self.value > 30:
            # a function with >30 basic blocks is unlikely a string decoding function
            return 0.1
        elif 3 <= self.value <= 10:
            # 3-10 basic blocks is the sweet spot
            return 1.0
        else:
            # everything else is less likely
            return 0.4


class InstructionCount(Feature):
    weight = LOW

    def __init__(self, instruction_count):
        super(InstructionCount, self).__init__(instruction_count)

    def score(self):
        if self.value > 10:
            return 0.8
        else:
            return 0.1


class Arguments(Feature):
    weight = LOW

    def __init__(self, args):
        super(Arguments, self).__init__(len(args))

        self.args = args

    def score(self):
        if 1 <= self.value <= 4:
            return 1.0
        elif 5 <= self.value <= 6:
            return 0.5
        else:
            return 0.0


class TightLoop(Feature):
    # basic block (BB) that jumps to itself
    weight = HIGH

    def __init__(self, startva, endva):
        super(TightLoop, self).__init__((f"0x{startva:x}", f"0x{endva:x}"))

        self.startva = startva
        self.endva = endva

    def score(self):
        return 1.0


class KindaTightLoop(TightLoop):
    # BB that jumps to itself via one intermediate BB
    pass


class TightFunction(Feature):
    # function that basically just wraps a tight loop
    weight = SEVERE

    def __init__(self):
        super(TightFunction, self).__init__(True)

    def score(self):
        # score 0 because we emulate all tight functions anyway
        return 0.0


class Mnem(Feature):
    def __init__(self, insn):
        super(Mnem, self).__init__(f"0x{insn.va:x}  {insn}")

        self.insn = insn

    def score(self):
        return 1.0


class Nzxor(Mnem):
    weight = HIGH


class Shift(Mnem):
    weight = HIGH


class Mov(Mnem):
    weight = MEDIUM


class CallsTo(Feature):
    weight = MEDIUM
    max_calls_to = None

    def __init__(self, vw, locations):
        super(CallsTo, self).__init__(len(locations))

        if not self.max_calls_to:
            # should be at least 1 to avoid divide by zero
            self.max_calls_to = floss.identify.get_max_calls_to(vw) or 1.0

        self.locations = locations

    def score(self):
        return float(self.value) / float(self.max_calls_to)


class Loop(Feature):
    weight = MEDIUM

    def __init__(self, comp):
        super(Loop, self).__init__(len(comp))

        self.comp = comp

    def score(self):
        return 1.0


class NzxorTightLoop(Feature):
    weight = SEVERE

    def __init__(self):
        super(NzxorTightLoop, self).__init__(True)

    def score(self):
        return 1.0


class NzxorLoop(Feature):
    weight = SEVERE

    def __init__(self):
        super(NzxorLoop, self).__init__(True)

    def score(self):
        return 1.0

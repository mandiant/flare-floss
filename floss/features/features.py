# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.

import floss.identify

# feature weights
LOW = 0.25
MEDIUM = 0.50
HIGH = 0.75
SEVERE = 1.00


class Feature:
    """A base class for defining features in code analysis, encapsulating common properties and methods.

    Attributes:
        name (str): Automatically derived from the class name.
        value: The specific value of the feature being analyzed.
    """

    def __init__(self, value):
        """Initializes the Feature instance.

        Args:
            value: The value associated with the feature.
        """
        super(Feature, self).__init__()

        self.name = self.__class__.__name__
        self.value = value

    @property
    def weight(self) -> float:
        """The importance weight of the feature. Must be implemented by subclasses.

        Raises:
            NotImplementedError: If the subclass does not implement this property.
        """
        # feature weight LOW, MEDIUM, ... (less to more important)
        raise NotImplementedError

    def score(self) -> float:
        """Calculates a score for the feature based on its value.

        Raises:
            NotImplementedError: If the subclass does not implement this method.
        """
        # returns a value between 0.0 and 1.0 (less likely to almost certain)
        # can be negative to exclude functions based on a feature
        raise NotImplementedError

    def weighted_score(self):
        """Computes the weighted score of the feature by multiplying its weight with its score.

        Returns:
            float: The weighted score of the feature.
        """
        return self.weight * self.score()

    def __str__(self):
        return (
            f"{self.name.ljust(20)} = {self.value} (score: {self.score():.2f}, weighted: {self.weighted_score():.2f})"
        )

    def __repr__(self):
        return str(self)


class BlockCount(Feature):
    """A feature representing the count of blocks in a function, influencing its analysis score.

    Inherits from Feature.
    """

    weight = LOW

    def __init__(self, block_count):
        """Initializes the BlockCount feature with the number of blocks.

        Args:
            block_count (int): The count of blocks in the function.
        """
        super(BlockCount, self).__init__(block_count)

    def score(self):
        """Determines the score based on the block count. Specific ranges of block count
        influence the score differently.

        Returns:
            float: A score indicating the likelihood of a function being a string decoding function.
        """
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
    """Represents the instruction count of a function, contributing to its analysis score.

    Attributes:
        weight (float): Importance of instruction count, predefined as LOW.
    """

    weight = LOW

    def __init__(self, instruction_count):
        """Initializes the InstructionCount feature with the number of instructions.

        Args:
            instruction_count (int): The total instruction count in the function.
        """
        super(InstructionCount, self).__init__(instruction_count)

    def score(self):
        """Calculates the score based on the instruction count. More instructions generally imply a higher likelihood
        of the function being significant, up to a point.

        Returns:
            float: Score based on the number of instructions.
        """
        if self.value > 10:
            return 0.8
        else:
            return 0.1


class Arguments(Feature):
    """Represents the number of arguments in a function, affecting its evaluation.

    Attributes:
        weight (float): Importance of the argument count, predefined as LOW.
    """

    weight = LOW

    def __init__(self, args):
        super(Arguments, self).__init__(len(args))

        self.args = args

    def score(self):
        """Scores the feature based on the optimal argument count for identification purposes.

        Returns:
            float: Score reflecting the appropriateness of the argument count.
        """
        if 1 <= self.value <= 4:
            return 1.0
        elif 5 <= self.value <= 6:
            return 0.5
        else:
            return 0.0


class TightLoop(Feature):
    """Identifies a tight loop within a function, indicating high importance.

    Attributes:
        weight (float): Importance of this feature, predefined as HIGH.
    """

    # basic block (BB) that jumps to itself
    weight = HIGH

    def __init__(self, startva, endva):
        super(TightLoop, self).__init__((f"0x{startva:x}", f"0x{endva:x}"))

        self.startva = startva
        self.endva = endva

    def score(self):
        """Returns a perfect score, indicating a significant feature of analysis.

        Returns:
            float: A static score of 1.0, due to the high relevance of tight loops.
        """
        return 1.0


class KindaTightLoop(TightLoop):
    """Identifies a tight loop within a function, but with an intermediate BB."""

    # BB that jumps to itself via one intermediate BB
    pass


class TightFunction(Feature):
    """A feature representing a tight function, indicating high importance."""

    # function that basically just wraps a tight loop
    weight = SEVERE

    def __init__(self):
        super(TightFunction, self).__init__(True)

    def score(self):
        """Returns a perfect score, indicating a significant feature of analysis."""
        # score 0 because we emulate all tight functions anyway
        return 0.0


class Mnem(Feature):
    """Represents a specific mnemonic instruction within a function, influencing its analysis score."""

    def __init__(self, insn):
        super(Mnem, self).__init__(f"0x{insn.va:x}  {insn}")

        self.insn = insn

    def score(self):
        """Scores the feature based on the mnemonic instruction."""
        return 1.0


class Nzxor(Mnem):
    """Represents the non-zeroing XOR operation within a function, influencing its analysis score."""

    weight = HIGH


class Shift(Mnem):
    """Represents the shift operation within a function, influencing its analysis score."""

    weight = HIGH


class Mov(Mnem):
    """Represents the move operation within a function, influencing its analysis score."""

    weight = MEDIUM


class CallsTo(Feature):
    """Represents the number of calls to external locations from within a function.

    This feature calculates its score based on the proportion of calls made to the total possible calls identified in the analysis, helping to assess the connectivity and complexity of functions.

    Attributes:
        weight (float): The importance weight of this feature, predefined as MEDIUM.
        max_calls_to (float): The maximum number of calls to any single location, used to normalize scores.

    Args:
        vw: The vivisect workspace instance for analysis.
        locations (list): A list of locations (addresses) where calls are made.
    """

    weight = MEDIUM
    max_calls_to = None

    def __init__(self, vw, locations):
        super(CallsTo, self).__init__(len(locations))

        if not self.max_calls_to:
            # should be at least 1 to avoid divide by zero
            self.max_calls_to = floss.identify.get_max_calls_to(vw) or 1.0

        self.locations = locations

    def score(self):
        """Calculates the feature's score as the ratio of observed calls to the maximum number of calls to any location.

        Returns:
            float: The normalized score, indicating the frequency of calls relative to the maximum observed.
        """
        return float(self.value / self.max_calls_to)


class Loop(Feature):
    """Represents loop structures within a function, evaluated for their impact on the function's behavior.

    Attributes:
        weight (float): Assigned importance of loop features, set to MEDIUM.
        comp: The components forming the loop within the function.

    Args:
        comp: A collection representing the loop's components.
    """

    weight = MEDIUM

    def __init__(self, comp):
        super(Loop, self).__init__(len(comp))

        self.comp = comp

    def score(self):
        """ """
        return 1.0


class NzxorTightLoop(Feature):
    """Identifies tight loops combined with non-zeroing XOR operations, indicating complex obfuscation or encoding routines.

    Attributes:
        weight (float): The severity of this feature, set to SEVERE.
    """

    weight = SEVERE

    def __init__(self):
        super(NzxorTightLoop, self).__init__(True)

    def score(self):
        """Provides a static score for nzxor tight loop features.

        Returns:
            float: A static score of 1.0, reflecting the high importance of this feature.
        """
        return 1.0


class NzxorLoop(Feature):
    """Similar to NzxorTightLoop but for more general loop structures combined with non-zeroing XOR operations.

    Attributes:
        weight (float): The severity of this feature, also set to SEVERE.
    """

    weight = SEVERE

    def __init__(self):
        super(NzxorLoop, self).__init__(True)

    def score(self):
        """Gives a static score for nzxor loop features.

        Returns:
            float: A static score of 1.0, denoting the critical nature of this feature.
        """
        return 1.0

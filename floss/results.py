# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.

import datetime
from enum import Enum
from typing import Dict, List
from dataclasses import field

# we use pydantic for dataclasses so that we can
# easily load and validate JSON reports.
#
# pydantic checks all the JSON fields look as they should
# while using the nice and familiar dataclass syntax.
#
# really, you should just pretend we're using stock dataclasses.
from pydantic.dataclasses import dataclass

import floss.logging_
from floss.version import __version__
from floss.render.sanitize import sanitize

logger = floss.logging_.getLogger(__name__)


class StringEncoding(str, Enum):
    ASCII = "ASCII"
    UTF16LE = "UTF-16LE"


@dataclass(frozen=True)
class StackString:
    """
    here's what the following members represent:
        
        
        [smaller addresses]
       
        +---------------+  <- stack_pointer (top of stack)
        |               | \
        +---------------+  | offset
        |               | /
        +---------------+
        | "abc"         | \
        +---------------+  |
        |               |  |
        +---------------+  | frame_offset
        |               |  |
        +---------------+  |
        |               | /
        +---------------+  <- original_stack_pointer (bottom of stack, probably bp)
        
        [bigger addresses]


    Attributes:
      function: the address of the function from which the stackstring was extracted
      string: the extracted string
      program_counter: the program counter at the moment the string was extracted
      stack_pointer: the stack counter at the moment the string was extracted
      original_stack_pointer: the initial stack counter when the function was entered
      offset: the offset into the stack from at which the stack string was found
      frame_offset: the offset from the function frame at which the stack string was found
    """

    function: int
    string: str
    encoding: StringEncoding
    program_counter: int
    stack_pointer: int
    original_stack_pointer: int
    offset: int
    frame_offset: int


class TightString(StackString):
    pass


class AddressType(str, Enum):
    STACK = "STACK"
    GLOBAL = "GLOBAL"
    HEAP = "HEAP"


@dataclass(frozen=True)
class DecodedString:
    """
    A decoding string and details about where it was found.

    Attributes:
        address: address of the string in memory
        address_type: type of the address of the string in memory
        string: the decoded string
        encoding: the string encoding, like ASCII or unicode
        decoded_at: the address at which the decoding routine is called
        decoding_routine: the address of the decoding routine
    """

    address: int
    address_type: AddressType
    string: str
    encoding: StringEncoding
    decoded_at: int
    decoding_routine: int


@dataclass(frozen=True)
class StaticString:
    """
    A string extracted from the raw bytes of the input.

    Attributes:
        string: the string
        offset: the offset into the input where the string is found
        encoding: the string encoding, like ASCII or unicode
    """

    string: str
    offset: int
    encoding: StringEncoding


@dataclass
class Runtime:
    start_date: datetime.datetime = datetime.datetime.now()
    total: float = 0
    vivisect: float = 0
    find_features: float = 0
    static_strings: float = 0
    stack_strings: float = 0
    decoded_strings: float = 0
    tight_strings: float = 0


@dataclass
class Functions:
    discovered: int = 0
    library: int = 0
    analyzed_stack_strings: int = 0
    analyzed_tight_strings: int = 0
    analyzed_decoded_strings: int = 0
    decoding_function_scores: Dict[int, float] = field(default_factory=dict)


@dataclass
class Analysis:
    enable_stack_strings: bool = True
    enable_tight_strings: bool = True
    enable_decoded_strings: bool = True
    enable_static_strings: bool = True
    functions: Functions = field(default_factory=Functions)


@dataclass
class Metadata:
    file_path: str
    version: str = __version__
    imagebase: int = 0
    runtime: Runtime = field(default_factory=Runtime)


@dataclass
class Strings:
    stack_strings: List[StackString] = field(default_factory=list)
    tight_strings: List[TightString] = field(default_factory=list)
    decoded_strings: List[DecodedString] = field(default_factory=list)
    static_strings: List[StaticString] = field(default_factory=list)


@dataclass
class ResultDocument:
    metadata: Metadata
    analysis: Analysis = field(default_factory=Analysis)
    strings: Strings = field(default_factory=Strings)

    @classmethod
    def parse_file(cls, path):
        return cls.__pydantic_model__.parse_file(path)


def log_result(decoded_string, verbosity):
    string = sanitize(decoded_string.string)
    if verbosity < floss.render.default.Verbosity.VERBOSE:
        logger.info("%s", string)
    else:
        if type(decoded_string) == DecodedString:
            logger.info(
                "%s [%s] decoded by 0x%x called at 0x%x",
                string,
                decoded_string.encoding,
                decoded_string.decoding_routine,
                decoded_string.decoded_at,
            )
        elif type(decoded_string) in (StackString, TightString):
            logger.info(
                "%s [%s] in 0x%x at address 0x%x",
                string,
                decoded_string.encoding,
                decoded_string.function,
                decoded_string.program_counter,
            )
        else:
            ValueError("unknown decoded or extracted string type: %s", type(decoded_string))

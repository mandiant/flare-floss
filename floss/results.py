# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.

import re
import json
import datetime
from enum import Enum
from typing import Dict, List
from pathlib import Path
from dataclasses import field

from pydantic import TypeAdapter, ValidationError

# we use pydantic for dataclasses so that we can
# easily load and validate JSON reports.
#
# pydantic checks all the JSON fields look as they should
# while using the nice and familiar dataclass syntax.
#
# really, you should just pretend we're using stock dataclasses.
from pydantic.dataclasses import dataclass

import floss.logging_
from floss.render import Verbosity
from floss.version import __version__
from floss.render.sanitize import sanitize

logger = floss.logging_.getLogger(__name__)


class InvalidResultsFile(Exception):
    """Indicates that a results file is invalid, corrupt, or in an incompatible format."""
    pass


class InvalidLoadConfig(Exception):
    """Indicates that the load configuration is invalid."""
    pass


class StringEncoding(str, Enum):
    """Enumeration of string encodings."""
    ASCII = "ASCII"
    UTF16LE = "UTF-16LE"
    UTF8 = "UTF-8"


@dataclass(frozen=True)
class StackString:
    """here's what the following members represent:
    
    
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
    """A string that is tightly packed in memory."""
    pass


class AddressType(str, Enum):
    """ Enumeration of address types."""
    STACK = "STACK"
    GLOBAL = "GLOBAL"
    HEAP = "HEAP"


@dataclass(frozen=True)
class DecodedString:
    """A decoding string and details about where it was found."""

    address: int
    address_type: AddressType
    string: str
    encoding: StringEncoding
    decoded_at: int
    decoding_routine: int


@dataclass(frozen=True)
class StaticString:
    """A string extracted from the raw bytes of the input."""

    string: str
    offset: int
    encoding: StringEncoding

    @classmethod
    def from_utf8(cls, buf, addr, min_length):
        """
        Create a StaticString from a buffer of bytes.

        Args:
            buf: The buffer of bytes.
            addr: The address of the buffer.
            min_length: The minimum length of the string.

        Returns:
            StaticString: The created string.

        """
        try:
            decoded_string = buf.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("not utf-8")

        if not re.sub(r"[\r\n\t]", "", decoded_string).isprintable():
            raise ValueError("not printable")

        if len(decoded_string) < min_length:
            raise ValueError("too short")
        return cls(string=decoded_string, offset=addr, encoding=StringEncoding.UTF8)


@dataclass
class Runtime:
    """ The runtime of the analysis."""
    start_date: datetime.datetime = datetime.datetime.now()
    total: float = 0
    vivisect: float = 0
    find_features: float = 0
    static_strings: float = 0
    language_strings: float = 0
    stack_strings: float = 0
    decoded_strings: float = 0
    tight_strings: float = 0


@dataclass
class Functions:
    """ The functions that were analyzed."""
    discovered: int = 0
    library: int = 0
    analyzed_stack_strings: int = 0
    analyzed_tight_strings: int = 0
    analyzed_decoded_strings: int = 0
    decoding_function_scores: Dict[int, Dict[str, float]] = field(default_factory=dict)


@dataclass
class Analysis:
    """ The analysis configuration."""
    enable_static_strings: bool = True
    enable_stack_strings: bool = True
    enable_tight_strings: bool = True
    enable_decoded_strings: bool = True
    functions: Functions = field(default_factory=Functions)


STRING_TYPE_FIELDS = set([field for field in Analysis.__annotations__ if field.startswith("enable_")])


@dataclass
class Metadata:
    """ Metadata about the analysis."""
    file_path: str
    version: str = __version__
    imagebase: int = 0
    min_length: int = 0
    runtime: Runtime = field(default_factory=Runtime)
    language: str = ""
    language_version: str = ""
    language_selected: str = ""  # configured by user


@dataclass
class Strings:
    """ The strings that were found."""
    stack_strings: List[StackString] = field(default_factory=list)
    tight_strings: List[TightString] = field(default_factory=list)
    decoded_strings: List[DecodedString] = field(default_factory=list)
    static_strings: List[StaticString] = field(default_factory=list)
    language_strings: List[StaticString] = field(default_factory=list)
    language_strings_missed: List[StaticString] = field(default_factory=list)


@dataclass
class ResultDocument:
    """ The result document."""
    metadata: Metadata
    analysis: Analysis = field(default_factory=Analysis)
    strings: Strings = field(default_factory=Strings)

    @classmethod
    def parse_file(cls, path):
        """
        Parse a result document from a file.

        Args:
            path: The path to the file.

        Returns:
            ResultDocument: The parsed result document.  
        """
        # We're ignoring the following mypy error since this field is guaranteed by the Pydantic dataclass.
        return cls.__pydantic_model__.parse_file(path)  # type: ignore


def log_result(decoded_string, verbosity):
    """
    Log a decoded string.

    Args:
        decoded_string: The decoded string.
        verbosity: The verbosity level.
    
    """
    string = sanitize(decoded_string.string)
    if verbosity < Verbosity.VERBOSE:
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


def load(sample: Path, analysis: Analysis, functions: List[int], min_length: int) -> ResultDocument:
    """
    Load a result document from a file, applying filters as needed.

    Args:
        sample: Path: 
        analysis: Analysis: 
        functions: List[int]: 
        min_length: int:

    Returns:
        ResultDocument: The loaded result document.

    
    """
    logger.debug("loading results document: %s", str(sample))
    results = read(sample)
    results.metadata.file_path = f"{sample}\n{results.metadata.file_path}"
    check_set_string_types(results, analysis)
    if functions:
        filter_functions(results, functions)
    if min_length:
        filter_string_len(results, min_length)
        results.metadata.min_length = min_length
    return results


def read(sample: Path) -> ResultDocument:
    """
    Loads a ResultDocument from a file.

    Attempts to read a file as JSON and deserialize it into a ResultDocument object. Handles potential JSON decoding errors, Unicode-related errors, and validation failures.

    Args:
        sample:  A Path object representing the file to load. 

    Returns:
        ResultDocument: The deserialized ResultDocument.

    Raises:
        InvalidResultsFile: If the file cannot be loaded as a valid ResultDocument (e.g., due to incorrect formatting or validation errors). 
    """
    try:
        with sample.open("rb") as f:
            results = json.loads(f.read().decode("utf-8"))
    except (json.decoder.JSONDecodeError, UnicodeDecodeError) as e:
        raise InvalidResultsFile(f"{e}")

    try:
        results = ResultDocument(**results)
    except (TypeError, ValidationError) as e:
        raise InvalidResultsFile(f"{str(sample)} is not a valid FLOSS result document: {e}")

    return results


def check_set_string_types(results: ResultDocument, wanted_analysis: Analysis) -> None:
    """
    Ensures consistency in string type analysis settings between loaded results and desired analysis.

    This function checks if specific string analysis types were enabled in a desired analysis configuration (`wanted_analysis`) but are missing from the loaded analysis results (`results`). If found, it issues warnings and updates the `results` object to match the `wanted_analysis` settings.

    Args:
        results: A ResultDocument object containing loaded analysis results.
        wanted_analysis: An Analysis object representing the desired analysis configuration.  
    """
    for string_type in STRING_TYPE_FIELDS:
        if getattr(wanted_analysis, string_type) and not getattr(results.analysis, string_type):
            logger.warning(f"{string_type} not in loaded data, use --only/--no to enable/disable type(s)")
        setattr(results.analysis, string_type, getattr(wanted_analysis, string_type))


def filter_functions(results: ResultDocument, functions: List[int]) -> None:
    """Updates a ResultDocument to include analysis data only from specified functions.

    Removes function-related data from the `results` object if the function's address (virtual address) is not present in the provided `functions` list.  

    Args:
        results: A ResultDocument object containing analysis results.
        functions: A list of function virtual addresses to keep in the results.

    Raises:
        InvalidLoadConfig:  If a specified function address is not found in the loaded results.
    """
    filtered_scores = dict()
    for fva in functions:
        try:
            filtered_scores[fva] = results.analysis.functions.decoding_function_scores[fva]
        except KeyError:
            raise InvalidLoadConfig(f"function 0x{fva:x} not found in loaded data")
    results.analysis.functions.decoding_function_scores = filtered_scores

    results.strings.stack_strings = list(filter(lambda f: f.function in functions, results.strings.stack_strings))
    results.strings.tight_strings = list(filter(lambda f: f.function in functions, results.strings.tight_strings))
    results.strings.decoded_strings = list(
        filter(lambda f: f.decoding_routine in functions, results.strings.decoded_strings)
    )

    results.analysis.functions.analyzed_stack_strings = len(results.strings.stack_strings)
    results.analysis.functions.analyzed_tight_strings = len(results.strings.tight_strings)
    results.analysis.functions.analyzed_decoded_strings = len(results.strings.decoded_strings)


def filter_string_len(results: ResultDocument, min_length: int) -> None:
    """
    Removes strings shorter than a specified length from the ResultDocument.

    Filters various string collections within the `results` object, keeping only strings that meet the minimum length criterion.

    Args:
        results: A ResultDocument object containing analysis results.
        min_length:  The minimum length a string must have to be retained.
    """
    results.strings.static_strings = list(filter(lambda s: len(s.string) >= min_length, results.strings.static_strings))
    results.strings.stack_strings = list(filter(lambda s: len(s.string) >= min_length, results.strings.stack_strings))
    results.strings.tight_strings = list(filter(lambda s: len(s.string) >= min_length, results.strings.tight_strings))
    results.strings.decoded_strings = list(
        filter(lambda s: len(s.string) >= min_length, results.strings.decoded_strings)
    )

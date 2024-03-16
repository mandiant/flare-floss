# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
from enum import Enum
from typing import Tuple, Iterable
from pathlib import Path

import pefile

import floss.logging_
from floss.results import StaticString
from floss.language.utils import get_rdata_section
from floss.language.rust.rust_version_database import rust_commit_hash

logger = floss.logging_.getLogger(__name__)


VERSION_UNKNOWN_OR_NA = "version unknown"


class Language(Enum):
    """Enumerates programming languages that can be identified in binary samples."""
    GO = "go"
    RUST = "rust"
    DOTNET = "dotnet"
    UNKNOWN = "unknown"
    DISABLED = "none"


def identify_language_and_version(
    sample: Path, static_strings: Iterable[StaticString]
) -> Tuple[Language, str]:
    """Identifies the programming language and version of a given binary sample based on static strings found within.

    Args:
        sample (Path): The path to the binary sample to be analyzed.
        static_strings (Iterable[StaticString]): An iterable of static strings extracted from the binary sample.

    Returns:
        Tuple[Language, str]: A tuple containing the identified programming language and its version. If the language
        cannot be identified, returns (Language.UNKNOWN, "unknown").
    """
    is_rust, version = get_if_rust_and_version(static_strings)
    if is_rust:
        logger.info("Rust binary found with version: %s", version)
        return Language.RUST, version

    # open file as PE for further checks
    try:
        pe = pefile.PE(str(sample))
    except pefile.PEFormatError as err:
        logger.debug(
            f"FLOSS currently only detects if Windows PE files were written in Go or .NET. "
            f"This is not a valid PE file: {err}"
        )
        return Language.UNKNOWN, VERSION_UNKNOWN_OR_NA

    is_go, version = get_if_go_and_version(pe)
    if is_go:
        logger.info("Go binary found with version %s", version)
        return Language.GO, version
    elif is_dotnet_bin(pe):
        return Language.DOTNET, VERSION_UNKNOWN_OR_NA
    else:
        return Language.UNKNOWN, VERSION_UNKNOWN_OR_NA


def get_if_rust_and_version(static_strings: Iterable[StaticString]) -> Tuple[bool, str]:
    """Determines if a binary sample is written in Rust and identifies its version.

    Args:
        static_strings (Iterable[StaticString]): An iterable of static strings extracted from the binary sample.

    Returns:
        Tuple[bool, str]: A tuple where the first element is a boolean indicating whether the sample is identified as Rust,
        and the second element is the version of Rust identified. If the version cannot be determined, returns "unknown".
    """
    # Check if the binary contains the rustc/commit-hash string

    # matches strings like "rustc/commit-hash[40 characters]/library" e.g. "rustc/59eed8a2aac0230a8b53e89d4e99d55912ba6b35/library"
    regex_hash = re.compile(r"rustc/(?P<hash>[a-z0-9]{40})[\\\/]library")

    # matches strings like "rustc/version/library" e.g. "rustc/1.54.0/library"
    regex_version = re.compile(r"rustc/(?P<version>[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2})")

    for static_string_obj in static_strings:
        string = static_string_obj.string

        match = regex_version.search(string)
        if match:
            return True, match["version"]

        matches = regex_hash.search(string)
        if matches:
            if matches["hash"] in rust_commit_hash.keys():
                version = rust_commit_hash[matches["hash"]]
                return True, version
            else:
                logger.debug(
                    "hash %s not found in Rust commit hash database", matches["hash"]
                )
                return True, VERSION_UNKNOWN_OR_NA

    return False, VERSION_UNKNOWN_OR_NA


def get_if_go_and_version(pe: pefile.PE) -> Tuple[bool, str]:
    """Determines if the provided PE file is compiled with Go and identifies the Go version.

    Args:
        pe (pefile.PE): The PE file to be analyzed.

    Returns:
        Tuple[bool, str]: A tuple containing a boolean indicating if the file is compiled with Go,
                          and a string representing the version of Go, or 'VERSION_UNKNOWN_OR_NA' if the version cannot be determined.

    This function checks the pclntab structure's magic header -pcHeader- to identify the Go version.
    The magic values vary with the version. It first searches the .rdata section, then all available sections for magic headers and common Go functions.

    Reference:
    https://github.com/0xjiayu/go_parser/blob/865359c297257e00165beb1683ef6a679edc2c7f/pclntbl.py#L46
    """
    go_magic = [
        b"\xf0\xff\xff\xff\x00\x00",
        b"\xfb\xff\xff\xff\x00\x00",
        b"\xfa\xff\xff\xff\x00\x00",
        b"\xf1\xff\xff\xff\x00\x00",
    ]
    go_functions = [
        b"runtime.main",
        b"main.main",
        b"runtime.gcWork",
        b"runtime.morestack",
        b"runtime.morestack_noctxt",
        b"runtime.newproc",
        b"runtime.gcWriteBarrier",
        b"runtime.Gosched",
    ]
    # look for the .rdata section first
    try:
        section = get_rdata_section(pe)
    except ValueError:
        logger.debug(".rdata section not found")
    else:
        section_va = section.VirtualAddress
        section_size = section.SizeOfRawData
        section_data = section.get_data(section_va, section_size)
        for magic in go_magic:
            if magic in section_data:
                pclntab_va = section_data.index(magic) + section_va
                if verify_pclntab(section, pclntab_va):
                    return True, get_go_version(magic)

    # if not found, search in all the available sections
    for magic in go_magic:
        for section in pe.sections:
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)
            if magic in section_data:
                pclntab_va = section_data.index(magic) + section_va
                if verify_pclntab(section, pclntab_va):
                    return True, get_go_version(magic)

    # if not found, the magic bytes may have been patched, search for common Go functions present in all Go samples including obfuscated files
    # look for the .rdata section first
    try:
        section = get_rdata_section(pe)
    except ValueError:
        logger.debug(".rdata section not found")
    else:
        section_va = section.VirtualAddress
        section_size = section.SizeOfRawData
        section_data = section.get_data(section_va, section_size)
        for go_function in go_functions:
            if go_function in section_data:
                logger.info("Go binary found, function name %s", go_function)
                return True, VERSION_UNKNOWN_OR_NA

    # if not found, search in all the available sections
    for section in pe.sections:
        section_va = section.VirtualAddress
        section_size = section.SizeOfRawData
        section_data = section.get_data(section_va, section_size)
        for go_function in go_functions:
            if go_function in section_data:
                logger.info("Go binary found, function name %s", go_function)
                return True, VERSION_UNKNOWN_OR_NA

    return False, VERSION_UNKNOWN_OR_NA


def get_go_version(magic):
    """Determines the Go compiler version used to compile the binary based on the magic header.

    Args:
        magic (bytes): The magic header bytes found in the binary.

    Returns:
        str: The identified Go version, or VERSION_UNKNOWN_OR_NA if the version cannot be determined.
    """
    MAGIC_112 = b"\xfb\xff\xff\xff\x00\x00"  # Magic Number from version 1.12
    MAGIC_116 = b"\xfa\xff\xff\xff\x00\x00"  # Magic Number from version 1.16
    MAGIC_118 = b"\xf0\xff\xff\xff\x00\x00"  # Magic Number from version 1.18
    MAGIC_120 = b"\xf1\xff\xff\xff\x00\x00"  # Magic Number from version 1.20

    if magic == MAGIC_112:
        return "1.12"
    elif magic == MAGIC_116:
        return "1.16"
    elif magic == MAGIC_118:
        return "1.18"
    elif magic == MAGIC_120:
        return "1.20"
    else:
        return VERSION_UNKNOWN_OR_NA


def verify_pclntab(section, pclntab_va: int) -> bool:
    """Verifies the legitimacy of the pclntab section by parsing its headers.

    Args:
        section: The section object from pefile where pclntab is located.
        pclntab_va (int): The virtual address of the pclntab header.

    Returns:
        bool: True if the pclntab header is valid, False otherwise.
    """
    try:
        pc_quanum = section.get_data(pclntab_va + 6, 1)[0]
        pointer_size = section.get_data(pclntab_va + 7, 1)[0]
    except:
        logger.error("Error parsing pclntab header")
        return False
    return True if pc_quanum in {1, 2, 4} and pointer_size in {4, 8} else False


def is_dotnet_bin(pe: pefile.PE) -> bool:
    """Checks whether the binary is a .NET assembly.

    Args:
        pe (pefile.PE): The PE file to check.

    Returns:
        bool: True if the file is a .NET assembly, False otherwise.
    """
    try:
        directory_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    except IndexError:
        return False

    return dir_entry.Size != 0 and dir_entry.VirtualAddress != 0

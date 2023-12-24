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
    GO = "go"
    RUST = "rust"
    DOTNET = "dotnet"
    UNKNOWN = "unknown"
    DISABLED = "none"


def identify_language_and_version(sample: Path, static_strings: Iterable[StaticString]) -> Tuple[Language, str]:
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
    """
    Return if the binary given is compiled with Rust compiler and its version
    reference: https://github.com/mandiant/flare-floss/issues/766
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
                logger.debug("hash %s not found in Rust commit hash database", matches["hash"])
                return True, VERSION_UNKNOWN_OR_NA

    return False, VERSION_UNKNOWN_OR_NA


def get_if_go_and_version(pe: pefile.PE) -> Tuple[bool, str]:
    """
    Return if the binary given is compiled with Go compiler and its version
    this checks the magic header of the pclntab structure -pcHeader-
    the magic values varies through the version
    reference:
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
    """get the version of the go compiler used to compile the binary"""

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
    """
    Parse headers of pclntab to verify it is legit
    used in go parser itself https://go.dev/src/debug/gosym/pclntab.go
    """
    try:
        pc_quanum = section.get_data(pclntab_va + 6, 1)[0]
        pointer_size = section.get_data(pclntab_va + 7, 1)[0]
    except:
        logger.error("Error parsing pclntab header")
        return False
    return True if pc_quanum in {1, 2, 4} and pointer_size in {4, 8} else False


def is_dotnet_bin(pe: pefile.PE) -> bool:
    """
    Check if the binary is .net or not
    Checks the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR entry in the OPTIONAL_HEADER of the file.
    If the entry is not found, or if its size is 0, the file is not a .net file.
    """
    try:
        directory_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    except IndexError:
        return False

    return dir_entry.Size != 0 and dir_entry.VirtualAddress != 0

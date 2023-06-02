# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import re
from typing import Iterable

import pefile

import floss.logging_
from floss.results import StaticString
from floss.strings import extract_ascii_unicode_strings
from floss.rust_version_database import rust_commit_hash

logger = floss.logging_.getLogger(__name__)


def identify_language(sample: str, static_strings: Iterable[StaticString]) -> str:
    """
    Identify the language of the binary given
    """
    if is_rust_bin(static_strings):
        logger.warning("Rust Binary Detected, Rust binaries are not supported yet. Results may be inaccurate.")
        logger.warning("Rust: Proceeding with analysis may take a long time.")
        return "rust"
    elif is_go_bin(sample):
        logger.warning("Go Binary Detected, Go binaries are not supported yet. Results may be inaccurate.")
        logger.warning("Go: Proceeding with analysis may take a long time.")
        return "go"
    else:
        return "unknown"


def is_rust_bin(static_strings: Iterable[StaticString]) -> bool:
    """
    Check if the binary given is compiled with Rust compiler or not
    reference: https://github.com/mandiant/flare-floss/issues/766
    """

    # Check if the binary contains the rustc/commit-hash string

    # matches strings like "rustc/commit-hash[40 characters]/library" e.g. "rustc/59eed8a2aac0230a8b53e89d4e99d55912ba6b35/library"
    regex_hash = re.compile(r"rustc/(?P<hash>[a-z0-9]{40})[\\\/]library")

    # matches strings like "rustc/version/library" e.g. "rustc/1.54.0/library"
    regex_version = re.compile(r"rustc/[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}")

    for static_string_obj in static_strings:
        string = static_string_obj.string
        matches = regex_hash.search(string)
        if matches and matches["hash"] in rust_commit_hash.keys():
            version = rust_commit_hash[matches["hash"]]
            logger.warning("Rust Binary found with version: %s", version)
            return True
        if regex_version.search(string):
            logger.warning("Rust Binary found with version: %s", string)
            return True

    return False


def is_go_bin(sample: str) -> bool:
    """
    Check if the binary given is compiled with Go compiler or not
    it checks the magic header of the pclntab structure -pcHeader-
    the magic values varies through the version
    reference:
    https://github.com/0xjiayu/go_parser/blob/865359c297257e00165beb1683ef6a679edc2c7f/pclntbl.py#L46
    """
    try:
        pe = pefile.PE(sample)
    except pefile.PEFormatError as err:
        logger.debug(f"NOT valid PE header: {err}")
        return False
    except IOError as err:
        logger.error(f"File does not exist or cannot be accessed: {err}")
        return False
    except Exception as err:
        logger.error(f"Unexpected error: {err}")
        raise

    go_magic = [
        b"\xf0\xff\xff\xff\x00\x00",
        b"\xfb\xff\xff\xff\x00\x00",
        b"\xfa\xff\xff\xff\x00\x00",
        b"\xf1\xff\xff\xff\x00\x00",
    ]

    # look for the .rdata section first
    for section in pe.sections:
        try:
            section_name = section.Name.partition(b"\x00")[0].decode("utf-8")
        except UnicodeDecodeError:
            continue
        if ".rdata" == section_name:
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)
            for magic in go_magic:
                if magic in section_data:
                    pclntab_va = section_data.index(magic) + section_va
                    if verify_pclntab(section, pclntab_va):
                        logger.warning("Go binary found with version %s", get_go_version(magic))
                        return True

    # if not found, search in all the available sections

    for magic in go_magic:
        for section in pe.sections:
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)
            if magic in section_data:
                pclntab_va = section_data.index(magic) + section_va
                if verify_pclntab(section, pclntab_va):
                    # just for testing
                    logger.warning("Go binary found with version %s", get_go_version(magic))
                    return True
    return False


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
        return "unknown"


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

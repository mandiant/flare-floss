# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
import os

import pefile

import floss.logging_
from floss.logging_ import DebugLevel

logger = floss.logging_.getLogger("floss")


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
    except:
        if not os.path.exists(sample):
            logger.error(f"Path {sample} does not exist or cannot be accessed")
        else:
            logger.debug("NOT valid PE header")
        return False

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
        if ".rdata" in section_name:
            section_va = section.VirtualAddress
            section_size = section.SizeOfRawData
            section_data = section.get_data(section_va, section_size)
            for magic in go_magic:
                if magic in section_data:
                    pclntab_va = section_data.index(magic) + section_va
                    if verify_pclntab(section, pclntab_va):
                        return True
            return False

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
                    return True
    return False


def verify_pclntab(section, pclntab_va: int) -> bool:
    """
    Parse headers of pclntab to verify it is legit
    used in go parser itself https://go.dev/src/debug/gosym/pclntab.go
    """
    pc_quanum = section.get_data(pclntab_va + 6, 1)[0]
    pointer_size = section.get_data(pclntab_va + 7, 1)[0]
    return True if pc_quanum in {1, 2, 4} and pointer_size in {4, 8} else False

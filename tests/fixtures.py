# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

import os

import pytest

CD = os.path.dirname(__file__)


@pytest.fixture
def exefile() -> str:
    # decode-in-place is among the fastest samples in data/src
    return os.path.join(CD, "data", "src", "decode-in-place", "bin", "test-decode-in-place.exe")


@pytest.fixture
def scfile() -> str:
    return os.path.join(CD, "data", "src", "shellcode-stackstrings", "bin", "shellcode-stackstrings.bin")

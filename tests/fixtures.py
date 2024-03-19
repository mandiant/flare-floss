# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

from pathlib import Path

import pytest

CD = Path(__file__).resolve().parent


@pytest.fixture
def exefile() -> str:
    # decode-in-place is among the fastest samples in data/src
    path = CD / "data" / "src" / "decode-in-place" / "bin" / "test-decode-in-place.exe"
    return str(path)


@pytest.fixture
def scfile() -> str:
    path = CD / "data" / "src" / "shellcode-stackstrings" / "bin" / "shellcode-stackstrings.bin"
    return str(path)

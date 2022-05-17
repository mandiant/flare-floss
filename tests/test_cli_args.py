# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.

import pytest
from fixtures import scfile, exefile

import floss.main


def test_functions(exefile):
    # 0x1111111 is not a function
    assert floss.main.main([exefile, "--function", "0x1111111"]) == -1

    # ok
    assert floss.main.main([exefile, "--function", "0x401560"]) == 0
    assert floss.main.main([exefile, "--function", "0x401560"]) == 0
    assert floss.main.main([exefile, "--function", "0x401560", "0x401000"]) == 0


def test_shellcode(scfile):
    # ok
    assert floss.main.main([scfile, "-f", "sc32"]) == 0
    assert floss.main.main([scfile, "--format", "sc64"]) == 0

    # fail
    assert floss.main.main([scfile, "--format", "pe"]) == -1


@pytest.mark.parametrize("type_", [t.value for t in floss.main.StringType])
@pytest.mark.parametrize("analysis", ("--only", "--no"))
def test_args_analysis_type(exefile, analysis, type_):
    assert (
        floss.main.main(
            [
                exefile,
                analysis,
                type_,
            ]
        )
        == 0
    )

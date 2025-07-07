# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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

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
from floss.cli import StringType


def test_functions(exefile):
    # 0x1111111 is not a function
    assert floss.main.main([exefile, "--analyze-functions", "0x1111111"]) == -1

    # ok
    assert floss.main.main([exefile, "--analyze-functions", "0x401560"]) == 0
    assert floss.main.main([exefile, "--analyze-functions", "0x401560", "0x401000"]) == 0

    # --string-type static only cannot be combined with --analyze-functions
    assert floss.main.main([exefile, "--analyze-functions", "0x401560", "--string-type", "static"]) == -1


def test_shellcode(scfile):
    # ok
    assert floss.main.main([scfile, "-f", "sc32"]) == 0
    assert floss.main.main([scfile, "--format", "sc64"]) == 0

    # fail
    assert floss.main.main([scfile, "--format", "pe"]) == -1


@pytest.mark.parametrize("type_", [t.value for t in StringType])
@pytest.mark.parametrize("analysis", ("--string-type", "--no-string-type"))
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


def test_args_analysis_type_conflict(exefile):
    assert floss.main.main([exefile, "--string-type", "stack", "--no-string-type", "tight"]) == -1


def test_no_layout_yields_classic_static(exefile):
    """enable_layout=False: no layout tree; classic static strings still present."""
    from pathlib import Path

    from floss.results import Analysis
    from floss.pipeline import Options, analyze

    results = analyze(
        Options(
            sample=Path(exefile),
            min_length=4,
            analysis=Analysis(
                enable_static_strings=True,
                enable_stack_strings=False,
                enable_tight_strings=False,
                enable_decoded_strings=False,
                enable_layout=False,
                enable_tags=True,
            ),
            prompt_deobfuscation=False,
        )
    )
    assert results is not None
    assert results.layout is None
    assert len(results.strings.static_strings) > 0


def test_no_tags_skips_tag_databases(exefile):
    """enable_tags=False: layout present; no DB tags (#common, #winapi, …).

    Layout-intrinsic tags such as #code / #duplicate may still appear.
    """
    from pathlib import Path

    from floss.results import Analysis, ResultLayout
    from floss.pipeline import Options, analyze

    results = analyze(
        Options(
            sample=Path(exefile),
            min_length=4,
            analysis=Analysis(
                enable_static_strings=True,
                enable_stack_strings=False,
                enable_tight_strings=False,
                enable_decoded_strings=False,
                enable_layout=True,
                enable_tags=False,
            ),
            prompt_deobfuscation=False,
        )
    )
    assert results is not None
    assert results.layout is not None
    assert isinstance(results.layout, ResultLayout)

    def all_tags(layout):
        tags = set()
        for s in layout.strings:
            tags.update(s.tags)
        for child in layout.children:
            tags.update(all_tags(child))
        return tags

    tags = all_tags(results.layout)
    # database-backed tags must be absent when tag DBs are disabled
    for db_tag in ("#common", "#winapi", "#capa", "#msvc", "#openssl"):
        assert db_tag not in tags
    for s in results.strings.static_strings:
        for db_tag in ("#common", "#winapi", "#capa", "#msvc", "#openssl"):
            assert db_tag not in s.tags

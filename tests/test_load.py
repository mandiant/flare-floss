import json
import textwrap
from pathlib import Path

import pytest
from fixtures import exefile

import floss.main
import floss.utils

# floss --no-string-type static -j tests/data/src/decode-in-place/bin/test-decode-in-place.exe
RESULTS = textwrap.dedent("""
{
    "analysis": {
        "enable_decoded_strings": true,
        "enable_stack_strings": true,
        "enable_static_strings": false,
        "enable_tight_strings": true,
        "functions": {
            "analyzed_decoded_strings": 20,
            "analyzed_stack_strings": 30,
            "analyzed_tight_strings": 2,
            "decoding_function_scores": {
                "4199648": {"score": 0.744, "xrefs_to": 2},
                "4199776": {"score": 0.763, "xrefs_to": 3},
                "4199888": {"score": 0.617, "xrefs_to": 1},
                "4200144": {"score": 0.62, "xrefs_to": 2},
                "4200304": {"score": 0.471, "xrefs_to": 1},
                "4200336": {"score": 0.617, "xrefs_to": 2},
                "4200560": {"score": 0.44, "xrefs_to": 1},
                "4201104": {"score": 0.931, "xrefs_to": 0},
                "4201200": {"score": 0.887, "xrefs_to": 2},
                "4201776": {"score": 0.576, "xrefs_to": 3},
                "4202640": {"score": 0.539, "xrefs_to": 1},
                "4202672": {"score": 0.886, "xrefs_to": 2},
                "4202992": {"score": 0.624, "xrefs_to": 1},
                "4203120": {"score": 0.686, "xrefs_to": 2},
                "4203264": {"score": 0.6, "xrefs_to": 1},
                "4203424": {"score": 0.497, "xrefs_to": 1},
                "4203584": {"score": 0.591, "xrefs_to": 2},
                "4203648": {"score": 0.727, "xrefs_to": 1},
                "4203872": {"score": 0.617, "xrefs_to": 2},
                "4204416": {"score": 0.531, "xrefs_to": 1}
            },
            "discovered": 50,
            "library": 0
        }
    },
    "metadata": {
        "file_path": "tests/data/src/decode-in-place/bin/test-decode-in-place.exe",
        "imagebase": 4194304,
        "min_length": 4,
        "runtime": {
            "decoded_strings": 0.9855,
            "find_features": 0.0546,
            "stack_strings": 0.207,
            "start_date": "2022-06-01T10:58:11.059390Z",
            "static_strings": 0.0,
            "tight_strings": 0.1788,
            "total": 7.2177,
            "vivisect": 5.7918
        },
        "version": "2.0.0"
    },
    "strings": {
        "decoded_strings": [
            {
                "address": 3216244620,
                "address_type": "STACK",
                "decoded_at": 4199986,
                "decoding_routine": 4199776,
                "encoding": "ASCII",
                "string": "hello world"
            }
        ],
        "stack_strings": [
            {
                "encoding": "ASCII",
                "frame_offset": 32,
                "function": 4199888,
                "offset": 32,
                "original_stack_pointer": 3216244656,
                "program_counter": 4199776,
                "stack_pointer": 3216244588,
                "string": "idmmn!vnsme"
            }
        ],
        "static_strings": [],
        "tight_strings": []
    }
}
""")


def test_load(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "results.json"
    p.write_text(RESULTS)
    assert (
        floss.main.main(
            [
                str(d.joinpath(p)),
            ]
        )
        == 0
    )


def test_detect_file_type_returns_results_for_results_json(tmp_path):
    p = tmp_path / "results.json"
    p.write_text(RESULTS)
    assert floss.utils.detect_file_type(p) is floss.utils.FileType.RESULTS


def test_detect_file_type_not_results_for_binary(exefile):
    assert floss.utils.detect_file_type(Path(exefile)) is not floss.utils.FileType.RESULTS


def test_detect_file_type_not_results_for_invalid_json(tmp_path):
    p = tmp_path / "invalid.json"
    p.write_text("{not valid json")
    assert floss.utils.detect_file_type(p) is not floss.utils.FileType.RESULTS


def test_detect_file_type_not_results_for_non_floss_json(tmp_path):
    p = tmp_path / "other.json"
    p.write_text(json.dumps({"hello": "world"}))
    assert floss.utils.detect_file_type(p) is not floss.utils.FileType.RESULTS


def test_filter_string_len_filters_language_and_layout():
    """-n on a loaded document must prune language and layout strings too."""
    from floss.results import (
        Strings,
        Analysis,
        Metadata,
        ResultLayout,
        ResultString,
        StaticString,
        ResultDocument,
        StringEncoding,
        filter_string_len,
    )

    short = ResultString(string="ab", offset=1, size=2, encoding="ascii")
    long = ResultString(string="abcdef", offset=2, size=6, encoding="ascii")
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(
            enable_static_strings=False,
            enable_stack_strings=False,
            enable_tight_strings=False,
            enable_decoded_strings=False,
        ),
        strings=Strings(
            language_strings=[StaticString(string="xy", offset=1, encoding=StringEncoding.ASCII)],
        ),
        layout=ResultLayout(name="pe", offset=0, length=10, strings=[short, long]),
    )
    filter_string_len(doc, 4)
    assert doc.layout is not None
    assert [s.string for s in doc.layout.strings] == ["abcdef"]
    assert doc.strings.language_strings == []


def test_filter_string_len_warns_when_requested_below_stored(caplog):
    """-n below the stored extraction min_length must warn: those strings are gone."""
    from floss.results import (
        Strings,
        Analysis,
        Metadata,
        ResultDocument,
        filter_string_len,
    )

    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=6),
        analysis=Analysis(
            enable_static_strings=False,
            enable_stack_strings=False,
            enable_tight_strings=False,
            enable_decoded_strings=False,
        ),
        strings=Strings(),
    )
    with caplog.at_level("WARNING", logger="floss.results"):
        filter_string_len(doc, 4)
    assert "minimum-length 4" in caplog.text
    assert "6" in caplog.text


def test_filter_string_len_no_warning_when_at_or_above_stored(caplog):
    """-n equal to or above the stored min_length is fine, no warning."""
    from floss.results import (
        Strings,
        Analysis,
        Metadata,
        ResultDocument,
        filter_string_len,
    )

    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(
            enable_static_strings=False,
            enable_stack_strings=False,
            enable_tight_strings=False,
            enable_decoded_strings=False,
        ),
        strings=Strings(),
    )
    with caplog.at_level("WARNING", logger="floss.results"):
        filter_string_len(doc, 4)
    assert "minimum-length" not in caplog.text


def test_filter_functions_accepts_stack_only_function():
    """a function with only stack strings (no decoding score) is valid."""
    from floss.results import (
        Strings,
        Analysis,
        Metadata,
        StackString,
        ResultDocument,
        StringEncoding,
        InvalidLoadConfig,
        filter_functions,
    )

    ss = StackString(
        function=0x401000,
        string="hello",
        encoding=StringEncoding.ASCII,
        program_counter=0x1000,
        stack_pointer=0x4000,
        original_stack_pointer=0x39A0,
        offset=0x10,
        frame_offset=0x10,
    )
    doc = ResultDocument(
        metadata=Metadata(file_path="x", min_length=4),
        analysis=Analysis(enable_stack_strings=True, enable_tight_strings=False, enable_decoded_strings=False),
        strings=Strings(stack_strings=[ss]),
    )
    filter_functions(doc, [0x401000])
    assert len(doc.strings.stack_strings) == 1

    with pytest.raises(InvalidLoadConfig):
        filter_functions(doc, [0x999999])

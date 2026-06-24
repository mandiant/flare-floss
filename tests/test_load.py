import textwrap

import floss.main

# floss --no static -j tests/data/src/decode-in-place/bin/test-decode-in-place.exe
RESULTS = textwrap.dedent(
    """
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
"""
)


def test_load(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "results.json"
    p.write_text(RESULTS)
    assert (
        floss.main.main(
            [
                "-l",
                str(d.joinpath(p)),
            ]
        )
        == 0
    )

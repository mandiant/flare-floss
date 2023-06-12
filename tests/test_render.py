# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

from floss.results import (
    Strings,
    Analysis,
    Metadata,
    AddressType,
    StackString,
    TightString,
    StaticString,
    DecodedString,
    ResultDocument,
    StringEncoding,
)
from floss.render.default import render


def test_render_rich_markup():
    results: ResultDocument = ResultDocument(
        metadata=Metadata(
            file_path="test",
            min_length=4,
        ),
        analysis=Analysis(),
        strings=Strings(
            static_strings=[StaticString(string="[/<]one", offset=1033749, encoding=StringEncoding.ASCII)],
            tight_strings=[
                TightString(
                    function=0x4000000,
                    string="[/<]two",
                    encoding=StringEncoding.ASCII,
                    program_counter=0x1000,
                    stack_pointer=0x4000,
                    original_stack_pointer=0x39A0,
                    offset=0x10,
                    frame_offset=0x10,
                )
            ],
            stack_strings=[
                StackString(
                    function=0x4000000,
                    string="[/<]three",
                    encoding=StringEncoding.ASCII,
                    program_counter=0x1000,
                    stack_pointer=0x4000,
                    original_stack_pointer=0x39A0,
                    offset=0x10,
                    frame_offset=0x10,
                )
            ],
            decoded_strings=[
                DecodedString(
                    address=0x3000,
                    address_type=AddressType.STACK,
                    string="[/<]four",
                    encoding=StringEncoding.ASCII,
                    decoded_at=0x100,
                    decoding_routine=0x10000,
                )
            ],
        ),
    )

    assert "[/<]one" in render(results, True, False, "auto")
    assert "[/<]one" in render(results, False, False, "auto")
    assert "[/<]two" in render(results, True, False, "auto")
    assert "[/<]two" in render(results, False, False, "auto")
    assert "[/<]three" in render(results, True, False, "auto")
    assert "[/<]three" in render(results, False, False, "auto")
    assert "[/<]four" in render(results, True, False, "auto")
    assert "[/<]four" in render(results, False, False, "auto")

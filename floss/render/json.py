# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

import json
import datetime
import dataclasses

from floss.results import ResultDocument


class FlossJSONEncoder(json.JSONEncoder):
    """
    serializes FLOSS data structures into JSON.
    specifically:
      - dataclasses into their dict representation
      - datetimes to ISO8601 strings
    """

    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat("T") + "Z"
        return super().default(o)


def create_custom_format(doc: ResultDocument):
    """
    Format the ResultDocument into a custom JSON structure in the format:
    Strings: 
        - static_strings
        - stack_strings
        - tight_strings
        - decoded_strings
        - Context:
            - structure
            - tags
    File Layout:
        - file_path
        - imagebase
        - min_length
    """
    static_strings = []
    stack_strings = []
    tight_strings = []
    decoded_strings = []
    context = {}

    string_id = 1
    for string in doc.strings.static_strings:
        static_strings.append({
            "id": string_id,
            "encoding": string.encoding.value.lower(),
            "offset": string.offset,
            "length": len(string.string),
            "string": string.string
        })
        
        if "DOS mode" in string.string:
            context[string_id] = {
                "structure": "pe.header",
                "tags": ["#common"]
            }
        elif string.string in ["VirtualQuery", "GetProcAddress", "LoadLibraryA"]:
            context[string_id] = {
                "structure": "import table",
                "tags": ["#winapi", "#common"]
            }
        
        string_id += 1

    for string in doc.strings.stack_strings:
        stack_entry = {
            "id": string_id,
            "encoding": string.encoding.value.lower(),
            "offset": string.program_counter,
            "length": len(string.string),
            "string": string.string,
            "function": string.function,
            "stack_pointer": string.stack_pointer,
            "frame_offset": string.frame_offset
        }
        stack_strings.append(stack_entry)
        string_id += 1

    for string in doc.strings.tight_strings:
        tight_entry = {
            "id": string_id,
            "encoding": string.encoding.value.lower(),
            "offset": string.program_counter,
            "length": len(string.string),
            "string": string.string,
            "function": string.function,
            "stack_pointer": string.stack_pointer,
            "frame_offset": string.frame_offset
        }
        tight_strings.append(tight_entry)
        string_id += 1

    for string in doc.strings.decoded_strings:
        decoded_strings.append({
            "id": string_id,
            "encoding": string.encoding.value.lower(),
            "offset": string.decoding_routine,
            "length": len(string.string),
            "string": string.string,
            "decoded_at": string.decoded_at,
            "address": string.address,
            "address_type": string.address_type
        })
        string_id += 1

    return {
        "strings": {
            "static_strings": static_strings,
            "stack_strings": stack_strings,
            "tight_strings": tight_strings,
            "decoded_strings": decoded_strings,
            "context": context
        },
        "file_layout": {
            "file_path": doc.metadata.file_path,
            "imagebase": doc.metadata.imagebase,
            "min_length": doc.metadata.min_length
        }
    }


def render(doc: ResultDocument) -> str:
    custom_format = create_custom_format(doc)
    return json.dumps(custom_format, indent=4)

# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

import json
import datetime
import dataclasses
import pefile
import logging

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
    Format the ResultDocument into a custom JSON structure with proper PE parsing.
    """
    static_strings = []
    stack_strings = []
    tight_strings = []
    decoded_strings = []
    context = {}

    pe_structure = {
        "headers": {"ranges": [], "strings": []},
        "sections": {}
    }
    
    pe = None
    try:
        pe = pefile.PE(doc.metadata.file_path)
    except Exception as e:
        logging.warning(f"Failed to parse PE file: {e}")

    pe_sections = {}
    import_entries = set()
    import_dll_map = {}
    
    if pe:

        pe_headers = [(0, pe.DOS_HEADER.e_lfanew + 4, "DOS_HEADER")]
        if hasattr(pe, 'NT_HEADERS'):
            pe_headers.append((pe.DOS_HEADER.e_lfanew, 
                              pe.DOS_HEADER.e_lfanew + pe.NT_HEADERS.sizeof(),
                              "NT_HEADERS"))
        
        pe_structure["headers"]["ranges"] = [
            {"start": start, "end": end, "type": htype} for start, end, htype in pe_headers
        ]

        for section in pe.sections:
            start = section.PointerToRawData
            end = start + section.SizeOfRawData
            name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            pe_sections[(start, end)] = name
            
            section_name = name
            if not section_name.startswith('.'):
                section_name = f".{section_name}"
                
            pe_structure["sections"][section_name] = {
                "range": {"start": start, "end": end},
                "strings": [],
                "structures": {}
            }

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore') if entry.dll else "unknown"
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', 'ignore')
                        import_entries.add(func_name)
                        import_dll_map[func_name] = dll_name

    for string in doc.strings.static_strings:
        offset = string.offset
        static_strings.append({
            "encoding": string.encoding.value.lower(),
            "offset": offset,
            "length": len(string.string),
            "string": string.string
        })
        
        structure_info = {"offset": offset, "string": string.string}
        
        if pe:
            for i, (start, end, htype) in enumerate(pe_headers):
                if start <= offset < end:
                    context[offset] = {
                        "structure": "pe.header",
                        "header_type": htype,
                        "tags": ["#common"]
                    }
                    pe_structure["headers"]["strings"].append(structure_info)
                    break
            
            section_found = False
            for (start, end), name in pe_sections.items():
                if start <= offset < end:
                    if name.startswith('.'):
                        structure_name = f"section{name}"
                    else:
                        structure_name = f"section.{name}"
                    
                    section_name = name if name.startswith('.') else f".{name}"
                    context[offset] = {
                        "structure": structure_name,
                        "parent_structure": "pe",
                        "tags": ["#section"]
                    }
                    
                    pe_structure["sections"][section_name]["strings"].append(structure_info)
                    section_found = True
                    
                    if string.string in import_entries:
                        dll_name = import_dll_map.get(string.string, "unknown")
                        context[offset] = {
                            "structure": "import table",
                            "parent_structure": structure_name,
                            "dll": dll_name,
                            "tags": ["#winapi"]
                        }
                        
                        if "imports" not in pe_structure["sections"][section_name]["structures"]:
                            pe_structure["sections"][section_name]["structures"]["imports"] = []
                            
                        pe_structure["sections"][section_name]["structures"]["imports"].append({
                            "function": string.string,
                            "dll": dll_name,
                            "offset": offset
                        })
                    
                    break
            
            if not section_found and string.string in import_entries:
                dll_name = import_dll_map.get(string.string, "unknown")
                context[offset] = {
                    "structure": "import table",
                    "dll": dll_name,
                    "tags": ["#winapi"]
                }

    for string in doc.strings.stack_strings:
        stack_entry = {
            "encoding": string.encoding.value.lower(),
            "offset": string.program_counter,
            "length": len(string.string),
            "string": string.string,
            "function": string.function,
            "stack_pointer": string.stack_pointer,
            "frame_offset": string.frame_offset
        }
        stack_strings.append(stack_entry)

    for string in doc.strings.tight_strings:
        tight_entry = {
            "encoding": string.encoding.value.lower(),
            "offset": string.program_counter,
            "length": len(string.string),
            "string": string.string,
            "function": string.function,
            "stack_pointer": string.stack_pointer,
            "frame_offset": string.frame_offset
        }
        tight_strings.append(tight_entry)

    for string in doc.strings.decoded_strings:
        decoded_strings.append({
            "encoding": string.encoding.value.lower(),
            "offset": string.decoding_routine,
            "length": len(string.string),
            "string": string.string,
            "decoded_at": string.decoded_at,
            "address": string.address,
            "address_type": string.address_type
        })
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
        },
        "pe_structure": pe_structure 
    }


def render(doc: ResultDocument) -> str:
    custom_format = create_custom_format(doc)
    return json.dumps(custom_format, indent=4)

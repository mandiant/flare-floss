#!/usr/bin/env python3
# Copyright 2021 Google LLC
# Modified for PyGhidra (Ghidra 12.0+) compatibility
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


"""
render-ghidra-import-script.py

Translate a floss result document into a PyGhidra-compatible script
that marks up the current workspace.

This version is compatible with Ghidra 12.0+ which uses PyGhidra (Python 3)
instead of Jython (Python 2.7).

Usage:

  $ floss suspicious.exe -j > floss-results.json
  $ python render-ghidra-import-script.py floss-results.json > apply_floss.py
  # now run `apply_floss.py` in Ghidra Script Manager
"""
import sys
import base64
import logging
import argparse
from pathlib import Path

from floss.results import AddressType, ResultDocument

logger = logging.getLogger("floss.render-ghidra-import-script")


# Template for the generated PyGhidra script
SCRIPT_TEMPLATE = '''# PyGhidra-compatible FLOSS import script
# Generated for Ghidra 12.0+ (PyGhidra / Python 3)
# @category FLOSS
# @menupath Tools.FLOSS.Apply FLOSS Results

import base64

from ghidra.program.model.listing import CodeUnit


def decode_string(b64_encoded: str) -> str:
    """Decode a base64-encoded UTF-8 string."""
    return base64.b64decode(b64_encoded).decode("utf-8")


def append_comment(ea: int, comment_text: str) -> None:
    """
    Append an EOL comment at the specified address.

    Args:
        ea: The effective address (as integer)
        comment_text: The comment text to append
    """
    addr = toAddr(ea)
    if addr is None:
        print(f"Warning: Could not resolve address 0x{{ea:x}}")
        return

    cu = currentProgram.getListing().getCodeUnitAt(addr)
    if cu is None:
        print(f"Warning: No code unit at address 0x{{ea:x}}")
        return

    existing_comment = cu.getComment(CodeUnit.EOL_COMMENT)

    if existing_comment is None:
        new_comment = comment_text
    else:
        # Ignore duplicates
        if comment_text in existing_comment:
            return
        new_comment = existing_comment + "\\n" + comment_text

    cu.setComment(CodeUnit.EOL_COMMENT, new_comment)
    createBookmark(addr, "decoded_string", comment_text)


def append_eol_comment_at_address(addr, comment_text: str) -> bool:
    """
    Append an EOL comment at the specified address.

    Returns True if successful, False otherwise.
    """
    cu = currentProgram.getListing().getCodeUnitAt(addr)
    if cu is None:
        return False

    existing_comment = cu.getComment(CodeUnit.EOL_COMMENT)

    if existing_comment is None:
        new_comment = comment_text
    else:
        if comment_text in existing_comment:
            return True  # Already exists
        new_comment = existing_comment + "\\n" + comment_text

    cu.setComment(CodeUnit.EOL_COMMENT, new_comment)
    return True


def find_stack_var_references(func, target_offset: int) -> list:
    """
    Find all instruction addresses that reference a stack variable at the given offset.

    Args:
        func: The function to search within
        target_offset: The stack frame offset to look for

    Returns:
        List of addresses where the stack variable is referenced
    """
    ref_addresses = []
    listing = currentProgram.getListing()

    # Iterate through all instructions in the function
    for inst in listing.getInstructions(func.getBody(), True):
        num_operands = inst.getNumOperands()
        for i in range(num_operands):
            refs = inst.getOperandReferences(i)
            for ref in refs:
                if ref.isStackReference():
                    stack_offset = ref.getStackOffset()
                    # Check both positive and negative offsets
                    if stack_offset == target_offset or stack_offset == -target_offset:
                        ref_addresses.append(inst.getAddress())
                        break

    return ref_addresses


def append_lvar_comment(fva: int, frame_offset: int, comment_text: str) -> None:
    """
    Append a comment to a stack variable in Ghidra and to all instructions that reference it.

    Args:
        fva: The function virtual address (as integer)
        frame_offset: The stack frame offset
        comment_text: The comment text to append
    """
    addr = toAddr(fva)
    if addr is None:
        print(f"Warning: Could not resolve function address 0x{{fva:x}}")
        return

    func = getFunctionContaining(addr)
    if func is None:
        print(f"Warning: No function at address 0x{{fva:x}}")
        return

    commented_count = 0

    # First, try to add comment to the stack variable itself
    stack_frame = func.getStackFrame()
    if stack_frame is not None:
        for offset in [frame_offset, -frame_offset]:
            var = stack_frame.getVariableContaining(offset)
            if var is not None:
                existing_comment = var.getComment()
                if existing_comment is None:
                    new_comment = comment_text
                elif comment_text not in existing_comment:
                    new_comment = existing_comment + "\\n" + comment_text
                else:
                    new_comment = None  # Already exists
                if new_comment is not None:
                    var.setComment(new_comment)
                break

    # Find all references to this stack variable and add EOL comments
    ref_addresses = find_stack_var_references(func, frame_offset)
    for ref_addr in ref_addresses:
        if append_eol_comment_at_address(ref_addr, comment_text):
            commented_count += 1

    if commented_count > 0:
        print(f"FLOSS: Added comment to {{commented_count}} instruction(s) referencing stack offset 0x{{frame_offset:x}} in function 0x{{fva:x}}")
        createBookmark(addr, "stackstring", comment_text)
    else:
        # Fallback: add comment at function entry point if no references found
        if append_eol_comment_at_address(addr, comment_text):
            print(f"FLOSS: Added comment at function entry 0x{{fva:x}} (no xrefs found for stack offset 0x{{frame_offset:x}})")
            createBookmark(addr, "stackstring", comment_text)
        else:
            print(f"Warning: Could not add comment for stack offset 0x{{frame_offset:x}} in function 0x{{fva:x}}")


def run() -> None:
    """Main entry point for the FLOSS annotation script."""
    print("Annotating {total_strings} strings from FLOSS for {file_path}")
{main_commands}


# Script execution
run()
'''


def render_ghidra_script(result_document: ResultDocument) -> str:
    """
    Create PyGhidra-compatible script contents for Ghidra file annotations.

    This generates a script that works with Ghidra 12.0+ PyGhidra environment.
    """
    main_commands = []

    for ds in result_document.strings.decoded_strings:
        if ds.string != "":
            b64 = base64.b64encode(ds.string.encode("utf-8")).decode("ascii")
            if ds.address_type == AddressType.GLOBAL:
                main_commands.append(
                    f'    print(f"FLOSS: string \\"{{decode_string(\\"{b64}\\")}}\\" at global VA 0x{ds.address:x}")'
                )
                main_commands.append(f'    append_comment(0x{ds.address:x}, "FLOSS: " + decode_string("{b64}"))')
            else:
                main_commands.append(
                    f'    print(f"FLOSS: string \\"{{decode_string(\\"{b64}\\")}}\\" decoded at VA 0x{ds.decoded_at:x}")'
                )
                main_commands.append(f'    append_comment(0x{ds.decoded_at:x}, "FLOSS: " + decode_string("{b64}"))')
    main_commands.append('    print("Imported decoded strings from FLOSS")')

    for ss in result_document.strings.stack_strings:
        if ss.string != "":
            b64 = base64.b64encode(ss.string.encode("utf-8")).decode("ascii")
            main_commands.append(
                f'    append_lvar_comment(0x{ss.function:x}, {ss.frame_offset}, "FLOSS stackstring: " + decode_string("{b64}"))'
            )
    main_commands.append('    print("Imported stackstrings from FLOSS")')

    for ts in result_document.strings.tight_strings:
        if ts.string != "":
            b64 = base64.b64encode(ts.string.encode("utf-8")).decode("ascii")
            main_commands.append(
                f'    append_lvar_comment(0x{ts.function:x}, {ts.frame_offset}, "FLOSS tightstring: " + decode_string("{b64}"))'
            )
    main_commands.append('    print("Imported tightstrings from FLOSS")')

    total_strings = (
        len(result_document.strings.decoded_strings)
        + len(result_document.strings.stack_strings)
        + len(result_document.strings.tight_strings)
    )
    file_path = result_document.metadata.file_path

    script_content = SCRIPT_TEMPLATE.format(
        total_strings=total_strings,
        file_path=file_path,
        main_commands="\n".join(main_commands),
    )

    return script_content


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a PyGhidra script to apply FLOSS results (Ghidra 12.0+).")
    parser.add_argument("/path/to/report.json", help="path to JSON document from `floss --json`")

    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
    )

    args = parser.parse_args()
    args.report_path = getattr(args, "/path/to/report.json")

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    # Support both Pydantic v1 and v2
    json_path = Path(args.report_path)
    if hasattr(ResultDocument, "model_validate_json"):
        # Pydantic v2
        result_document = ResultDocument.model_validate_json(json_path.read_text(encoding="utf-8"))
    else:
        # Pydantic v1
        result_document = ResultDocument.parse_file(json_path)

    print(render_ghidra_script(result_document))
    return 0


if __name__ == "__main__":
    sys.exit(main())

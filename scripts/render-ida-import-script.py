#!/usr/bin/env python3
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


# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""
render-ida-import-script.py

Translate a floss result document into an IDA Python script
that marks up the current workspace.

Usage:

  $ floss suspicious.exe -j > floss-results.json
  $ python render-ida-import-script.py floss-results.json > apply_floss.py
  # now run `apply_floss.py` in IDA
"""
import sys
import base64
import logging
import argparse
from pathlib import Path

from floss.results import AddressType, ResultDocument

logger = logging.getLogger("floss.render-ida-import-script")


def render_ida_script(result_document: ResultDocument) -> str:
    """
    Create IDAPython script contents for IDB file annotations.
    """
    main_commands = []
    for ds in result_document.strings.decoded_strings:
        if ds.string != "":
            b64 = base64.b64encode(ds.string.encode("utf-8")).decode("ascii")
            b64 = 'base64.b64decode("%s").decode("utf-8")' % b64
            if ds.address_type == AddressType.GLOBAL:
                main_commands.append('print("FLOSS: string \\"%%s\\" at global VA 0x%x" %% (%s))' % (ds.address, b64))
                main_commands.append('AppendComment(%d, "FLOSS: " + %s, True)' % (ds.address, b64))
            else:
                main_commands.append(
                    'print("FLOSS: string \\"%%s\\" decoded at VA 0x%x" %% (%s))' % (ds.decoded_at, b64)
                )
                main_commands.append('AppendComment(%d, "FLOSS: " + %s)' % (ds.decoded_at, b64))
    main_commands.append('print("Imported decoded strings from FLOSS")')

    for ss in result_document.strings.stack_strings:
        if ss.string != "":
            b64 = base64.b64encode(ss.string.encode("utf-8")).decode("ascii")
            b64 = 'base64.b64decode("%s").decode("utf-8")' % b64
            main_commands.append(
                'AppendLvarComment(%d, %d, "FLOSS stackstring: " + %s, True)' % (ss.function, ss.frame_offset, b64)
            )
    main_commands.append('print("Imported stackstrings from FLOSS")')

    for ts in result_document.strings.tight_strings:
        if ts.string != "":
            b64 = base64.b64encode(ts.string.encode("utf-8")).decode("ascii")
            b64 = 'base64.b64decode("%s").decode("utf-8")' % b64
            main_commands.append(
                'AppendLvarComment(%d, %d, "FLOSS tightstring: " + %s, True)' % (ts.function, ts.frame_offset, b64)
            )
    main_commands.append('print("Imported tightstrings from FLOSS")')

    script_content = """
import base64

def AppendComment(ea, string, repeatable=False):
    current_string = get_cmt(ea, repeatable)

    if not current_string:
        cmt = string
    else:
        if string in current_string:  # ignore duplicates
            return
        cmt = current_string + "\\n" + string
    set_cmt(ea, cmt, repeatable)


def AppendLvarComment(fva, frame_offset, s, repeatable=False):
    stack = get_func_attr(fva, FUNCATTR_FRAME)
    if stack:
        lvar_offset = get_func_attr(fva, FUNCATTR_FRSIZE) - frame_offset
        if lvar_offset and lvar_offset > 0:
            string = get_member_cmt(stack, lvar_offset, repeatable)
            if not string:
                string = s
            else:
                if s in string:  # ignore duplicates
                    return
                string = string + "\\n" + s
            if set_member_cmt(stack, lvar_offset, string, repeatable):
                print('FLOSS appended stackstring comment \\"%%s\\" at stack frame offset 0x%%x in function 0x%%x' %% (s, frame_offset, fva))
                return
    print('Failed to append stackstring comment \\"%%s\\" at stack frame offset 0x%%x in function 0x%%x' %% (s, frame_offset, fva))


def main():
    print('Annotating %d strings from FLOSS for %s')
    %s
    ida_kernwin.refresh_idaview_anyway()

if __name__ == "__main__":
    main()
""" % (
        len(result_document.strings.decoded_strings)
        + len(result_document.strings.stack_strings)
        + len(result_document.strings.tight_strings),
        result_document.metadata.file_path,
        "\n    ".join(main_commands),
    )
    return script_content


def main():
    parser = argparse.ArgumentParser(description="Generate an IDA Python script to apply FLOSS results.")
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

    result_document = ResultDocument.parse_file(Path(args.report_path))

    print(render_ida_script(result_document))
    return 0


if __name__ == "__main__":
    sys.exit(main())

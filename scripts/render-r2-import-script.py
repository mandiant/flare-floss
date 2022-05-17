#!/usr/bin/env python3
# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.

"""
render-r2-import-script.py

Translate a floss result document into an radare2 script
that marks up the current workspace.

Usage:

  $ floss suspicious.exe -j > floss-results.json
  $ python render-r2-import-script.py floss-results.json > apply_floss.py
  # now run `apply_floss.py` in radare2

Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import sys
import base64
import logging
import argparse

from floss.results import AddressType, ResultDocument

logger = logging.getLogger("floss.render-r2-import-script")


def render_r2_script(result_document: ResultDocument) -> str:
    """
    Create r2script contents for r2 session annotations.
    """
    main_commands = []
    fvas = []
    for ds in result_document.strings.decoded_strings:
        if ds.string != "":
            sanitized_string = base64.b64encode(
                b'"FLOSS: %s (floss_%x)"' % (ds.string.encode("utf-8"), ds.address)
            ).decode("ascii")
            if ds.address_type == AddressType.GLOBAL:
                main_commands.append("CCu base64:%s @ %d" % (sanitized_string, ds.address))
                if ds.decoding_routine not in fvas:
                    main_commands.append("af @ %d" % (ds.decoding_routine))
                    main_commands.append("afn floss_%x @ %d" % (ds.decoding_routine, ds.decoding_routine))
                    fvas.append(ds.decoding_routine)
            else:
                main_commands.append("CCu base64:%s @ %d" % (sanitized_string, ds.decoded_at))
                if ds.decoding_routine not in fvas:
                    main_commands.append("af @ %d" % (ds.decoding_routine))
                    main_commands.append("afn floss_%x @ %d" % (ds.decoding_routine, ds.decoding_routine))
                    fvas.append(ds.decoding_routine)
    ss_len = 0
    for ss in result_document.strings.stack_strings:
        if ss.string != "":
            sanitized_string = base64.b64encode(b'"FLOSS: %s"' % ss.string.encode("utf-8")).decode("ascii")
            main_commands.append("Ca -0x%x base64:%s @ %d" % (ss.frame_offset, sanitized_string, ss.function))
            ss_len += 1

    return "\n".join(main_commands)


def main():
    parser = argparse.ArgumentParser(description="Generate an radare2 script to apply FLOSS results.")
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

    result_document = ResultDocument.parse_file(args.report_path)

    print(render_r2_script(result_document))
    return 0


if __name__ == "__main__":
    sys.exit(main())

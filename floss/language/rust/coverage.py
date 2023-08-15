# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import sys
import hashlib
import logging
import pathlib
import argparse
from typing import List, Tuple, Iterable, Optional

import pefile
import tabulate

from floss.results import StaticString, StringEncoding
from floss.strings import extract_ascii_unicode_strings
from floss.render.sanitize import sanitize
from floss.language.rust.extract import extract_rust_strings

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4


def main():
    parser = argparse.ArgumentParser(description="Get Rust strings")
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length",
    )
    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="disable all status output except fatal errors",
    )
    arrs = parser.parse_arrs()

    if arrs.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    try:
        pe = pefile.PE(arrs.path)
    except pefile.PEFormatError as err:
        logger.debug(f"NOT a valid PE file: {err}")
        return 1

    path = pathlib.Path(arrs.path)

    # see only .rdata section
    buf = path.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    static_strings = list(extract_ascii_unicode_strings(buf, arrs.min_length))

    rust_strings = extract_rust_strings(path, arrs.min_length)

    get_extract_stats(pe, static_strings, rust_strings, arrs.min_length)


def get_extract_stats(pe, all_ss_strings: List[StaticString], rust_strings, min_len) -> float:
    all_strings = list()

    for ss in all_ss_strings:
        sec = pe.get_section_by_rva(ss.offset)
        secname = sec.Name.decode("utf-8").split("\x00")[0] if sec else ""
        all_strings.append((secname, ss))

    len_all_ss = 0
    len_rust_str = 0

    rs_found = list()
    results = list()
    for secname, s in all_strings:
        if secname != ".rdata":
            continue

        len_all_ss += len(s.string)

        # Generate unique ID for each string
        orig_len = len(s.string)
        sha256 = hashlib.sha256()
        sha256.update(s.string.encode("utf-8"))
        s_id = sha256.hexdigest()[:3].upper()
        s_range = (s.offset, s.offset + len(s.string))

        found = False
        for rs in rust_strings:
            sec = pe.get_section_by_rva(rs.offset)
            rs_sec = sec.Name.decode("utf-8").split("\x00")[0] if sec else ""

            if rs_sec != ".rdata":
                continue

            if (
                rs.string
                and rs.string in s.string
                and rs_sec == secname
                and s.offset <= rs.offset <= s.offset + orig_len
            ):
                found = True
                len_rust_str += len(rs.string)

                # remove found string data
                idx = s.string.find(rs.string)
                assert idx != -1
                if idx == 0:
                    new_offset = s.offset + idx + len(rs.string)
                else:
                    new_offset = s.offset

                replaced_s = s.string.replace(rs.string, "", 1)
                replaced_len = len(replaced_s)
                s_trimmed = StaticString(
                    string=replaced_s,
                    offset=new_offset,
                    encoding=s.encoding,
                )

                type_ = "substring"
                if s.string[: len(rs.string)] == rs.string and s.offset == rs.offset:
                    type_ = "exactsubstr"

                results.append((secname, s_id, s_range, True, type_, s, replaced_len, rs))

                s = s_trimmed

                rs_found.append(rs)

                if replaced_len < min_len:
                    results.append((secname, s_id, s_range, False, "missing", s, orig_len - replaced_len, rs))
                    break

        if not found:
            null = StaticString(string="", offset=0, encoding=StringEncoding.UTF8)
            results.append((secname, s_id, s_range, False, "", s, 0, null))

    rows = list()
    for rs in rust_strings:
        sec = pe.get_section_by_rva(rs.offset)
        rs_sec = sec.Name.decode("utf-8").split("\x00")[0] if sec else ""
        if rs_sec != ".rdata":
            continue

        if rs in rs_found:
            continue

        rsdata = rs.string
        if len(rs.string) >= 50:
            rsdata = rs.string[:36] + "...." + rs.string[-10:]
        rsdata = sanitize(rsdata)

        rows.append(
            (
                f"{rs_sec}",
                f"",
                f"",
                f"{rs.offset:8x}",
                f"",
                f"unmatched rust string",
                f"",
                f"",
                f"{len(rs.string) if rs.string else ''}",
                f"{rsdata}",
                f"{hex(rs.offset) if rs.offset else ''}",
            )
        )

    for r in results:
        secname, s_id, s_range, found, msg, s, len_after, rs = r

        sdata = s.string
        if len(s.string) >= 50:
            sdata = s.string[:36] + "...." + s.string[-10:]
        sdata = sanitize(sdata)

        rsdata = rs.string
        if len(rs.string) >= 50:
            rsdata = rs.string[:36] + "...." + rs.string[-10:]
        rsdata = sanitize(rsdata)

        len_info = f"{len(s.string):3d}"
        if found:
            len_info = f"{len(s.string):3d} > {len_after:3d} ({(len(s.string) - len_after) * -1:2d})"

        rows.append(
            (
                f"{secname}",
                f"<{s_id}>",
                f"{s_range[0]:x} - {s_range[1]:x}",
                f"{s.offset:8x}",
                f"{found}",
                f"{msg}",
                len_info,
                f"{sdata}",
                f"{len(rs.string) if rs.string else ''}",
                f"{rsdata}",
                f"{hex(rs.offset) if rs.offset else ''}",
            )
        )

    rows = sorted(rows, key=lambda t: t[3])

    print(
        tabulate.tabulate(
            rows,
            headers=[
                "section",
                "id",
                "range",
                "offset",
                "found",
                "msg",
                "slen",
                "string",
                "rslen",
                "ruststring",
                "rsoff",
            ],
            tablefmt="psql",
        )
    )

    print(".rdata only")
    print("len all string chars:", len_all_ss)
    print("len rust string chars  :", len_rust_str)
    print(f"Percentage of string chars extracted: {round(100 * (len_rust_str / len_all_ss))}%")
    print()

    return 100 * (len_rust_str / len_all_ss)


if __name__ == "__main__":
    sys.exit(main())

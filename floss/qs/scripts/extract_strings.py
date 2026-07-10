# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

# examples:
# $ extract_strings.py -d --pes C:\Windows cwinpes

import os
import sys
import json
import hashlib
import logging
import argparse
import datetime
import collections
import dataclasses
from typing import List, Tuple, Mapping
from collections.abc import Iterator

import dnfile
import pefile

import floss.strings
from floss.qs.db.gp import Encoding, Location

MIN_LEN = 6
MAX_LEN_PES = 100
MAX_LEN_LIBS = 64  # TODO check, but these tend to contain long strings, focus on actual string data via better parsing

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class FileString:
    offset: int
    string: str
    encoding: Encoding
    location: Location


@dataclasses.dataclass
class PeStrings:
    path: str
    sha256: str
    timestamp: str
    dotnet: bool
    strings: List[FileString]


def match(path: str, suffixes: Tuple[str, ...], prefixes: Tuple[str, ...]):
    if suffixes and path.endswith(suffixes):
        return True
    elif prefixes and path.startswith(prefixes):
        return True
    return False


def find_file_paths(path: str, suffixes: Tuple[str, ...] = (), prefixes: Tuple[str, ...] = ()) -> Iterator[str]:
    if not os.path.exists(path):
        raise IOError(f"path {path} does not exist or cannot be accessed")

    if os.path.isfile(path):
        if match(path, suffixes, prefixes):
            yield path
    elif os.path.isdir(path):
        logger.debug("searching directory %s", os.path.abspath(os.path.normpath(path)))
        for root, dirs, files in os.walk(path):
            if root.startswith((r"C:\Windows\WinSxS",)):  # can be large, stores install/backup related files
                logger.debug("skip %s", root)
                continue

            for file in files:
                if match(file, suffixes, prefixes):
                    file_path = os.path.join(root, file)
                    logger.debug("found file: %s", os.path.abspath(os.path.normpath(file_path)))
                    yield file_path


# TODO adjust to new JSON format
def extract_libs(dir_path: str, outdir: str, min_len: int, max_len: int):
    for file_path in find_file_paths(dir_path, suffixes=(".lib",)):
        with open(file_path, "rb") as f:
            binary_data = f.read()

        extracted_strings = floss.strings.extract_ascii_unicode_strings(binary_data, min_len)
        filtered_strings = filter(lambda s: len(s.string) <= max_len, extracted_strings)
        sorted_strings = sorted(filtered_strings, key=lambda s: (s.string, len(s.string)))

        outfile = os.path.join(outdir, f"{file_path.replace(os.sep, '--')}.json")
        d: Mapping[str, Mapping[str, List[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
        for s in sorted_strings:
            if s.string not in d[file_path][s.encoding]:
                d[file_path][s.encoding.value].append(s.string)
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)


def get_section(offset: int, sections: List):
    sec = None
    for sname, (low, high) in sections:
        if low <= offset < high:
            return sname
    if sec is None:
        raise ValueError(f"{offset} not in sections:\n {sections}")


def extract_pes(dir_path, outdir, min_len: int, max_len: int):
    seen_hashes = set()

    for file_path in find_file_paths(dir_path, suffixes=(".exe", ".dll", ".sys", ".exe_", ".dll_", ".sys_")):
        outfile = os.path.join(outdir, f"{os.path.basename(file_path)}.json")
        if os.path.exists(outfile):
            with open(outfile, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
                if os.path.abspath(file_path) == existing_data["path"]:
                    logger.info("skipping file with existing data: %s", file_path)
                    continue
                else:
                    # this doesn't work well for multiple extractions of the same data sources as data gets duplicated
                    # dedup is possible via the hashes though
                    #
                    # ignoring type so that the f can alias over the file handle above
                    f, ext = os.path.splitext(outfile)  # type: ignore
                    outfile = f"{f}{str(datetime.datetime.now().timestamp()).replace('.', '')}{ext}"
                    if os.path.exists(outfile):
                        logger.warning("skipping file with existing data: %s", file_path)
                    logger.info("updating file name: %s", outfile)

        try:
            with open(file_path, "rb") as f:
                binary_data = f.read()
        except PermissionError as e:
            logger.warning("%s", e)
            continue

        try:
            pe = pefile.PE(data=binary_data)
        except pefile.PEFormatError:
            continue

        dnpe = dnfile.dnPE(data=binary_data)
        sections = get_section_boundaries(pe, len(binary_data))

        extracted_strings = floss.strings.extract_ascii_unicode_strings(binary_data, min_len)
        filtered_strings = filter(lambda es: len(es.string) <= max_len, extracted_strings)

        if os.path.exists(outfile):
            raise Exception(f"{outfile} already exists")

        sha256 = hashlib.sha256()
        sha256.update(binary_data)
        sha256_hash = sha256.hexdigest()

        if sha256_hash in seen_hashes:
            logger.info("skipping file with sha256 hash %s: already analyzed", sha256_hash)
            continue
        else:
            seen_hashes.add(sha256_hash)

        filestrings = []
        for s in filtered_strings:
            encoding = s.encoding.value.lower()
            assert isinstance(encoding, str)
            assert encoding in ("ascii", "utf-16le", "unknown")

            filestrings.append(
                FileString(
                    offset=s.offset,
                    string=s.string,
                    encoding=encoding,  # type: ignore
                    location=get_section(s.offset, sections),
                )
            )

        pestrings = PeStrings(
            path=os.path.abspath(os.path.normpath(file_path)),
            sha256=sha256_hash,
            timestamp=datetime.datetime.now().isoformat(),
            dotnet=bool(dnpe.net),
            strings=filestrings,
        )

        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(pestrings), f, indent=2)


def get_section_boundaries(pe: pefile.PE, file_size: int):
    sections = [("header", (0, len(pe.header)))]

    for section in pe.sections:
        try:
            # TODO there must be a better way to deal with section names
            name = section.Name.decode("utf-8").split("\x00")[0]
        except UnicodeDecodeError:
            name = section.Name[: section.Name.index(b"\x00")].decode("utf-8").rstrip("\x00")
            logger.warning("weird section name: %s - using: %s", section.Name, name)
        if section.Misc_PhysicalAddress and section.SizeOfRawData:
            # section names may not be unique
            sections.append((name, (section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData)))

    if file_size > sections[-1][1][1]:
        sections.append(("overlay", (sections[-1][1][1], file_size)))

    return sections


def main():
    parser = argparse.ArgumentParser(description="Extract raw strings from select files.")
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument("outdir", help="directory to store results to")
    parser.add_argument(
        "--libs",
        action="store_true",
        help=r"recursively search and extract string from .lib files under path, e.g., C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.35.32215\crt\src\i386",
    )
    parser.add_argument(
        "--pes",
        action="store_true",
        help="recursively search and extract string from PE files under path, e.g., C:\\Windows",
    )
    parser.add_argument("--min-len", type=int, default=MIN_LEN, help="minimum string length")
    parser.add_argument("--max-len", type=int, default=-1, help="maximum string length")

    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
    )
    args = parser.parse_args()

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    # ignore WARNING:dnfile.utils:invalid compressed int: leading byte: 0xec
    logging.getLogger("dnfile.utils").setLevel(logging.CRITICAL)

    if os.path.exists(args.outdir):
        logger.error("%s already exists", args.outdir)
        use = input("use existing dir? y/[n] ")
        if use != "y":
            return -1
    else:
        os.mkdir(args.outdir)

    max_len = args.max_len
    if max_len == -1:
        if args.libs:
            max_len = MAX_LEN_PES
        elif args.libs:
            max_len = MAX_LEN_LIBS
        else:
            raise ValueError("unknown extraction type")

    if args.libs:
        extract_libs(args.path, args.outdir, args.min_len, max_len)
    elif args.pes:
        extract_pes(args.path, args.outdir, args.min_len, max_len)

    return 0


if __name__ == "__main__":
    sys.exit(main())

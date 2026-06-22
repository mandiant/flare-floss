# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

# examples:
# $ extract_strings.py --pes C:\Windows ./extracted/
# $ extract_strings.py --pes ./samples/ ./extracted/

import os
import sys
import json
import hashlib
import logging
import pathlib
import argparse
import datetime
import dataclasses
from typing import List, Optional, Tuple
from collections.abc import Iterator

import dnfile
import pefile

import floss.strings
from floss.qs.db.gp import Encoding, Location

MIN_LEN = 6
MAX_LEN_PES = 100
MAX_LEN_LIBS = 64

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
    imphash: Optional[str] = None


def find_file_paths(path: str, suffixes: Tuple[str, ...] = (), prefixes: Tuple[str, ...] = ()) -> Iterator[str]:
    if not os.path.exists(path):
        raise IOError(f"path {path} does not exist or cannot be accessed")

    if os.path.isfile(path):
        if suffixes and path.endswith(suffixes):
            yield path
    elif os.path.isdir(path):
        logger.debug("searching directory %s", os.path.abspath(os.path.normpath(path)))
        for root, dirs, files in os.walk(path):
            if root.startswith((r"C:\Windows\WinSxS",)):
                logger.debug("skip %s", root)
                continue

            for file in files:
                if suffixes and file.endswith(suffixes):
                    file_path = os.path.join(root, file)
                    logger.debug("found file: %s", os.path.abspath(os.path.normpath(file_path)))
                    yield file_path


def get_section_boundaries(pe: pefile.PE, file_size: int):
    sections = [("header", (0, len(pe.header)))]

    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8").split("\x00")[0]
        except UnicodeDecodeError:
            name = section.Name[: section.Name.index(b"\x00")].decode("utf-8").rstrip("\x00")
            logger.warning("weird section name: %s - using: %s", section.Name, name)
        if section.Misc_PhysicalAddress and section.SizeOfRawData:
            sections.append((name, (section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData)))

    if file_size > sections[-1][1][1]:
        sections.append(("overlay", (sections[-1][1][1], file_size)))

    return sections


def get_section(offset: int, sections: List):
    for sname, (low, high) in sections:
        if low <= offset < high:
            return sname
    raise ValueError(f"{offset} not in sections:\n {sections}")


def _scan_existing_hashes(outdir: pathlib.Path) -> set:
    seen = set()
    for p in outdir.rglob("*.json"):
        seen.add(p.stem)
    return seen


def extract_pes(dir_path: str, outdir: pathlib.Path, min_len: int, max_len: int):
    seen_hashes = _scan_existing_hashes(outdir)
    logger.info("found %d already-processed files in %s", len(seen_hashes), outdir)

    for file_path in find_file_paths(dir_path, suffixes=(".exe", ".dll", ".sys", ".exe_", ".dll_", ".sys_")):
        try:
            with open(file_path, "rb") as f:
                binary_data = f.read()
        except PermissionError as e:
            logger.warning("%s", e)
            continue

        sha256 = hashlib.sha256(binary_data).hexdigest()

        if sha256 in seen_hashes:
            logger.debug("skipping already-processed %s (%s)", file_path, sha256)
            continue

        out_path = outdir / sha256[:2] / f"{sha256}.json"
        if out_path.exists():
            seen_hashes.add(sha256)
            logger.debug("skipping existing output %s", out_path)
            continue

        try:
            pe = pefile.PE(data=binary_data)
        except pefile.PEFormatError:
            continue

        dnpe = dnfile.dnPE(data=binary_data)
        sections = get_section_boundaries(pe, len(binary_data))

        try:
            imphash = pe.get_imphash() or None
        except Exception:
            imphash = None

        extracted_strings = floss.strings.extract_ascii_unicode_strings(binary_data, min_len)
        filtered_strings = [s for s in extracted_strings if len(s.string) <= max_len]

        filestrings = []
        for s in filtered_strings:
            encoding = s.encoding.value.lower()
            assert isinstance(encoding, str)
            assert encoding in ("ascii", "utf-16le", "unknown")

            try:
                location = get_section(s.offset, sections)
            except ValueError:
                location = "unknown"

            filestrings.append(
                FileString(
                    offset=s.offset,
                    string=s.string,
                    encoding=encoding,  # type: ignore
                    location=location,
                )
            )

        pestrings = PeStrings(
            path=os.path.abspath(os.path.normpath(file_path)),
            sha256=sha256,
            timestamp=datetime.datetime.now().isoformat(),
            dotnet=bool(dnpe.net),
            imphash=imphash,
            strings=filestrings,
        )

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(pestrings), f)

        seen_hashes.add(sha256)
        logger.info("extracted %s -> %s", file_path, out_path)


def main():
    parser = argparse.ArgumentParser(description="Extract raw strings from PE files.")
    parser.add_argument("path", help="file or directory to analyze")
    parser.add_argument("outdir", help="directory to store results")
    parser.add_argument(
        "--pes",
        action="store_true",
        help="recursively search and extract strings from PE files (.exe, .dll, .sys)",
    )
    parser.add_argument("--min-len", type=int, default=MIN_LEN, help="minimum string length")
    parser.add_argument("--max-len", type=int, default=-1, help="maximum string length (-1 = auto)")

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

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    max_len = args.max_len
    if max_len == -1:
        if args.pes:
            max_len = MAX_LEN_PES
        else:
            raise ValueError("--pes required when --max-len is not set")

    if args.pes:
        extract_pes(args.path, outdir, args.min_len, max_len)
    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

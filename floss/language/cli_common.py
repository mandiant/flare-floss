import logging
import argparse

import pefile


def add_common_args(parser: argparse.ArgumentParser, default_min_length: int):
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=default_min_length,
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


def configure_logging(debug):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level)
    logging.getLogger().setLevel(level)


def open_pe_or_none(path: str, logger: logging.Logger):
    try:
        return pefile.PE(path)
    except pefile.PEFormatError as err:
        logger.debug(f"NOT a valid PE file: {err}")
        return None

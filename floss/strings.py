# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import re
from itertools import chain
from typing import Iterable

from floss.results import StaticString, StringEncoding

# we don't include \r and \n to make output easier to understand by humans and to simplify rendering
ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
ASCII_RE_4 = re.compile(rb"([%s]{%d,})" % (ASCII_BYTE, 4))
UNICODE_RE_4 = re.compile(rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = ["A", "\x00", "\xfe", "\xff"]
MIN_LENGTH = 4
SLICE_SIZE = 4096


def buf_filled_with(buf, character):
    """Determines if a buffer is entirely filled with a specified character.

    Checks the buffer in chunks and compares them against a reference chunk created from the provided character.

    Args:
        buf: The buffer to be analyzed.
        character: The character to check for.

    Returns:
        bool: True if the buffer is filled with the given character, False otherwise.
    """
    dupe_chunk = character * SLICE_SIZE
    for offset in range(0, len(buf), SLICE_SIZE):
        new_chunk = buf[offset : offset + SLICE_SIZE]
        if dupe_chunk[: len(new_chunk)] != new_chunk:
            return False
    return True


def extract_ascii_unicode_strings(buf, n=MIN_LENGTH) -> Iterable[StaticString]:
    """Extract ASCII and Unicode strings from the given binary data.

    Args:
        buf: A bytestring.
        n: The minimum length of strings to extract. (Default value = MIN_LENGTH)
    """
    yield from chain(extract_ascii_strings(buf, n), extract_unicode_strings(buf, n))


def extract_ascii_strings(buf, n=MIN_LENGTH) -> Iterable[StaticString]:
    """Extract ASCII strings from the given binary data.

    Args:
        buf: A bytestring.
        n: The minimum length of strings to extract. (Default value = MIN_LENGTH)

    Returns:
        Iterable[StaticString]: An iterable of StaticString objects representing the extracted strings.
    """

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    r = None
    if n == 4:
        r = ASCII_RE_4
    else:
        reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        yield StaticString(
            string=match.group().decode("ascii"),
            offset=match.start(),
            encoding=StringEncoding.ASCII,
        )


def extract_unicode_strings(buf, n=MIN_LENGTH) -> Iterable[StaticString]:
    """Extract naive UTF-16 strings from the given binary data.

    Args:
        buf: A bytestring.
        n: The minimum length of strings to extract. (Default value = MIN_LENGTH)

    Returns:
        Iterable[StaticString]: An iterable of StaticString objects representing the extracted strings.
    """

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    if n == 4:
        r = UNICODE_RE_4
    else:
        reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        try:
            yield StaticString(
                string=match.group().decode("utf-16"),
                offset=match.start(),
                encoding=StringEncoding.UTF16LE,
            )
        except UnicodeDecodeError:
            pass


def main():
    """Main function for standalone usage."""
    import sys

    with open(sys.argv[1], "rb") as f:
        b = f.read()

    for s in extract_ascii_strings(b):
        print("0x{:x}: {:s}".format(s.offset, s.string))

    for s in extract_unicode_strings(b):
        print("0x{:x}: {:s}".format(s.offset, s.string))


if __name__ == "__main__":
    main()

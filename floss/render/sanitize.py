# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import string


def sanitize(s: str, is_ascii_only=True) -> str:
    """
    Sanitize a string for printing.
    
    Args:
        s: The string to sanitize.
        is_ascii_only: Whether to only allow ASCII characters.

    Returns:
        The sanitized string.

    """
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    s = s.replace("\\\\", "\\")  # print single backslashes
    if is_ascii_only:
        s = "".join(c for c in s if c in string.printable)
    return s

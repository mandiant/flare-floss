# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import string


def sanitize(s: str) -> str:
    """
    Return sanitized string for printing to cli.
    """
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    s = s.replace("\\\\", "\\")  # print single backslashes
    s = "".join(c for c in s if c in string.printable)
    return s

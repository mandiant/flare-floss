# Copyright 2022 Google LLC
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


import logging
from enum import Enum

TRACE = logging.DEBUG - 1
setattr(logging, "TRACE", TRACE)
logging.addLevelName(TRACE, "TRACE")


class DebugLevel(int, Enum):
    NONE = 0
    DEFAULT = 1
    TRACE = 2
    SUPERTRACE = 3


GREY = "\x1b[38;21m"
CYAN = "\x1b[36;21m"
MAUVE = "\x1b[34;21m"
YELLOW = "\x1b[33;21m"
RED = "\x1b[31;21m"
BOLD_RED = "\x1b[31;1m"
RESET = "\x1b[0m"


def make_format(color):
    return f"{color}%(levelname)s{RESET}: %(name)s: %(message)s"


FORMATS = {
    logging.TRACE: make_format(MAUVE),  # type: ignore
    logging.DEBUG: make_format(GREY),
    logging.INFO: make_format(CYAN),
    logging.WARNING: make_format(YELLOW),
    logging.ERROR: make_format(RED),
    logging.CRITICAL: make_format(BOLD_RED),
}

FORMATTERS = {level: logging.Formatter(FORMATS[level]) for level in FORMATS.keys()}


class ColorFormatter(logging.Formatter):
    """
    Logging Formatter to add colors and count warning / errors

    via: https://stackoverflow.com/a/56944256/87207
    """

    def format(self, record):
        return FORMATTERS[record.levelno].format(record)


class LoggerWithTrace(logging.getLoggerClass()):  # type: ignore
    def trace(self, msg, *args, **kwargs):
        self.log(TRACE, msg, *args, **kwargs)


logging.setLoggerClass(LoggerWithTrace)


def getLogger(name) -> LoggerWithTrace:
    """
    a logging constructor that guarantees that the TRACE level is available.
    use this just like `logging.getLogger`.

    because we patch stdlib logging upon import of this module (side-effect),
    and we can't be sure how callers order their imports,
    then we want to provide a way to ensure that callers can access TRACE consistently.
    if callers use `floss.logging.getLogger()` intead of `logging.getLogger()`,
    then they'll be guaranteed to have access to TRACE.
    """
    return logging.getLogger(name)  # type: ignore

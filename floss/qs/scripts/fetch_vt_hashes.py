"""
fetches hashes of relevent file types published by VT in the given time range.
example:

    $ python fetch_vt_hashes.py 202305010000 202305020000
    INFO:__main__:fetching feed: 2023-05-01T00:00:00
    3bf67578d120ecc7710e56781e2f9a2fa14b94bbcd45d7ae0aa82098d327e4d7
    2a2c83bfd4b2e73e452365b972f2e479a6476f8ba6db2eb44d166bb9dfb1d3bd
    6ac76d0fc8bfe86f97301824b8631827aa77ef951d48cfc2c60b648098571fe5
    d27979456d897b1a8ebda208cb413004e48c4894ebabd934d89f6bfaeca2ae25
    12dd4c2e26a7e686d952addfde5eb8c1ccce99bdd3af2a7661c4368a2b2526c4
    33831bd454dffa78b850cd4d24903d968d36aaf2141a2c6eb8f29fc7cecd35d9
    5b641dec81aec1cf7ac0cce9fc067bb642fbd32da138a36e3bdac3bb5b36c37a
    b801b4fcb18b341f1d64f89aa631731be22511067bf5b5197e24359ce471184a
    f636851dc4ea34e0defae4d54aeb42af8d48d473aced48c4fc6a757db762bc00
    5fb46dabf5d4e418eaba2b0ccaa8fdf138c4af8502b6b1ba37aef1f97035da90
    047af1acd89d8d58a60f1894a7bd80184d6954b0407e2f3443eae83ad177945c
    ...
    INFO:__main__:fetching feed: 2023-05-01T00:01:00
    ...
    INFO:__main__:fetching feed: 2023-05-01T00:02:00
    ...

dependencies:

    virustotal3==1.0.8

selected mime types from one hour of VT data:

  31798 PE32 executable for MS Windows (GUI) Intel 80386 32-bit
   4749 PE32 executable for MS Windows (DLL) (GUI) Intel 80386 32-bit
   3319 PE32 executable for MS Windows (console) Intel 80386 32-bit
   2125 PE32+ executable for MS Windows (GUI) Mono/.Net assembly
   1346 ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, stripped
   1128 MS-DOS executable, MZ for MS-DOS
   1124 PE32+ executable for MS Windows (console) Mono/.Net assembly
   1000 PE32+ executable for MS Windows (DLL) (GUI) Mono/.Net assembly
    943 PE32+ executable for MS Windows (console)
    901 PE32 executable for MS Windows (DLL) (console) Intel 80386 32-bit
    874 PE32 executable for MS Windows (GUI) Intel 80386 32-bit Mono/.Net assembly
    649 PE32+ executable for MS Windows (DLL) (GUI)
    604 PE32+ executable for MS Windows (DLL) (console)
    528 PE32+ executable for MS Windows (DLL) (console) Mono/.Net assembly
    451 PE32 executable for MS Windows (GUI) Intel 80386 Mono/.Net assembly
    406 PE32 executable for MS Windows (DLL) (console) Intel 80386 32-bit Mono/.Net assembly
    300 PE32+ executable for MS Windows (GUI)
    285 ELF 64-bit LSB shared object, version 1 (SYSV), dynamically linked, stripped
    280 PE32 executable for MS Windows (DLL) (console) Intel 80386 Mono/.Net assembly
    271 ELF 32-bit LSB shared object, ARM, version 1 (SYSV), dynamically linked, stripped
    233 PE32 executable for MS Windows (console) Intel 80386 32-bit Mono/.Net assembly
    199 Mach-O 64-bit dynamically linked shared library
    191 ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, stripped
    143 PE32 executable for MS Windows (console) Intel 80386 Mono/.Net assembly
    115 MS-DOS executable
    104 COM executable for DOS
     96 PE32 executable for MS Windows (unknown subsystem) unknown processor 32-bit
     83 ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, stripped
     76 Mach-O 64-bit bundle
     66 PE32 executable for MS Windows (native) Intel 80386 32-bit
     66 Mach-O fat file with 2 architectures
     61 PE32+ executable for MS Windows (native) Mono/.Net assembly
     61 Mach-O 64-bit executable
     50 Mach-O 64-bit filetype=10
     38 PE32 executable for MS Windows (DLL) Intel 80386 32-bit
     35 ELF 32-bit LSB shared object, ARM, version 1 (SYSV), dynamically linked (uses shared libs), stripped
"""

import io
import os
import bz2
import sys
import json
import shelve
import hashlib
import logging
import pathlib
import argparse
import datetime
from typing import Any, List, Iterator

import requests
import virustotal3.errors

logger = logging.getLogger(__name__)


API_KEY = os.environ["VT_API_KEY"]


# TypeAlias. note: using `foo: TypeAlias = bar` is Python 3.10+
CacheIdentifier = str


def get_this_file_hash() -> str:
    hash = hashlib.sha256()
    hash.update(pathlib.Path(__file__).read_bytes())
    return hash.hexdigest()


def compute_cache_identifier(*keys: bytes) -> CacheIdentifier:
    hash = hashlib.sha256()

    # so that if we change this file the cache is invalidated.
    hash.update(get_this_file_hash().encode("ascii"))
    hash.update(b"\x00")

    for key in keys:
        hash.update(key)
        hash.update(b"\x00")

    return hash.hexdigest()


def get_default_cache_directory(app="floss") -> str:
    # ref: https://github.com/mandiant/capa/issues/1212#issuecomment-1361259813
    #
    # Linux:   $XDG_CACHE_HOME/floss/
    # Windows: %LOCALAPPDATA%\flare\floss\cache
    # MacOS:   ~/Library/Caches/floss

    # ref: https://stackoverflow.com/a/8220141/87207
    if sys.platform == "linux" or sys.platform == "linux2":
        directory = os.environ.get("XDG_CACHE_HOME", os.path.join(os.environ["HOME"], ".cache", app))
    elif sys.platform == "darwin":
        directory = os.path.join(os.environ["HOME"], "Library", "Caches", app)
    elif sys.platform == "win32":
        directory = os.path.join(os.environ["LOCALAPPDATA"], "flare", "capa", app)
    else:
        raise NotImplementedError(f"unsupported platform: {sys.platform}")

    os.makedirs(directory, exist_ok=True)

    return directory


def format_timestamp(dt: datetime.datetime) -> str:
    return f"{dt.year}{dt.month:02}{dt.day:02}{dt.hour:02}{dt.minute:02}"


VirusTotalApiError = virustotal3.errors.VirusTotalApiError


def _raise_exception(response):
    """Raise Exception

    Function to raise an exception using the error messages returned by the API.

    Parameters:
        response (dict) Reponse containing the error returned by the API.

    vendored from: https://github.com/traceflow/virustotal3/blob/58dcfab/virustotal3/enterprise.py
    """
    # https://developers.virustotal.com/v3.0/reference#errors
    raise VirusTotalApiError(response.text)


def _get_feed(api_key, type_, time, timeout=None):
    """Get a minute from a feed

    Parameters:
        api_key (str): VT key
        type_ (str): type of feed to get
        time (str): YYYYMMDDhhmm
        timeout (float, optional): The amount of time in seconds the request should wait before timing out.

    Returns:
        BytesIO: each line is a json string for one report

    vendored from: https://github.com/traceflow/virustotal3/blob/58dcfab/virustotal3/enterprise.py
    """
    if api_key is None:
        raise Exception("You must provide a valid API key")

    response = requests.get(
        "https://www.virustotal.com/api/v3/feeds/{}/{}".format(type_, time),
        headers={"x-apikey": api_key, "Content-Type": "application/json"},
        timeout=timeout,
    )

    if response.status_code != 200:
        _raise_exception(response)

    return io.BytesIO(bz2.decompress(response.content))


def file_feed(api_key, time, timeout=None):
    """Get a file feed batch for a given date, by the minute.

    From the official documentation:
    "Time 201912010802 will return the batch corresponding to December 1st, 2019 08:02 UTC.
    You can download batches up to 7 days old, and the most recent batch has always a 60 minutes
    lag with respect with to the current time."

    Parameters:
        api_key (str): VirusTotal key
        time (str): YYYYMMDDhhmm
        timeout (float, optional): The amount of time in seconds the request should wait before timing out.

    Returns:
        BytesIO: each line is a json string for one report

    vendored from: https://github.com/traceflow/virustotal3/blob/58dcfab/virustotal3/enterprise.py
    """
    return _get_feed(api_key, "files", time, timeout=timeout)


def fetch_feed(api_key: str, ts: datetime.datetime) -> Iterator[Any]:
    feed = file_feed(api_key, format_timestamp(ts)).read().decode("utf-8")
    for line in feed.split("\n"):
        if not line:
            continue
        yield json.loads(line)


def fetch_feed_hashes(api_key: str, ts: datetime.datetime) -> List[str]:
    ts_key = format_timestamp(ts)

    dir = pathlib.Path(get_default_cache_directory())
    name = compute_cache_identifier() + ".db"

    p = dir / name

    with shelve.open(str(p)) as db:
        if ts_key not in db:
            try:
                hashes = []
                for line in fetch_feed(API_KEY, ts):
                    try:
                        if line.get("type") != "file":
                            continue

                        if "magic" not in line.get("attributes", {}) or "sha256" not in line.get("attributes", {}):
                            continue

                        magic = line["attributes"]["magic"]
                        if any(
                            map(lambda prefix: magic.startswith(prefix), ["PE32", "ELF", "MS-DOS", "Mach-O", "COM"])
                        ):
                            hashes.append(line["attributes"]["sha256"])
                    except Exception as e:
                        logger.warning("error: %s", str(e), exc_info=True)
                        continue

                db[ts_key] = hashes
            except Exception as e:
                logger.warning("error: %s", str(e), exc_info=True)
                return []

        return db[ts_key]


def main():
    parser = argparse.ArgumentParser(
        description="fetch the hashes of PE files from the VT feed for the given time range."
    )
    parser.add_argument("start", help="timestamp to start, YYYYMMDDhhmm")
    parser.add_argument("end", help="timestamp to start, YYYYMMDDhhmm")

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

    start = datetime.datetime.strptime(args.start, "%Y%m%d%H%M")
    end = datetime.datetime.strptime(args.end, "%Y%m%d%H%M")

    logger.info("fetching feed: %s - %s", start.isoformat(), end.isoformat())

    current = start
    while format_timestamp(current) < format_timestamp(end):
        logger.info("fetching feed: %s", current.isoformat())
        for hash in fetch_feed_hashes(API_KEY, current):
            print(hash)

        current += datetime.timedelta(minutes=1)

    return 0


if __name__ == "__main__":
    sys.exit(main())

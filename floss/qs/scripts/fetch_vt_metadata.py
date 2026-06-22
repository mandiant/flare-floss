"""
Fetch VT file metadata for a list of SHA256 hashes and cache to disk.

For each SHA256 in the input file, queries the VT API and saves a small
JSON with the fields needed for cluster selection (vhash, imphash, tlsh, etc.).
Already-fetched hashes are skipped, so the script is fully resumable.

Usage:
    VT_API_KEY=... python fetch_vt_metadata.py hashes.txt ./metadata/

Output layout:
    ./metadata/{sha256[:2]}/{sha256}.json

Dependencies:
    requests (already used by fetch_vt_hashes.py)

Example output JSON:
    {
      "sha256": "d55f983c...",
      "vhash": "095056655d15656az47!z",
      "imphash": "59349b16...",
      "rich_pe_header_hash": "60c050aa...",
      "ssdeep": "24576:vMz7...",
      "tlsh": "T1D915BF...",
      "magic": "PE32 executable (GUI) Intel 80386, for MS Windows"
    }
"""

import os
import sys
import json
import time
import logging
import pathlib
import argparse
from typing import Iterator, Optional

import requests

logger = logging.getLogger(__name__)

VT_FILES_URL = "https://www.virustotal.com/api/v3/files/{sha256}"


def iter_hashes(path: pathlib.Path) -> Iterator[str]:
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
            yield line.lower()


def metadata_path(outdir: pathlib.Path, sha256: str) -> pathlib.Path:
    return outdir / sha256[:2] / f"{sha256}.json"


def fetch_metadata(session: requests.Session, sha256: str, api_key: str) -> Optional[dict]:
    url = VT_FILES_URL.format(sha256=sha256)
    try:
        resp = session.get(url, headers={"x-apikey": api_key}, timeout=30)
    except requests.RequestException as e:
        logger.warning("request failed for %s: %s", sha256, e)
        return None

    if resp.status_code == 404:
        logger.debug("not found: %s", sha256)
        return None

    if resp.status_code == 429:
        logger.warning("rate limited, sleeping 60s")
        time.sleep(60)
        return fetch_metadata(session, sha256, api_key)

    if resp.status_code == 401:
        logger.error("invalid API key")
        sys.exit(1)

    if not resp.ok:
        logger.warning("HTTP %d for %s: %s", resp.status_code, sha256, resp.text[:200])
        return None

    try:
        attrs = resp.json()["data"]["attributes"]
    except (KeyError, ValueError) as e:
        logger.warning("unexpected response for %s: %s", sha256, e)
        return None

    pe_info = attrs.get("pe_info") or {}
    return {
        "sha256": sha256,
        "vhash": attrs.get("vhash"),
        "imphash": attrs.get("imphash"),
        "rich_pe_header_hash": pe_info.get("rich_pe_header_hash"),
        "ssdeep": attrs.get("ssdeep"),
        "tlsh": attrs.get("tlsh"),
        "magic": attrs.get("magic"),
    }


def main():
    parser = argparse.ArgumentParser(description="Fetch VT metadata for a list of SHA256 hashes.")
    parser.add_argument("hashes", type=pathlib.Path, help="file with one SHA256 per line")
    parser.add_argument("outdir", type=pathlib.Path, help="directory to store metadata JSONs")
    parser.add_argument("--rate-limit", type=float, default=4.0, help="max requests per second (default: 4)")

    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true")
    logging_group.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.root.level)

    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        logger.error("VT_API_KEY environment variable not set")
        return 1

    args.outdir.mkdir(parents=True, exist_ok=True)

    min_interval = 1.0 / args.rate_limit
    hashes = list(iter_hashes(args.hashes))
    logger.info("loaded %d hashes from %s", len(hashes), args.hashes)

    nfetched = 0
    nskipped = 0
    nfailed = 0
    failed_path = args.outdir / "failed.txt"

    with requests.Session() as session:
        for i, sha256 in enumerate(hashes):
            out = metadata_path(args.outdir, sha256)
            if out.exists():
                nskipped += 1
                continue

            t0 = time.monotonic()
            data = fetch_metadata(session, sha256, api_key)
            elapsed = time.monotonic() - t0

            if data is None:
                nfailed += 1
                with open(failed_path, "a") as f:
                    f.write(sha256 + "\n")
            else:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(data, indent=2), encoding="utf-8")
                nfetched += 1

            if (i + 1) % 1000 == 0:
                logger.info("progress: %d/%d (fetched=%d skipped=%d failed=%d)",
                            i + 1, len(hashes), nfetched, nskipped, nfailed)

            sleep = max(0.0, min_interval - elapsed)
            if sleep:
                time.sleep(sleep)

    logger.info("done: fetched=%d skipped=%d failed=%d", nfetched, nskipped, nfailed)
    if nfailed:
        logger.info("failed hashes written to %s", failed_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

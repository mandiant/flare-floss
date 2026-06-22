"""
Download PE files from VirusTotal by SHA256 hash.

Reads SHA256 hashes from an input file (one per line), downloads each file
from VT, verifies the SHA256 after download, and skips already-downloaded files.
Failed downloads are logged to failed_downloads.txt in the output directory.

Usage:
    VT_API_KEY=... python download_vt_samples.py representatives.txt ./samples/

Output layout:
    ./samples/{sha256[:2]}/{sha256}.bin

Dependencies:
    requests (already used by fetch_vt_hashes.py)
"""

import os
import sys
import time
import hashlib
import logging
import pathlib
import argparse
from typing import Iterator

import requests

logger = logging.getLogger(__name__)

VT_DOWNLOAD_URL = "https://www.virustotal.com/api/v3/files/{sha256}/download"


def iter_hashes(path: pathlib.Path) -> Iterator[str]:
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
            yield line.lower()


def sample_path(outdir: pathlib.Path, sha256: str) -> pathlib.Path:
    return outdir / sha256[:2] / f"{sha256}.bin"


def download_file(session: requests.Session, sha256: str, api_key: str, outdir: pathlib.Path) -> bool:
    out = sample_path(outdir, sha256)
    if out.exists():
        return True

    url = VT_DOWNLOAD_URL.format(sha256=sha256)
    try:
        resp = session.get(url, headers={"x-apikey": api_key}, stream=True, timeout=120)
    except requests.RequestException as e:
        logger.warning("request failed for %s: %s", sha256, e)
        return False

    if resp.status_code == 404:
        logger.debug("not found: %s", sha256)
        return False

    if resp.status_code == 429:
        logger.warning("rate limited, sleeping 60s")
        time.sleep(60)
        return download_file(session, sha256, api_key, outdir)

    if resp.status_code == 401:
        logger.error("invalid API key or insufficient permissions (file download requires premium)")
        sys.exit(1)

    if not resp.ok:
        logger.warning("HTTP %d for %s", resp.status_code, sha256)
        return False

    tmp = out.with_suffix(".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    try:
        with open(tmp, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
                hasher.update(chunk)
    except Exception as e:
        logger.warning("write failed for %s: %s", sha256, e)
        tmp.unlink(missing_ok=True)
        return False

    actual = hasher.hexdigest()
    if actual != sha256:
        logger.warning("SHA256 mismatch for %s: got %s", sha256, actual)
        tmp.unlink(missing_ok=True)
        return False

    tmp.rename(out)
    return True


def main():
    parser = argparse.ArgumentParser(description="Download PE files from VirusTotal by SHA256.")
    parser.add_argument("hashes", type=pathlib.Path, help="file with one SHA256 per line")
    parser.add_argument("outdir", type=pathlib.Path, help="directory to store downloaded binaries")
    parser.add_argument("--rate-limit", type=float, default=2.0, help="max downloads per second (default: 2)")

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
    failed_path = args.outdir / "failed_downloads.txt"

    min_interval = 1.0 / args.rate_limit
    hashes = list(iter_hashes(args.hashes))
    logger.info("loaded %d hashes from %s", len(hashes), args.hashes)

    ndownloaded = 0
    nskipped = 0
    nfailed = 0

    with requests.Session() as session:
        for i, sha256 in enumerate(hashes):
            if sample_path(args.outdir, sha256).exists():
                nskipped += 1
                continue

            t0 = time.monotonic()
            ok = download_file(session, sha256, api_key, args.outdir)
            elapsed = time.monotonic() - t0

            if ok:
                ndownloaded += 1
                logger.info("downloaded %s", sha256)
            else:
                nfailed += 1
                with open(failed_path, "a") as f:
                    f.write(sha256 + "\n")

            if (i + 1) % 100 == 0:
                logger.info("progress: %d/%d (downloaded=%d skipped=%d failed=%d)",
                            i + 1, len(hashes), ndownloaded, nskipped, nfailed)

            sleep = max(0.0, min_interval - elapsed)
            if sleep:
                time.sleep(sleep)

    logger.info("done: downloaded=%d skipped=%d failed=%d", ndownloaded, nskipped, nfailed)
    if nfailed:
        logger.info("failed hashes written to %s", failed_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

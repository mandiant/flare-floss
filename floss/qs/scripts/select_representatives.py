"""
Group files by Vhash and select representative SHA256s for download.

Reads all cached metadata JSONs (from fetch_vt_metadata.py) and groups them
by Vhash, selecting at most --max-per-cluster representatives per group.
Files with no Vhash fall back to imphash grouping, then to singletons.

Writes:
  - representatives.txt    one SHA256 per line, to feed into download_vt_samples.py
  - cluster_assignments.json   full cluster map for debugging/analysis

Usage:
    python select_representatives.py ./metadata/ ./

    # select more representatives per cluster for better coverage:
    python select_representatives.py ./metadata/ ./ --max-per-cluster 5
"""

import sys
import json
import logging
import pathlib
import argparse
from typing import Dict, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


def read_metadata(metadata_dir: pathlib.Path) -> List[dict]:
    records = []
    for p in metadata_dir.rglob("*.json"):
        if p.name in ("failed.txt",):
            continue
        try:
            records.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception as e:
            logger.warning("failed to read %s: %s", p, e)
    return records


def select_representatives(
    records: List[dict],
    max_per_cluster: int,
) -> tuple[List[str], dict]:
    """
    Group by vhash first, then imphash for files without vhash, then singletons.
    Returns (representative_sha256s, cluster_assignments_dict).
    """
    # cluster_key -> list of sha256s in that cluster
    clusters: Dict[str, List[str]] = defaultdict(list)
    singletons: List[str] = []

    for rec in records:
        sha256 = rec.get("sha256")
        if not sha256:
            continue

        vhash = rec.get("vhash")
        imphash = rec.get("imphash")

        if vhash:
            clusters[f"vhash:{vhash}"].append(sha256)
        elif imphash:
            clusters[f"imphash:{imphash}"].append(sha256)
        else:
            singletons.append(sha256)

    representatives: List[str] = []
    cluster_assignments: Dict[str, list] = {}

    for cluster_key, sha256s in clusters.items():
        reps = sha256s[:max_per_cluster]
        representatives.extend(reps)
        cluster_assignments[cluster_key] = {
            "size": len(sha256s),
            "representatives": reps,
            "all": sha256s,
        }

    representatives.extend(singletons)

    stats = {
        "total_input": len(records),
        "total_clusters": len(clusters),
        "singleton_count": len(singletons),
        "total_representatives": len(representatives),
        "largest_clusters": sorted(
            [{"key": k, "size": v["size"]} for k, v in cluster_assignments.items()],
            key=lambda x: x["size"],
            reverse=True,
        )[:20],
    }

    return representatives, {"stats": stats, "clusters": cluster_assignments}


def main():
    parser = argparse.ArgumentParser(
        description="Select representative SHA256s from VT metadata clusters."
    )
    parser.add_argument("metadata_dir", type=pathlib.Path, help="directory of metadata JSONs")
    parser.add_argument("outdir", type=pathlib.Path, help="directory to write output files")
    parser.add_argument(
        "--max-per-cluster",
        type=int,
        default=3,
        help="maximum representatives to select per Vhash/imphash cluster (default: 3)",
    )

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

    args.outdir.mkdir(parents=True, exist_ok=True)

    logger.info("reading metadata from %s", args.metadata_dir)
    records = read_metadata(args.metadata_dir)
    logger.info("loaded %d metadata records", len(records))

    representatives, assignments = select_representatives(records, args.max_per_cluster)

    stats = assignments["stats"]
    logger.info(
        "clusters: %d total, %d singletons, %d representatives (from %d inputs)",
        stats["total_clusters"],
        stats["singleton_count"],
        stats["total_representatives"],
        stats["total_input"],
    )
    logger.info("largest clusters:")
    for entry in stats["largest_clusters"][:10]:
        logger.info("  %s: %d files", entry["key"], entry["size"])

    reps_path = args.outdir / "representatives.txt"
    reps_path.write_text("\n".join(representatives) + "\n", encoding="utf-8")
    logger.info("wrote %d representatives to %s", len(representatives), reps_path)

    assignments_path = args.outdir / "cluster_assignments.json"
    assignments_path.write_text(json.dumps(assignments, indent=2), encoding="utf-8")
    logger.info("wrote cluster assignments to %s", assignments_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())

import sys
import logging
import pathlib
import argparse
import subprocess

import floss.main
import floss.qs.main

logger = logging.getLogger("floss.qs.bulk")


def main():
    parser = argparse.ArgumentParser(description="Bulk analyze a directory of binaries with floss-qs.")
    parser.add_argument("input_directory", type=pathlib.Path, help="Directory containing binaries to analyze.")
    parser.add_argument("output_directory", type=pathlib.Path, help="Directory to write JSON results to.")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=floss.qs.main.MIN_STR_LEN,
        help="Minimum string length.",
    )
    parser.add_argument(
        "--save-rendered",
        action="store_true",
        help="Save the rendered output to a .txt file in the output directory.",
    )

    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="Enable debugging output on STDERR.")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="Disable all status output except fatal errors."
    )
    args = parser.parse_args()

    floss.main.set_log_config(args.debug, args.quiet)

    if not args.input_directory.is_dir():
        logger.error("Input path %s is not a directory.", args.input_directory)
        return 1

    args.output_directory.mkdir(parents=True, exist_ok=True)

    for file_path in args.input_directory.iterdir():
        if not file_path.is_file():
            continue

        logger.info("Analyzing file: %s", file_path)
        json_output_path = args.output_directory / f"{file_path.name}.json"

        cmd = [
            sys.executable,
            "-m",
            "floss.qs.main",
            str(file_path),
            "--json-out",
            str(json_output_path),
            "-n",
            str(args.min_length),
        ]
        if args.quiet:
            cmd.append("--quiet")
        if args.debug:
            cmd.append("--debug")

        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, encoding="utf-8")
            logger.info("Wrote     JSON output to %s", json_output_path)
            if result.returncode != 0:
                logger.error("Failed to analyze file %s, exited with code %d", file_path, result.returncode)
                if result.stdout:
                    logger.error("stdout:\n%s", result.stdout)
                if result.stderr:
                    logger.error("stderr:\n%s", result.stderr)
            else:
                # success
                if args.save_rendered:
                    rendered_output_path = args.output_directory / f"{file_path.name}.txt"
                    with rendered_output_path.open("w", encoding="utf-8") as f:
                        f.write(result.stdout)
                    logger.info("Wrote rendered output to %s", rendered_output_path)

        except Exception as e:
            logger.error("Failed to run subprocess for file %s: %s", file_path, e, exc_info=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())

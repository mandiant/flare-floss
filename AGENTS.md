# AGENTS.md

- FLOSS (FLARE Obfuscated String Solver) is a static analysis tool that automatically extracts and deobfuscates strings from malware binaries. It extends traditional string-extraction utilities (e.g., `strings.exe`) by using emulation-based techniques to recover strings that are never present in plaintext on disk.
- To set up the development environment, make sure that a venv is created and the pre-commit and pre-push hooks are installed.
- All lints, formatters and tests **must** pass before making a PR. Enforce this strictly.
- The `floss/` folder has the main functionality, while `scripts/` has auxiliary plugins and scripts. Docs are in `doc/`.

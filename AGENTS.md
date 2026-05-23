# AGENTS.md

## Project Overview

FLOSS (FLARE Obfuscated String Solver) is a static analysis tool that automatically extracts and deobfuscates strings from malware binaries. It extends traditional string-extraction utilities (e.g., `strings.exe`) by using emulation-based techniques to recover strings that are never present in plaintext on disk.

Maintained by Google/Mandiant FLARE team. Licensed under Apache 2.0.

### String Categories

| Type | Description |
|------|-------------|
| **Static** | Regular ASCII / UTF-16LE strings found directly in the binary |
| **Stack** | Strings constructed byte-by-byte on the stack at runtime |
| **Tight** | Stack strings built inside tight loops, refined further |
| **Decoded** | Strings recovered by emulating decoding/decryption routines |
| **Language-specific** | Go and Rust runtime strings extracted from metadata (no emulation required) |

## Theory & Algorithm

FLOSS performs static analysis combined with selective emulation. The pipeline is:

1. **Workspace loading**: vivisect parses the binary, identifies functions, basic blocks, and cross-references.
2. **Static string extraction**: regex scans for ASCII (≥4 chars) and UTF-16LE sequences via `binary2strings`.
3. **Feature extraction** (`floss/identify.py`, `floss/features/`): each function is scored on instruction features: MOV counts, XOR (non-zeroing), shifts/rotates, tight loops, call counts. This produces a ranked list of decoder candidates.
4. **Stack string extraction** (`floss/stackstrings.py`): emulates functions with ≥5 MOV-to-stack instructions; monitors stack memory as strings are assembled. A context monitor captures strings passed to callees.
5. **Tight string extraction** (`floss/tightstrings.py`): specialized emulation for tight single-block loops (≤`TS_MAX_INSN_COUNT`=10 000 instructions).
6. **Decoded string extraction** (`floss/string_decoder.py`): emulates top-ranked decoder functions; takes memory snapshots before and after; diffs them with a binary-search algorithm (`memdiff_search`) to find newly appeared strings.
7. **Language-specific extraction** (`floss/language/`): detects Go via `pclntab` and Rust via `.rodata` patterns; parses runtime string tables directly without emulation.
8. **Rendering** (`floss/render/`): outputs formatted tables (Rich), JSON, or script stubs for IDA/Ghidra/Binary Ninja/Radare2/x64dbg.

## Development Setup

**Python requirement:** >= 3.10

```
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

# Install with dev dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install --hook-type pre-commit --hook-type pre-push
```

## Running Tests

**All of the following must pass before pushing.**

### Pre-commit hooks (isort, black, mypy)

Make sure this is configured to run before **every single commit**

```
pre-commit run --all-files
```

Pre-commit is configured in `.pre-commit-config.yaml` and runs on `pre-commit` and `pre-push` stages. It enforces:
- `isort`: import sorting (profile: black, length-sort)
- `black`: formatting (line length 120)
- `mypy`: type checking (`--check-untyped-defs`)

Unit and integration tests:

```
pytest tests/
```

Type checking:

```
mypy floss/
```

> CI runs tests on Ubuntu 22.04, Windows 2022, and macOS 14 across Python 3.10, 3.11, and 3.12. Test locally on your platform before pushing, and ensure the full matrix passes in CI before merging.

## Coding Conventions

### Style

- **Black** with line length 120. Do not exceed this limit.
- **isort** with `profile = black` and `length_sort = true`.
- **Type hints are required** on all functions. mypy enforces this with `--check-untyped-defs`.
- Use `floss.logging_.getLogger(__name__)`: not `logging.getLogger`.
- Data structures use **Pydantic** dataclasses (not stdlib `dataclasses`).
- Categorical values use `enum.Enum` (see `StringType`, `Language`, `StringEncoding` in `results.py`).
- Copyright headers: `Copyright (C) <YEAR> Mandiant, Inc. All Rights Reserved.`

### Comments

Default to **no comments**. Add one when the WHY is non-obvious: a hidden constraint, a subtle invariant, a workaround for a specific bug, or behavior that would surprise a reader. Never explain WHAT the code does: well-named identifiers do that.

## Core Priorities

**Performance first. Reliability first.**

Keep behavior predictable under load and during failures (session restarts, reconnects, partial streams).

If a tradeoff is required, choose correctness and robustness over short-term convenience.

This applies concretely to emulation code: emulation limits (`const.py`) exist to bound resource usage: do not remove or raise them without a measured justification. API hooks (`api_hooks.py`) exist to prevent emulation from stalling on OS calls: extend them rather than bypassing them.

## Maintainability

Long-term maintainability is a core priority. If you add new functionality, first check if there is shared logic that can be extracted to a separate module. Duplicate logic across multiple files is a code smell and should be avoided. Don't be afraid to change existing code. Don't take shortcuts by just adding local logic to solve a problem.

Concretely:
- Shared emulator setup lives in `floss/utils.py`: add helpers there, not inline.
- Feature extraction logic belongs in `floss/features/`, not scattered across analysis modules.
- New string types should follow the existing pattern: a dedicated module (`stackstrings.py`, `tightstrings.py`), a Pydantic result class in `results.py`, and renderer support in `floss/render/`.
- If a new analysis phase needs constants (instruction counts, thresholds), add them to `floss/const.py`.


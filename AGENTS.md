# AGENTS.md

- To set up the development environment, make sure that a venv is created and the pre-commit and pre-push hooks are installed, see `.pre-commit-config.yaml`
- All lints, formatters and tests in `.github/workflows` **must** pass before making a PR. Enforce this strictly.
- The `floss/` folder has the main functionality, while `scripts/` has auxiliary plugins and scripts. Docs are in `doc/`.

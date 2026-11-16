# AGENTS.md

This repository is a a python package that allows to query BitWarden and VaultWarden
instances for credentials.

## Ground rules

- When something is ambiguous: if you can ask, ask. If you cannot, pick the option
  that is the most reliable, and record it in `PROGRESS.md` under "Decisions" so
  it can be reviewed.
- Never stage or commit `PROGRESS.md` in Git
- Project should be buildable and ready to be used in pypi. Do not automate this and
  never upload, run only needed checks to make sure that `hatch` will succeed.

## Dependencies

- Never introduce any external dependencies. 
- Rely only on what is already installed.
- If there's an exceptional need in new dependency - ask first.
- Use backwards-comaptible syntax to cover all python version from 3.8 to 3.15. The
  package `ruff` is already installed as dev-dependency and is configured to use the
  `target-version = "py38"`. Call it accordingly to check maximum compatibility.

## Testing

- Before committing always run unit tests, ruff, lint and flake8. Neither should report
  any errors.

## Notes

- There was a significant response schema change in VaultWarden 1.3.7. Hence there's
  a test for both cases - new and old schemas. Keep it as is.

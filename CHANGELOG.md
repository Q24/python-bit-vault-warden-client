# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-11-16

### Added

- `WardenCacheMode.LOCALONLY`: the remote is never queried, the cache is used even when expired (with a warning).
  Raises `RuntimeError` when there is no cache.
- Support for individually encrypted items (per-item cipher keys), used by current Bitwarden and
  VaultWarden 2026.10 clients. Previously any such item made every lookup fail with "MAC did not match".
- Support for RSA-OAEP organization key encryption types 3, 5 and 6, in addition to 4.
- `WardenConfiguration.timeout` option (default 30 seconds) for every request to the remote.
- `WardenClient` can be used as a context manager and has a `close()` method.
- `UnsupportedEncryptionError` (subclass of `NotImplementedError`), raised for unsupported KDF or encryption types.
- Integration tests against a real VaultWarden 2026.10 vault, unit and end-to-end tests with real cryptography
  for both the legacy and the 1.37+ response schemas.
- Python version limitations documented in the README.

### Changed

- `cryptography` is now required in version 50.0.2 or newer on Python 3.9.2+. Python 3.8 – 3.9.1 stay on older
  releases, which are still affected by the vulnerabilities listed under [Security](#security).
- A rejected login now raises `CredentialsError("Login failed: ...")` instead of `KeyError: 'Key'`;
  other HTTP errors raise `requests.HTTPError`.
- `FALLBACK` mode (and `AGGRESSIVE` with an expired cache) falls back to the cache on connection errors, timeouts
  and HTTP 5xx responses. When there is no cache, the original error is raised instead of `FileNotFoundError`.
- Items that can't be decrypted are skipped with a warning instead of failing every lookup.
  Only item names are decrypted while searching; only the matching item is fully decrypted.
- Cache state is evaluated on every call, so a long-lived client uses a freshly written cache and refreshes
  an expired one.
- The client logs through the `bit_vault_warden_client.client` logger instead of the root logger.
- The cache file is written atomically and is readable by its owner only (`0600`).
- `cache_filename` pointing outside the system temporary directory (e.g. `foo/../../x`) or empty is rejected.
- The derived master key is reused, so a remote fetch runs the key derivation once instead of twice.
- The user supplied `auth_data` is no longer modified by a remote fetch.
- The project is checked with `ruff` (`py38` target) in addition to `pylint` and `flake8`.

### Fixed

- Passwords and notes containing `"`, `\`, new lines or non-ASCII characters were returned escaped or corrupted.
  Values are now returned exactly as stored.
- E-mail addresses with upper-case letters or surrounding spaces could not log in: the KDF salt now uses the
  trimmed lower-cased e-mail, like the official clients.
- Secure notes (items with no login) crashed the result parsing in the 1.37+ schema.
- `__version__` reported `1.0.0` in release 1.1.0.
- The `LICENSE` file was not included in the built packages.

### Removed

- Internal `bcrypt.decrypt_bitwarden_data` and `bcrypt.get_json_escaped_string` helpers (not part of the
  public API).
- `assert` statements used for input validation, replaced with explicit exceptions.

### Security

- `cryptography` bumped to 50.0.2: fixes CVE-2026-69247, CVE-2026-69248, CVE-2026-69249 and the vulnerable
  bundled OpenSSL (GHSA-537c-gmf6-5ccf). Not available on Python older than 3.9.2.
- MAC verification is now constant-time.
- Passwords and keys are hidden from `repr()` of `Result`, `WardenConfiguration`, `WardenAuthData` and the
  internal secrets, so they don't leak into logs and tracebacks.

## [1.1.0] - 2026-07-28

### Fixed

- Compatibility with VaultWarden 1.37.0, which moved item fields out of `data` into top-level `name`, `notes`
  and a nested `login` object ([#1](https://github.com/Q24/python-bit-vault-warden-client/issues/1)).
  Both schemas are supported.

### Changed

- Dependencies are managed with `uv` (`uv.lock`, dev dependency group in `pyproject.toml`),
  `requirements.txt` and `requirements-dev.txt` are generated from it.

## [1.0.0] - 2025-03-05

### Added

- First release: fetch an item's username, password, TOTP and notes from Bitwarden or VaultWarden by item name.
- PBKDF2-SHA256 key derivation, AES-256 (type 2) vault data, organization items.
- Local encrypted cache with `AGGRESSIVE` and `FALLBACK` modes and configurable TTL and file name.
- HTTP and SOCKS proxies, custom CA file and option to disable TLS verification.

[1.2.0]: https://github.com/Q24/python-bit-vault-warden-client/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Q24/python-bit-vault-warden-client/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Q24/python-bit-vault-warden-client/releases/tag/v1.0.0

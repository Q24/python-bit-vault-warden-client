# Python Bitwarden/Vaultwarden client

Python http client to fetch data from Bitwarden or Vaultwarden.

### Current limitations

- Supports only PBKDF2-SHA256 key derivation (KDF type: 0), Argon2id is not supported
- Supports only AES-256 encryption (type: 2) for vault data and RSA-OAEP (types: 3-6) for organization keys
- Supports only fetching data, totally not a CRUD API
- Two-factor authentication is not supported

# Installation

```
pip install bit-vault-warden-client
```

### Supported Python versions

The client works on Python 3.8 and newer, but only **Python 3.9.2+** gets a `cryptography` release
without known vulnerabilities:

| Python            | `cryptography` installed       | Status                                                                                  |
|-------------------|--------------------------------|-----------------------------------------------------------------------------------------|
| 3.9.2 and newer   | 50.0.2 or newer (enforced)     | Recommended. Fixes CVE-2026-69247, CVE-2026-69248, CVE-2026-69249, GHSA-537c-gmf6-5ccf  |
| 3.8 – 3.9.1       | older release (47.0.0 on 3.8)  | Works, **at your own risk**: still affected by the CVEs above, no fixed release exists  |

`cryptography` 50.x dropped support for Python older than 3.9.2, so on those versions the newest available
release is installed and the vulnerabilities stay unpatched. Most of them are in features this client does not
use (PKCS#7, X.509 verification), but the bundled OpenSSL one does apply. Upgrade to a supported Python version
to be safe.

# Usage

```python
from bit_vault_warden_client import (
    WardenConfiguration, WardenAuthData,
    WardenClient, WardenCacheMode
)

# Define authentication data
auth_data = WardenAuthData(
    scope='api offline_access',
    client_id='web',
    grant_type='password',
    deviceType=9,
    deviceName='Bitwarden-Web-API'
)

# Create Warden client configuration
config = WardenConfiguration(
    url='https://bitwarden.domain.tld',
    username='username@domain.tld',
    password='verysecure',
    auth_data=auth_data,
    cache_mode=WardenCacheMode.FALLBACK,
)

# Instantiate client and fetch data
with WardenClient(config) as client:
    result = client.fetch_credentials('credentials item name')

username, password, totp = result
notes = result.notes
```

- Item name lookup is case-insensitive, items in trash are ignored
- Personal, organization and individually encrypted (cipher key) items are supported
- `CredentialsNotFoundError` is raised when there is no item with such name
- `CredentialsError` is raised when credentials are wrong or login is rejected
- `UnsupportedEncryptionError` is raised for unsupported KDF or encryption types

# WardenConfiguration options

```
cache_ttl=int
```
- Cache expiration timer in seconds

---

```
cache_mode=WardenCacheMode.FALLBACK  
cache_mode=WardenCacheMode.AGGRESSIVE
cache_mode=WardenCacheMode.LOCALONLY
```
- **WardenCacheMode.FALLBACK** for using cache only when remote is not available.<br>In this mode client will always query remote, and will try to use cache if remote is not available (connection error, timeout or 5xx response) and even if cache is expired (in this case it will trigger a warning). 
- **WardenCacheMode.AGGRESSIVE** (default) cache will be used firsthand, and remote will be queried only if cache doesn't exist or is expired
- **WardenCacheMode.LOCALONLY** remote is never queried, cache is used even if it is expired (with a warning). Raises `RuntimeError` if cache doesn't exist

---

```
cache_filename='bitwarden.rpx.cache',
```
- Cache filename, by default it is `bitwarden.cache` and is always placed in system temporary directory
- Must not start with `/`, `\` or `..` and must not point outside of system temporary directory
- Cache contains encrypted vault data and is readable by its owner only

---

```
timeout=30
```
- Timeout in seconds for each request to remote

---

```
http_proxy='socks5h://127.0.0.1:1082',
http_proxy='http://127.0.0.1:1082',
https_proxy='socks5h://127.0.0.1:1082',
https_proxy='https://127.0.0.1:1082',
```
- Proxy configuration, http and socks proxies are supported

---

```
https_verify=True,
```
- Certification authority verification, set `False` to be like `curl --insecure`

---

```
https_cafile='./customCA.crt',
```
- Relative or absolute path to self-signed custom CA file (in PEM format) to verify server against
- Will throw `FileNotFoundError` upon initialization if specified file has not been found

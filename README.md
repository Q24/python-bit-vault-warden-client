# Python Bitwarden/Vaultwarden client

Python http client to fetch data Bitwarden or Vaultwarden.

### Current limitations

- Supports only AES encoding (type: 2)
- Supports only fetching data, totally not a CRUD API

# Installation

```
pip install bit-vault-warden-client
```

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

# Create Warden client configuraion
config = WardenConfiguration(
    url='https://bitwarden.domain.tld',
    username='username@domain.tld',
    password='verysecure',
    auth_data=auth_data,
    cache_mode=WardenCacheMode.FALLBACK,
)

# Instantiate client and fetch data
client = WardenClient(config)
result = client.fetch_credentials('credentials item name')
```

# WardenConfiguration options

```
cache_ttl=int
```
- Cache expiration timer in seconds

---

```
cache_mode=WardenCacheMode.FALLBACK  
cache_mode=WardenCacheMode.AGGRESSIVE
```
- **WardenCacheMode.FALLBACK** for using cache only when remote is not available. In this mode client will try to use cache even if it is expired with logged warning. 
- **WardenCacheMode.AGGRESSIVE** cache will be used firsthand, and remote will be queried only if cache doesn't exist or is expired

---

```
cache_filename='bitwarden.rpx.cache',
```
- Cache filename, by default it is `bitwarden.cache` and is always placed in system temporary directory
- Must not start with `/`, `\` or `..`

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

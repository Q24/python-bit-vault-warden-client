"""
End-to-end client tests: real encryption, only the HTTP transport is faked
"""
# pylint: disable=redefined-outer-name
import json
import os
import stat
import sys
import time
from unittest.mock import MagicMock

import pytest
import requests

from bit_vault_warden_client import (
    CredentialsError, CredentialsNotFoundError, UnsupportedEncryptionError,
    WardenCacheMode, WardenClient, WardenConfiguration
)
from tests.fixtures.vault_builder import VaultBuilder
from tests.fixtures.login_data_builder import LoginDataBuilder

EMAIL = "User@Example.com"
PASSWORD = "master password"
URL = "https://vault.example.com"


class FakeServer:
    """
    Answers pre-login, token and sync requests of the client session with the vault data
    """

    def __init__(self, vault: VaultBuilder, legacy: bool = False):
        self.vault = vault
        self.legacy = legacy
        self.error = None
        self.token_status = 200
        self.token_body = None
        self.sync_status = 200
        self.requests = []

    def install(self, client: WardenClient) -> None:
        client._session.post = self.handle  # pylint: disable=protected-access
        client._session.get = self.handle  # pylint: disable=protected-access

    def handle(self, url, **kwargs):
        self.requests.append((url, kwargs))
        if self.error:
            raise self.error
        if url.endswith("/api/accounts/prelogin"):
            return self.response(200, self.vault.prelogin_response())
        if url.endswith("/identity/connect/token"):
            if kwargs["data"]["password"] != self.vault.master_password_hash:
                return self.response(400, {"error": "invalid_grant", "error_description": "Wrong password"})
            return self.response(self.token_status, self.token_body or self.vault.token_response())
        if url.endswith("/api/sync"):
            return self.response(self.sync_status, self.vault.sync_response(legacy=self.legacy))
        return self.response(404, {})

    @staticmethod
    def response(status: int, body) -> requests.Response:
        response = requests.Response()
        response.status_code = status
        content = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        response._content = content  # pylint: disable=protected-access
        return response

    @property
    def remote_calls(self) -> int:
        return len(self.requests)


@pytest.fixture(autouse=True)
def isolated_tempdir(tmp_path, monkeypatch):
    monkeypatch.setattr("bit_vault_warden_client.models.gettempdir", lambda: str(tmp_path))
    return tmp_path


@pytest.fixture
def vault():
    return (
        VaultBuilder(EMAIL, PASSWORD)
        .add_organization("org-1")
        .add_login("Deleted", username="old", password="old", deleted=True)
        .add_login("Personal", username="me", password='pa"ss\\word ēā 密码', totp="JBSWY3DPEHPK3PXP", notes="n\n2")
        .add_login("Deleted", username="current", password="current")
        .add_login("Organization", username="org-user", password="org-pass", organization_id="org-1")
        .add_login("Cipher key", username="ck-user", password="ck-pass", cipher_key=True)
        .add_login("Org cipher key", username="ock", password="ock-pass", organization_id="org-1", cipher_key=True)
        .add_login("Secure note", notes="only notes", cipher_type=2)
    )


@pytest.fixture(params=[False, True], ids=["schema-1.37", "schema-legacy"])
def server(request, vault):
    return FakeServer(vault, legacy=request.param)


def make_client(server: FakeServer, **kwargs) -> WardenClient:
    params = {
        "url": URL,
        "username": EMAIL,
        "password": PASSWORD,
        "auth_data": LoginDataBuilder().build(),
        "cache_mode": WardenCacheMode.FALLBACK,
    }
    params.update(kwargs)
    client = WardenClient(WardenConfiguration(**params))
    server.install(client)
    return client


@pytest.mark.parametrize("query, expected", [
    ("Personal", ("me", 'pa"ss\\word ēā 密码', "JBSWY3DPEHPK3PXP")),
    ("personal", ("me", 'pa"ss\\word ēā 密码', "JBSWY3DPEHPK3PXP")),
    ("Deleted", ("current", "current", "")),
    ("Organization", ("org-user", "org-pass", "")),
    ("Cipher key", ("ck-user", "ck-pass", "")),
    ("Org cipher key", ("ock", "ock-pass", "")),
    ("Secure note", ("", "", "")),
])
def test_fetch_credentials_from_remote(server, query, expected):
    result = make_client(server).fetch_credentials(query)
    assert result.astuple() == expected


def test_fetch_credentials_notes(server):
    client = make_client(server)
    assert client.fetch_credentials("Personal").notes == "n\n2"
    assert client.fetch_credentials("Secure note").notes == "only notes"


def test_fetch_credentials_not_found(server):
    with pytest.raises(CredentialsNotFoundError, match="'Missing'"):
        make_client(server).fetch_credentials("Missing")


def test_undecryptable_item_is_skipped(server, vault, caplog):
    vault.ciphers.insert(0, dict(vault.ciphers[1], name="2.aW52YWxpZA==|aW52YWxpZA==|aW52YWxpZA==", id="bad"))
    vault.add_login("Broken", password="x", broken=True)
    vault.add_organization("org-removed").add_login("Removed org", password="x", organization_id="org-removed")
    del vault.org_keys["org-removed"]

    client = make_client(server)

    assert client.fetch_credentials("Personal").username == "me"
    for query in ("Broken", "Removed org"):
        with pytest.raises(CredentialsNotFoundError):
            client.fetch_credentials(query)
    assert "Skipping item 'bad'" in caplog.text


def test_wrong_password(server):
    with pytest.raises(CredentialsError, match="Login failed: Wrong password"):
        make_client(server, password="wrong").fetch_credentials("Personal")


def test_login_rejected_without_json_body(server):
    server.token_status = 401
    server.token_body = b"Unauthorized"
    with pytest.raises(CredentialsError, match="Login failed: unknown reason"):
        make_client(server).fetch_credentials("Personal")


def test_unsupported_kdf(server, vault):
    vault.prelogin_response = lambda: {"kdf": 1, "kdfIterations": 3}
    with pytest.raises(UnsupportedEncryptionError, match="KDF"):
        make_client(server).fetch_credentials("Personal")


def test_legacy_pascal_case_prelogin_response(server, vault):
    vault.prelogin_response = lambda: {"Kdf": 0, "KdfIterations": vault.iterations}
    assert make_client(server).fetch_credentials("Personal").username == "me"


def test_requests(server):
    auth_data = LoginDataBuilder().build()
    make_client(server, auth_data=auth_data, timeout=5).fetch_credentials("Personal")

    (prelogin_url, prelogin), (token_url, token), (sync_url, sync) = server.requests
    assert prelogin_url == f"{URL}/api/accounts/prelogin"
    assert prelogin == {"json": {"email": EMAIL}, "timeout": 5}
    assert token_url == f"{URL}/identity/connect/token"
    assert token["data"]["username"] == EMAIL
    assert token["data"]["password"] == server.vault.master_password_hash
    assert token["data"]["scope"] == auth_data.scope
    assert token["timeout"] == 5
    assert sync_url == f"{URL}/api/sync"
    assert sync == {"headers": {"Authorization": "Bearer fake_access_token"}, "timeout": 5}
    # configured auth data is not altered
    assert auth_data.asdict() == LoginDataBuilder().build().asdict()


def test_remote_refreshes_cache(server, isolated_tempdir):
    client = make_client(server)
    client.fetch_credentials("Personal")

    cache_file = isolated_tempdir / "bitwarden.cache"
    with open(cache_file, encoding="utf8") as file:
        cache = json.load(file)
    assert cache == {"KDFITERATIONS": server.vault.iterations, "DATA": server.vault.sync_response(server.legacy)}
    assert [p.name for p in isolated_tempdir.iterdir()] == ["bitwarden.cache"]
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(cache_file).st_mode) == 0o600


def test_cache_write_failure_does_not_fail_fetch(server, isolated_tempdir, caplog):
    (isolated_tempdir / "bitwarden.cache").mkdir()
    assert make_client(server).fetch_credentials("Personal").username == "me"
    assert "Could not save data to cache" in caplog.text
    assert [p.name for p in isolated_tempdir.iterdir()] == ["bitwarden.cache"]


def test_fetch_credentials_from_cache(server):
    make_client(server).fetch_credentials("Personal")
    offline = make_client(server)
    server.error = requests.exceptions.ConnectionError("offline")

    assert offline.fetch_credentials_from_cache("Organization").astuple() == ("org-user", "org-pass", "")
    assert offline.fetch_credentials_from_cache("Org cipher key").astuple() == ("ock", "ock-pass", "")


def test_fetch_credentials_from_cache_missing(server):
    with pytest.raises(FileNotFoundError):
        make_client(server).fetch_credentials_from_cache("Personal")


def expire_cache(client: WardenClient) -> None:
    expired = time.time() - client.config.cache_ttl - 10
    os.utime(client.config.cache_file, (expired, expired))


# Cache modes

def test_aggressive_uses_fresh_cache(server):
    client = make_client(server, cache_mode=WardenCacheMode.AGGRESSIVE)
    client.fetch_credentials("Personal")
    calls = server.remote_calls

    assert client.fetch_credentials("Organization").username == "org-user"
    assert server.remote_calls == calls


def test_aggressive_refreshes_expired_cache(server):
    client = make_client(server, cache_mode=WardenCacheMode.AGGRESSIVE)
    client.fetch_credentials("Personal")
    expire_cache(client)
    calls = server.remote_calls

    client.fetch_credentials("Personal")
    assert server.remote_calls == calls + 3
    assert client.cache_not_expired is True


def test_fallback_always_queries_remote(server):
    client = make_client(server, cache_mode=WardenCacheMode.FALLBACK)
    client.fetch_credentials("Personal")
    client.fetch_credentials("Personal")
    assert server.remote_calls == 6


@pytest.mark.parametrize("error", [
    requests.exceptions.ConnectionError("offline"),
    requests.exceptions.ConnectTimeout("timeout"),
    requests.exceptions.ReadTimeout("timeout"),
])
def test_fallback_uses_cache_when_remote_unavailable(server, error, caplog):
    client = make_client(server, cache_mode=WardenCacheMode.FALLBACK)
    client.fetch_credentials("Personal")
    expire_cache(client)
    server.error = error

    assert client.fetch_credentials("Personal").username == "me"
    assert "Remote not reachable" in caplog.text
    assert "Cache is expired" in caplog.text


def test_fallback_uses_cache_on_server_error(server):
    client = make_client(server, cache_mode=WardenCacheMode.FALLBACK)
    client.fetch_credentials("Personal")
    server.sync_status = 502

    assert client.fetch_credentials("Personal").username == "me"


def test_fallback_does_not_mask_client_error(server):
    client = make_client(server, cache_mode=WardenCacheMode.FALLBACK)
    client.fetch_credentials("Personal")
    server.sync_status = 404

    with pytest.raises(requests.exceptions.HTTPError):
        client.fetch_credentials("Personal")


def test_fallback_without_cache_raises_remote_error(server):
    server.error = requests.exceptions.ConnectionError("offline")
    with pytest.raises(requests.exceptions.ConnectionError):
        make_client(server, cache_mode=WardenCacheMode.FALLBACK).fetch_credentials("Personal")


def test_aggressive_falls_back_to_expired_cache(server):
    client = make_client(server, cache_mode=WardenCacheMode.AGGRESSIVE)
    client.fetch_credentials("Personal")
    expire_cache(client)
    server.error = requests.exceptions.ConnectionError("offline")

    assert client.fetch_credentials("Personal").username == "me"


def test_localonly_never_queries_remote(server):
    make_client(server).fetch_credentials("Personal")
    calls = server.remote_calls
    client = make_client(server, cache_mode=WardenCacheMode.LOCALONLY)
    expire_cache(client)

    assert client.fetch_credentials("Personal").username == "me"
    assert server.remote_calls == calls


def test_localonly_without_cache(server):
    with pytest.raises(RuntimeError, match="Cache file does not exist"):
        make_client(server, cache_mode=WardenCacheMode.LOCALONLY).fetch_credentials("Personal")
    assert server.remote_calls == 0


def test_cache_state_is_not_stale(server):
    client = make_client(server)
    assert (client.cache_exists, client.cache_not_expired) == (False, False)
    client.fetch_credentials("Personal")
    assert (client.cache_exists, client.cache_not_expired) == (True, True)
    expire_cache(client)
    assert (client.cache_exists, client.cache_not_expired) == (True, False)


# Session configuration

def test_session_defaults():
    client = WardenClient(WardenConfiguration(url=URL, username=EMAIL, password=PASSWORD,
                                              auth_data=LoginDataBuilder().build()))
    assert client._session.verify is True  # pylint: disable=protected-access
    assert client._session.proxies == {}  # pylint: disable=protected-access


def test_session_insecure_and_proxies():
    client = WardenClient(WardenConfiguration(
        url=URL, username=EMAIL, password=PASSWORD, auth_data=LoginDataBuilder().build(),
        https_verify=False, http_proxy="http://proxy:1", https_proxy="socks5h://proxy:2",
    ))
    assert client._session.verify is False  # pylint: disable=protected-access
    assert client._session.proxies == {  # pylint: disable=protected-access
        "http": "http://proxy:1", "https": "socks5h://proxy:2"
    }


def test_session_custom_ca(tmp_path):
    cafile = tmp_path / "ca.crt"
    cafile.write_text("")
    client = WardenClient(WardenConfiguration(
        url=URL, username=EMAIL, password=PASSWORD, auth_data=LoginDataBuilder().build(), https_cafile=str(cafile),
    ))
    assert client._session.verify == str(cafile)  # pylint: disable=protected-access


def test_context_manager_closes_session():
    with WardenClient(WardenConfiguration(url=URL, username=EMAIL, password=PASSWORD,
                                          auth_data=LoginDataBuilder().build())) as client:
        client._session.close = MagicMock()  # pylint: disable=protected-access
    client._session.close.assert_called_once_with()  # pylint: disable=protected-access

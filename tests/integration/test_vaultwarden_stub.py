"""
Integration tests against real data: a cache file produced by this client from an empty VaultWarden
(2026.10, docker) with three items created through the web vault. Nothing is generated or mocked on
the crypto side, so these tests catch incompatibilities with what a real server produces.

The account is a throw-away one, its credentials are not a secret.
"""
# pylint: disable=redefined-outer-name
import json
import shutil
from pathlib import Path

import pytest
import requests

from bit_vault_warden_client import (
    CredentialsError, CredentialsNotFoundError, WardenCacheMode, WardenClient, WardenConfiguration
)
from tests.fixtures.login_data_builder import LoginDataBuilder

STUB = Path(__file__).resolve().parents[1] / "_stubs" / "bitwarden.2026-10-1.cache"
EMAIL = "shader@inbox.lv"
PASSWORD = "kjdhgi781y2kjbsd"
URL = "http://localhost:8080"

# name, (username, password, totp), notes
ITEMS = [
    ("test item 1", ("testuser1", "test'passwo\"rd1", ""), ""),
    ("test item 2", ("testuser2", "testpassword2", ""), "test notes 2"),
    ("test item 3", ("testuser3", "testpassword3", "somebullshit2faplaceholder"), ""),
]


@pytest.fixture
def stub_data():
    with open(STUB, encoding="utf8") as file:
        return json.load(file)


@pytest.fixture(autouse=True)
def tempdir(tmp_path, monkeypatch):
    """
    Work on a copy of the stub in an isolated temp dir, the stub itself is never modified
    """
    monkeypatch.setattr("bit_vault_warden_client.models.gettempdir", lambda: str(tmp_path))
    shutil.copyfile(STUB, tmp_path / STUB.name)
    return tmp_path


def make_client(cache_mode=WardenCacheMode.LOCALONLY, password=PASSWORD, email=EMAIL) -> WardenClient:
    return WardenClient(WardenConfiguration(
        url=URL,
        username=email,
        password=password,
        auth_data=LoginDataBuilder().build(),
        cache_mode=cache_mode,
        cache_filename=STUB.name,
        cache_ttl=10 ** 10,
    ))


def test_stub_is_what_tests_expect(stub_data):
    """
    Guard: the stub uses the 1.37+ schema and individual cipher keys for every item
    """
    ciphers = stub_data["DATA"]["ciphers"]
    assert stub_data["KDFITERATIONS"] == 600000
    assert len(ciphers) == len(ITEMS)
    assert all("data" not in cipher and cipher["key"] for cipher in ciphers)
    assert all(cipher["organizationId"] is None and cipher["deletedDate"] is None for cipher in ciphers)


@pytest.mark.parametrize("name, credentials, notes", ITEMS, ids=[item[0] for item in ITEMS])
def test_fetch_credentials_from_cache(name, credentials, notes):
    with make_client() as client:
        result = client.fetch_credentials(name)

    assert result.astuple() == credentials
    assert tuple(result) == credentials
    assert result.notes == notes


def test_lookup_is_case_insensitive_and_email_normalized():
    with make_client(email="  Shader@Inbox.LV ") as client:
        assert client.fetch_credentials("TEST ITEM 2").password == "testpassword2"


def test_item_not_found():
    with make_client() as client, pytest.raises(CredentialsNotFoundError):
        client.fetch_credentials("test item 4")


def test_wrong_password():
    with make_client(password="wrong password") as client, pytest.raises(CredentialsError, match="MAC did not match"):
        client.fetch_credentials("test item 1")


def test_expired_stub_is_still_used_locally(tempdir, caplog):
    client = WardenClient(WardenConfiguration(
        url=URL, username=EMAIL, password=PASSWORD, auth_data=LoginDataBuilder().build(),
        cache_mode=WardenCacheMode.LOCALONLY, cache_filename=STUB.name, cache_ttl=0,
    ))
    assert client.fetch_credentials("test item 1").username == "testuser1"
    assert "Cache is expired" in caplog.text
    assert (tempdir / STUB.name).read_bytes() == STUB.read_bytes()


class StubServer:
    """
    Replays the stub data as the server would return it: pre-login, token and sync responses
    """

    def __init__(self, data: dict):
        self.data = data
        self.requests = []

    def handle(self, url, **kwargs):
        self.requests.append((url, kwargs))
        profile = self.data["DATA"]["profile"]
        if url.endswith("/api/accounts/prelogin"):
            body = {"kdf": 0, "kdfIterations": self.data["KDFITERATIONS"], "kdfMemory": None, "kdfParallelism": None}
        elif url.endswith("/identity/connect/token"):
            body = {"access_token": "token", "Key": profile["key"], "PrivateKey": profile["privateKey"]}
        else:
            body = self.data["DATA"]
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(body).encode("utf-8")  # pylint: disable=protected-access
        return response


def test_fetch_credentials_from_remote_refreshes_cache(stub_data, tempdir):
    (tempdir / STUB.name).unlink()
    server = StubServer(stub_data)

    with make_client(cache_mode=WardenCacheMode.FALLBACK) as client:
        client._session.post = client._session.get = server.handle  # pylint: disable=protected-access
        result = client.fetch_credentials("test item 1")

        assert result.astuple() == ITEMS[0][1]
        assert len(server.requests) == 3

        # cache written from the remote response is usable on its own
        with open(tempdir / STUB.name, encoding="utf8") as file:
            assert json.load(file) == stub_data
        server.handle = None
        assert client.fetch_credentials_from_cache("test item 3").totp == "somebullshit2faplaceholder"

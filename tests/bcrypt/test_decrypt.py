import os

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from bit_vault_warden_client.bcrypt import (
    BitwardenSecrets, decrypt_cipher, decrypt_cipher_string, decrypt_rsa, decrypt_string,
    get_cipher_keys, get_organization_key
)
from bit_vault_warden_client.errors import CredentialsError, UnsupportedEncryptionError
from tests.fixtures.vault_builder import RSA_KEY, VaultBuilder, encrypt_aes, encrypt_rsa, encrypt_text

KEY = os.urandom(64)
DER_KEY = RSA_KEY.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())


def test_decrypt_cipher_string_roundtrip():
    payload = os.urandom(64)
    assert decrypt_cipher_string(encrypt_aes(payload, KEY), KEY[0:32], KEY[32:64]) == (
        payload, payload[0:32], payload[32:64]
    )


@pytest.mark.parametrize("text", [
    "plain",
    'with "quotes"',
    "back\\slash and double \\\\ backslash",
    "multi\nline\ttext",
    "unicode: ēāšķ 密码 🔑",
    "{\"json\": [1, 2]}",
])
def test_decrypt_string_keeps_value_intact(text):
    assert decrypt_string(encrypt_text(text, KEY), KEY[0:32], KEY[32:64]) == text


def test_decrypt_cipher_string_wrong_mac_key():
    with pytest.raises(CredentialsError, match="MAC did not match"):
        decrypt_cipher_string(encrypt_aes(b"data", KEY), KEY[0:32], os.urandom(32))


def test_decrypt_cipher_string_wrong_encryption_key():
    with pytest.raises(CredentialsError, match="Could Not Decode"):
        # MAC is valid, but the padding of the decrypted data is not
        decrypt_cipher_string(encrypt_aes(b"data", KEY), os.urandom(32), KEY[32:64])


@pytest.mark.parametrize("cipher_string", ["0.aXY=|ZGF0YQ==", "1.aXY=|ZGF0YQ==|bWFj", "4.ZGF0YQ=="])
def test_decrypt_cipher_string_unsupported_type(cipher_string):
    with pytest.raises(UnsupportedEncryptionError, match="Unsupported encryption type"):
        decrypt_cipher_string(cipher_string, KEY[0:32], KEY[32:64])


@pytest.mark.parametrize("cipher_string", ["", "no-dot", "x.aXY=|ZGF0YQ==|bWFj", "2.aXY=|ZGF0YQ==", None])
def test_decrypt_cipher_string_malformed(cipher_string):
    with pytest.raises(ValueError, match="Malformed cipher string"):
        decrypt_cipher_string(cipher_string, KEY[0:32], KEY[32:64])


@pytest.mark.parametrize("enc_type", [3, 4, 5, 6])
def test_decrypt_rsa(enc_type):
    assert decrypt_rsa(encrypt_rsa(b"organization key", enc_type), DER_KEY) == b"organization key"


@pytest.mark.parametrize("cipher_string", ["2.aXY=|ZGF0YQ==|bWFj", "7.ZGF0YQ=="])
def test_decrypt_rsa_unsupported_type(cipher_string):
    with pytest.raises(UnsupportedEncryptionError):
        decrypt_rsa(cipher_string, DER_KEY)


@pytest.fixture(name="vault")
def fixture_vault():
    return VaultBuilder("user@example.com", "secret").add_organization("org-1")


@pytest.fixture(name="secrets")
def fixture_secrets(vault):
    return BitwardenSecrets(
        email=vault.email,
        kdfIterations=vault.iterations,
        MasterPassword=vault.password.encode("utf-8"),
        ProtectedSymmetricKey=vault.protected_user_key,
        ProtectedRSAPrivateKey=vault.protected_private_key,
    )


def test_get_organization_key_is_memoized(vault, secrets):
    data = vault.sync_response()
    key = get_organization_key("org-1", data, secrets)
    assert key == vault.org_keys["org-1"][0]
    assert secrets.OrgSecrets == {"org-1": key}

    data["profile"]["organizations"] = []
    assert get_organization_key("org-1", data, secrets) == key


def test_get_organization_key_unknown_organization(vault, secrets):
    with pytest.raises(CredentialsError, match="org-2"):
        get_organization_key("org-2", vault.sync_response(), secrets)


@pytest.mark.parametrize("organization_id, cipher_key", [
    (None, False),
    (None, True),
    ("org-1", False),
    ("org-1", True),
])
def test_get_cipher_keys(vault, secrets, organization_id, cipher_key):
    vault.add_login("item", password="pass", organization_id=organization_id, cipher_key=cipher_key)
    data = vault.sync_response()
    cipher = data["ciphers"][0]

    enc_key, mac_key = get_cipher_keys(cipher, data, secrets)

    assert decrypt_string(cipher["name"], enc_key, mac_key) == "item"


@pytest.mark.parametrize("legacy", [False, True])
def test_decrypt_cipher(vault, secrets, legacy):
    vault.add_login("item", username="user", password="pass", totp="otpauth://totp/x", notes="note")
    data = vault.sync_response(legacy=legacy)
    cipher = data["ciphers"][0]
    original = dict(cipher)

    decrypted = decrypt_cipher(cipher, secrets.GeneratedEncryptionKey, secrets.GeneratedMACKey)

    login = decrypted if legacy else decrypted["login"]
    assert decrypted["name"] == "item"
    assert decrypted["notes"] == "note"
    assert (login["username"], login["password"], login["totp"]) == ("user", "pass", "otpauth://totp/x")
    # source data is left untouched
    assert cipher == original


def test_decrypt_cipher_secure_note(vault, secrets):
    vault.add_login("note item", notes="secret note", cipher_type=2)
    cipher = vault.sync_response()["ciphers"][0]

    decrypted = decrypt_cipher(cipher, secrets.GeneratedEncryptionKey, secrets.GeneratedMACKey)

    assert decrypted["name"] == "note item"
    assert decrypted["notes"] == "secret note"
    assert decrypted["login"] is None

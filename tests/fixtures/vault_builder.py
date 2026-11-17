"""
Builds a real, encrypted Bitwarden/VaultWarden dataset (pre-login, token and sync responses),
so the client can be tested end-to-end without mocking any cryptography.
"""
from __future__ import annotations
import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetricpadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_HASHES = {3: hashes.SHA256, 4: hashes.SHA1, 5: hashes.SHA256, 6: hashes.SHA1}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def encrypt_aes(plaintext: bytes, key: bytes) -> str:
    """
    Encrypt into "2.<iv>|<ciphertext>|<mac>" cipher string with a 64 bytes (enc + mac) key
    """
    enc_key, mac_key = key[0:32], key[32:64]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv)
    h.update(ciphertext)
    return f"2.{b64(iv)}|{b64(ciphertext)}|{b64(h.finalize())}"


def encrypt_text(text: str, key: bytes) -> str:
    return encrypt_aes(text.encode("utf-8"), key)


def encrypt_rsa(plaintext: bytes, enc_type: int = 4) -> str:
    algorithm = RSA_HASHES[enc_type]
    ciphertext = RSA_KEY.public_key().encrypt(
        plaintext,
        asymmetricpadding.OAEP(mgf=asymmetricpadding.MGF1(algorithm=algorithm()), algorithm=algorithm(), label=None)
    )
    if enc_type in (5, 6):
        return f"{enc_type}.{b64(ciphertext)}|{b64(b'ignored-mac')}"
    return f"{enc_type}.{b64(ciphertext)}"


def stretch(master_key: bytes) -> bytes:
    enc = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(master_key)
    mac = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(master_key)
    return enc + mac


# pylint: disable=too-many-instance-attributes
class VaultBuilder:
    """
    Usage:
        vault = VaultBuilder("user@example.com", "secret")
        vault.add_login("item name", username="u", password="p")
        vault.sync_response(legacy=False)
    """

    def __init__(self, email: str, password: str, iterations: int = 1000):
        self.email = email
        self.password = password
        self.iterations = iterations
        self.user_key = os.urandom(64)
        self.org_keys = {}
        self.ciphers: list[dict] = []

        self.master_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), email.strip().lower().encode("utf-8"), iterations
        )
        self.master_password_hash = b64(
            hashlib.pbkdf2_hmac("sha256", self.master_key, password.encode("utf-8"), 1)
        )
        self.protected_user_key = encrypt_aes(self.user_key, stretch(self.master_key))
        der = RSA_KEY.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        self.protected_private_key = encrypt_aes(der, self.user_key)

    def add_organization(self, org_id: str, enc_type: int = 4) -> VaultBuilder:
        key = os.urandom(64)
        self.org_keys[org_id] = (key, encrypt_rsa(key, enc_type))
        return self

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def add_login(
        self,
        name: str,
        username: str | None = None,
        password: str | None = None,
        totp: str | None = None,
        notes: str | None = None,
        organization_id: str | None = None,
        cipher_key: bool = False,
        deleted: bool = False,
        cipher_type: int = 1,
        broken: bool = False,
    ) -> VaultBuilder:
        key = self.org_keys[organization_id][0] if organization_id else self.user_key
        protected_cipher_key = None
        if cipher_key:
            individual_key = os.urandom(64)
            protected_cipher_key = encrypt_aes(individual_key, key)
            key = individual_key
        if broken:
            key = os.urandom(64)

        def enc(value):
            return encrypt_text(value, key) if value is not None else None

        self.ciphers.append({
            "id": f"cipher-{len(self.ciphers)}",
            "type": cipher_type,
            "organizationId": organization_id,
            "key": protected_cipher_key,
            "deletedDate": "2024-01-01T00:00:00Z" if deleted else None,
            "name": enc(name),
            "notes": enc(notes),
            "login": None if cipher_type != 1 else {
                "username": enc(username),
                "password": enc(password),
                "totp": enc(totp),
                "uris": [],
            },
        })
        return self

    def prelogin_response(self) -> dict:
        return {"kdf": 0, "kdfIterations": self.iterations, "kdfMemory": None, "kdfParallelism": None}

    def token_response(self) -> dict:
        return {
            "access_token": "fake_access_token",
            "token_type": "Bearer",
            "Key": self.protected_user_key,
            "PrivateKey": self.protected_private_key,
        }

    def sync_response(self, legacy: bool = False) -> dict:
        """
        :param legacy: pre VaultWarden 1.37 schema, where cipher fields are kept flat in "data"
        """
        ciphers = []
        for cipher in self.ciphers:
            cipher = dict(cipher)
            if legacy:
                login = cipher.pop("login") or {}
                cipher["data"] = {
                    "name": cipher.pop("name"),
                    "notes": cipher.pop("notes"),
                    "username": login.get("username"),
                    "password": login.get("password"),
                    "totp": login.get("totp"),
                }
            ciphers.append(cipher)

        return {
            "profile": {
                "email": self.email,
                "key": self.protected_user_key,
                "privateKey": self.protected_private_key,
                "organizations": [{"id": org_id, "key": key[1]} for org_id, key in self.org_keys.items()],
            },
            "folders": [],
            "collections": [],
            "ciphers": ciphers,
        }

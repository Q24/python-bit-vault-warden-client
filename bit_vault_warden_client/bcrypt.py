# pylint: disable=invalid-name,too-many-instance-attributes
from __future__ import annotations
import base64
import copy
import hashlib
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetricpadding
from cryptography.hazmat.primitives.serialization import load_der_private_key

from bit_vault_warden_client.errors import CredentialsError, UnsupportedEncryptionError

# KDF types, as returned by the pre-login endpoint
KDF_PBKDF2_SHA256 = 0

# Symmetric encryption type: AesCbc256_HmacSha256_B64
ENC_TYPE_AES_CBC_256_HMAC_SHA256 = 2

# Asymmetric encryption types (RSA-2048 OAEP) and the hash algorithm each one uses
RSA_ENC_TYPE_HASHES = {
    3: hashes.SHA256,  # Rsa2048_OaepSha256_B64
    4: hashes.SHA1,  # Rsa2048_OaepSha1_B64
    5: hashes.SHA256,  # Rsa2048_OaepSha256_HmacSha256_B64
    6: hashes.SHA1,  # Rsa2048_OaepSha1_HmacSha256_B64
}

# Encrypted fields of a cipher (vault item)
CIPHER_FIELDS = ("name", "notes")
LOGIN_FIELDS = ("username", "password", "totp")
# Pre VaultWarden 1.37 schema keeps all the fields flat in "data"
LEGACY_DATA_FIELDS = CIPHER_FIELDS + LOGIN_FIELDS


def normalize_email(email: str) -> str:
    """
    Bitwarden clients always use trimmed lower-cased e-mail as the KDF salt
    """
    return email.strip().lower()


@dataclass(repr=False)
class BitwardenSecrets:
    # defined
    email: str = field()
    kdfIterations: int = field()
    MasterPassword: bytes = field()
    ProtectedSymmetricKey: str = field()
    ProtectedRSAPrivateKey: str = field()
    # generated, MasterKey may be provided to skip the expensive derivation
    MasterKey: bytes = field(default=None)
    MasterKey_b64: str = field(default=None)
    MasterPasswordHash: str = field(default=None)
    StretchedEncryptionKey: bytes = field(default=None)
    StretchedEncryptionKey_b64: str = field(default=None)
    StretchedMacKey: bytes = field(default=None)
    StretchedMacKey_b64: str = field(default=None)
    StretchedMasterKey: bytes = field(default=None)
    StretchedMasterKey_b64: str = field(default=None)
    GeneratedSymmetricKey: bytes = field(default=None)
    GeneratedEncryptionKey: bytes = field(default=None)
    GeneratedMACKey: bytes = field(default=None)
    GeneratedSymmetricKey_b64: str = field(default=None)
    GeneratedEncryptionKey_b64: str = field(default=None)
    GeneratedMACKey_b64: str = field(default=None)
    RSAPrivateKey: bytes = field(default=None)
    # decrypted organization keys, by organization id
    OrgSecrets: dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self):
        if self.MasterKey is None:
            kdf = self.__pbkdf2hmac(bytes(normalize_email(self.email), "utf-8"), self.kdfIterations)
            self.MasterKey = kdf.derive(self.MasterPassword)
        self.MasterKey_b64 = base64.b64encode(self.MasterKey).decode("utf-8")

        kdf = self.__pbkdf2hmac(bytes(self.MasterPassword), 1)
        self.MasterPasswordHash = base64.b64encode(kdf.derive(self.MasterKey)).decode("utf-8")

        hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc", backend=default_backend())
        self.StretchedEncryptionKey = hkdf.derive(self.MasterKey)
        self.StretchedEncryptionKey_b64 = base64.b64encode(self.StretchedEncryptionKey).decode("utf-8")

        hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac", backend=default_backend())
        self.StretchedMacKey = hkdf.derive(self.MasterKey)
        self.StretchedMacKey_b64 = base64.b64encode(self.StretchedMacKey).decode("utf-8")
        self.StretchedMasterKey = self.StretchedEncryptionKey + self.StretchedMacKey
        self.StretchedMasterKey_b64 = base64.b64encode(self.StretchedMasterKey).decode("utf-8")

        self.GeneratedSymmetricKey, self.GeneratedEncryptionKey, self.GeneratedMACKey = decrypt_cipher_string(
            self.ProtectedSymmetricKey,
            self.StretchedEncryptionKey,
            self.StretchedMacKey
        )

        self.GeneratedSymmetricKey_b64 = base64.b64encode(self.GeneratedSymmetricKey).decode("utf-8")
        self.GeneratedEncryptionKey_b64 = base64.b64encode(self.GeneratedEncryptionKey).decode("utf-8")
        self.GeneratedMACKey_b64 = base64.b64encode(self.GeneratedMACKey).decode("utf-8")

        decrypted_key = decrypt_cipher_string(
            self.ProtectedRSAPrivateKey,
            self.GeneratedEncryptionKey,
            self.GeneratedMACKey
        )

        self.RSAPrivateKey = decrypted_key[0]

    @staticmethod
    def __pbkdf2hmac(salt: bytes, iterations: int):
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )


def decrypt_user_key(email: str, master_password: str, kdf: int, kdf_iterations: int) -> bytes:
    """
    Derive the master key from master password and e-mail

    :raises UnsupportedEncryptionError: when the account uses another KDF than PBKDF2-SHA256
    """
    if kdf != KDF_PBKDF2_SHA256:
        raise UnsupportedEncryptionError(f"Unsupported KDF type: {kdf}, only PBKDF2-SHA256 (0) is supported")
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        normalize_email(email).encode("utf-8"),
        kdf_iterations
    )


def _parse_cipher_string(cipher_string: str) -> tuple[int, list[str]]:
    """
    Split "<encType>.<part>|<part>|..." into encryption type and its parts

    :raises ValueError: when the string is not a valid cipher string
    """
    try:
        enc_type, payload = cipher_string.split(".", 1)
        return int(enc_type), payload.split("|")
    except (AttributeError, ValueError) as e:
        raise ValueError("Malformed cipher string") from e


def decrypt_cipher_string(cipher_string: str, master_key: bytes, master_mac: bytes) -> tuple[bytes, bytes, bytes]:
    """
    :param cipher_string: str
    :param master_key: bytes
    :param master_mac: bytes
    :return: tuple[SymmetricKey: ``bytes``, EncryptionKey: ``bytes``, MACKey: ``bytes``]
    :raises UnsupportedEncryptionError: when the encryption type is not supported
    :raises CredentialsError: when the MAC does not match or the data can not be decrypted
    :raises ValueError: when the cipher string is malformed
    """
    enc_type, parts = _parse_cipher_string(cipher_string)
    if enc_type != ENC_TYPE_AES_CBC_256_HMAC_SHA256:
        raise UnsupportedEncryptionError(f"Unsupported encryption type: {enc_type}")
    if len(parts) != 3:
        raise ValueError("Malformed cipher string")

    iv, ciphertext, mac = (base64.b64decode(part) for part in parts)

    # Verify CipherString MAC (constant time comparison)
    h = hmac.HMAC(master_mac, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    h.update(ciphertext)
    try:
        h.verify(mac)
    except InvalidSignature as e:
        raise CredentialsError("Wrong credentials. MAC did not match.") from e

    unpadder = padding.PKCS7(128).unpadder()
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        cleartext = unpadder.update(decrypted) + unpadder.finalize()
    except ValueError as e:
        raise CredentialsError("Wrong credentials. Could Not Decode Protected Symmetric Key.") from e

    #   SymmetricKey, EncryptionKey,   MACKey
    return cleartext, cleartext[0:32], cleartext[32:64]


def decrypt_rsa(cipher_string: str, key: bytes) -> bytes:
    """
    Decrypt RSA-OAEP encrypted cipher string (used for organization keys)

    :param cipher_string: str
    :param key: DER encoded RSA private key
    :raises UnsupportedEncryptionError: when the encryption type is not supported
    """
    enc_type, parts = _parse_cipher_string(cipher_string)
    if enc_type not in RSA_ENC_TYPE_HASHES:
        raise UnsupportedEncryptionError(f"Unsupported encryption type: {enc_type}")
    algorithm = RSA_ENC_TYPE_HASHES[enc_type]

    # For HMAC variants the second part is the MAC, which is not needed for decryption
    ciphertext = base64.b64decode(parts[0])
    private_key = load_der_private_key(key, password=None, backend=default_backend())

    return private_key.decrypt(
        ciphertext,
        asymmetricpadding.OAEP(
            mgf=asymmetricpadding.MGF1(algorithm=algorithm()),
            algorithm=algorithm(),
            label=None
        )
    )


def decrypt_string(data: str, enc_key: bytes, mac_key: bytes) -> str:
    """
    Decrypt cipher string into a text value
    """
    return decrypt_cipher_string(data, enc_key, mac_key)[0].decode("utf-8")


def get_organization_key(org_id: str, data: dict, bitwarden_secrets: BitwardenSecrets) -> bytes:
    """
    Get decrypted organization key, decrypting (and memoizing) it on first use

    :raises CredentialsError: when the profile has no key for the organization
    """
    if org_id not in bitwarden_secrets.OrgSecrets:
        organizations = data.get("profile", {}).get("organizations") or []
        protected_key = next((org.get("key") for org in organizations if org.get("id") == org_id), None)
        if not protected_key:
            raise CredentialsError(f"Profile does not contain key for organization '{org_id}'")
        bitwarden_secrets.OrgSecrets[org_id] = decrypt_rsa(protected_key, bitwarden_secrets.RSAPrivateKey)
    return bitwarden_secrets.OrgSecrets[org_id]


def get_cipher_keys(cipher: dict, data: dict, bitwarden_secrets: BitwardenSecrets) -> tuple[bytes, bytes]:
    """
    Resolve encryption and MAC keys for a cipher (vault item):
    user key or organization key, optionally wrapping an individual cipher key.

    :return: tuple[EncryptionKey: ``bytes``, MACKey: ``bytes``]
    """
    org_id = cipher.get("organizationId")
    if org_id:
        org_key = get_organization_key(org_id, data, bitwarden_secrets)
        enc_key, mac_key = org_key[0:32], org_key[32:64]
    else:
        enc_key, mac_key = bitwarden_secrets.GeneratedEncryptionKey, bitwarden_secrets.GeneratedMACKey

    if cipher.get("key"):
        _, enc_key, mac_key = decrypt_cipher_string(cipher["key"], enc_key, mac_key)

    return enc_key, mac_key


def get_cipher_fields(cipher: dict) -> dict:
    """
    Get the dict holding cipher fields (name, notes, ...), pre and post VaultWarden 1.37 schemas
    """
    return cipher["data"] if isinstance(cipher.get("data"), dict) else cipher


def decrypt_cipher(cipher: dict, enc_key: bytes, mac_key: bytes) -> dict:
    """
    Return a copy of cipher fields with name, notes and login fields decrypted
    """
    source = get_cipher_fields(cipher)
    fields = copy.deepcopy(source)

    if source is not cipher:
        _decrypt_fields(fields, LEGACY_DATA_FIELDS, enc_key, mac_key)
    else:
        _decrypt_fields(fields, CIPHER_FIELDS, enc_key, mac_key)
        if isinstance(fields.get("login"), dict):
            _decrypt_fields(fields["login"], LOGIN_FIELDS, enc_key, mac_key)

    return fields


def _decrypt_fields(container: dict, names: tuple[str, ...], enc_key: bytes, mac_key: bytes) -> None:
    for name in names:
        value: str | None = container.get(name)
        if value:
            container[name] = decrypt_string(value, enc_key, mac_key)

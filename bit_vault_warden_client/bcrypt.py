# pylint: disable=invalid-name,too-many-instance-attributes
import json
import base64
import hashlib
from dataclasses import dataclass, field
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetricpadding
from cryptography.hazmat.primitives.serialization import load_der_private_key

from bit_vault_warden_client.errors import CredentialsError


@dataclass
class BitwardenSecrets:
    # defined
    email: str = field()
    kdfIterations: int = field()
    MasterPassword: bytes = field()
    ProtectedSymmetricKey: str = field()
    ProtectedRSAPrivateKey: str = field()
    # generated
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

    def __post_init__(self):
        kdf = self.__pbkdf2hmac(bytes(self.email, "utf-8"), self.kdfIterations)
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
    assert kdf == 0
    return hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), email.encode("utf-8"), kdf_iterations)


def decrypt_cipher_string(cipher_string: str, master_key: bytes, master_mac: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    :param cipher_string: str
    :param master_key: bytes
    :param master_mac: bytes
    :return: tuple[SymmetricKey: ``bytes``, EncryptionKey: ``bytes``, MACKey: ``bytes``]
    """
    iv = base64.b64decode(cipher_string.split(".")[1].split("|")[0])
    ciphertext = base64.b64decode(cipher_string.split(".")[1].split("|")[1])
    mac = base64.b64decode(cipher_string.split(".")[1].split("|")[2])

    encType = int(cipher_string.split(".")[0])
    assert encType == 2, f"Unsupported encryption type: {encType}"
    # TODO: [0, 1] encTypes also could match AES, check if relevant

    # Calculate CipherString MAC
    h = hmac.HMAC(master_mac, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    h.update(ciphertext)

    if mac != h.finalize():
        raise CredentialsError("Wrong credentials. MAC did not match.")

    unpadder = padding.PKCS7(128).unpadder()
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    # noinspection PyBroadException
    try:
        cleartext = unpadder.update(decrypted) + unpadder.finalize()
    except Exception as e:
        raise CredentialsError("Wrong credentials. Could Not Decode Protected Symmetric Key.") from e

    #   SymmetricKey, EncryptionKey,   MACKey
    return cleartext, cleartext[0:32], cleartext[32:64]


def decrypt_rsa(cipher_string: str, key: bytes) -> bytes:
    encType = int(cipher_string.split(".")[0])
    assert encType == 4, f"Unsupported encryption type: {encType}"
    # TODO: for [3, 5] support replace SHA1() with SHA256()
    # TODO: enctype [6] probably also is SHA1() but could not test

    ciphertext = base64.b64decode(cipher_string.split(".")[1].split("|")[0])
    private_key = load_der_private_key(key, password=None, backend=default_backend())

    return private_key.decrypt(
        ciphertext,
        asymmetricpadding.OAEP(
            mgf=asymmetricpadding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


# pylint: disable=too-many-branches
# flake8: noqa
def decrypt_bitwarden_data(data: dict, bitwarden_secrets: BitwardenSecrets) -> str:
    bitwarden_secrets.OrgSecrets = {}

    for orgItems in data["profile"]["organizations"]:
        bitwarden_secrets.OrgSecrets.update({
            orgItems["id"]: decrypt_rsa(orgItems["key"], bitwarden_secrets.RSAPrivateKey)
        })

    for folder_name in data["folders"]:
        enc_key = bitwarden_secrets.GeneratedEncryptionKey
        mac_key = bitwarden_secrets.GeneratedMACKey
        folder_name["name"] = get_json_escaped_string(folder_name["name"], enc_key, mac_key)

    for collections_name in data["collections"]:
        if len(collections_name["organizationId"]) > 0:
            enc_key = bitwarden_secrets.OrgSecrets[collections_name["organizationId"]][0:32]
            mac_key = bitwarden_secrets.OrgSecrets[collections_name["organizationId"]][32:64]
        else:
            enc_key = bitwarden_secrets.GeneratedEncryptionKey
            mac_key = bitwarden_secrets.GeneratedMACKey

        collections_name["name"] = get_json_escaped_string(collections_name["name"], enc_key, mac_key)

    for ciphername in data["ciphers"]:
        enc_key = None
        mac_key = None

        if ciphername["organizationId"]:
            if len(ciphername["organizationId"]) > 0:
                enc_key = bitwarden_secrets.OrgSecrets[ciphername["organizationId"]][0:32]
                mac_key = bitwarden_secrets.OrgSecrets[ciphername["organizationId"]][32:64]
        else:
            enc_key = bitwarden_secrets.GeneratedEncryptionKey
            mac_key = bitwarden_secrets.GeneratedMACKey

        if not enc_key or not mac_key:
            raise RuntimeError('This should not happen - empty encKey or macKey')

        if "data" not in ciphername:
            raise RuntimeError('Empty, broken or unsupported entity')

        if "name" in ciphername["data"] and ciphername["data"]["name"]:
            ciphername["data"]["name"] = get_json_escaped_string(ciphername["data"]["name"], enc_key, mac_key)

        if "notes" in ciphername["data"] and ciphername["data"]["notes"]:
            ciphername["data"]["notes"] = get_json_escaped_string(ciphername["data"]["notes"], enc_key, mac_key)

        if "password" in ciphername["data"] and ciphername["data"]["password"]:
            ciphername["data"]["password"] = get_json_escaped_string(ciphername["data"]["password"], enc_key, mac_key)

        if "username" in ciphername["data"] and ciphername["data"]["username"]:
            ciphername["data"]["username"] = get_json_escaped_string(ciphername["data"]["username"], enc_key, mac_key)

        if "totp" in ciphername["data"] and ciphername["data"]["totp"]:
            ciphername["data"]["totp"] = get_json_escaped_string(ciphername["data"]["totp"], enc_key, mac_key)

    return json.dumps(data, indent=2, ensure_ascii=False)


def get_json_escaped_string(data: str, enc_key: bytes, mac_key: bytes) -> str:
    decrypted_key = decrypt_cipher_string(data, enc_key, mac_key)
    decrypted_data = decrypted_key[0].decode("utf-8")
    json_escaped_string = json.JSONEncoder().encode(decrypted_data)
    return json_escaped_string[1:(len(json_escaped_string) - 1)]

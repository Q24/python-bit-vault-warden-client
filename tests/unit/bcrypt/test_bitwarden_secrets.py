import base64
import hashlib
import unittest
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from bit_vault_warden_client.bcrypt import (
    BitwardenSecrets, decrypt_user_key, decrypt_string
)
from bit_vault_warden_client.errors import CredentialsError, UnsupportedEncryptionError
from tests.fixtures.vault_builder import VaultBuilder


class TestBitwardenSecrets(unittest.TestCase):
    @patch("bit_vault_warden_client.bcrypt.decrypt_cipher_string")
    @patch("bit_vault_warden_client.bcrypt.PBKDF2HMAC")
    @patch("bit_vault_warden_client.bcrypt.HKDFExpand")
    def test_initialization(self, mock_hkdf, mock_pbkdf2, mock_decrypt):
        # Mock PBKDF2HMAC
        mock_kdf_instance = MagicMock()
        mock_kdf_instance.derive.return_value = b"mock_derived_key_32_bytes__"
        mock_pbkdf2.return_value = mock_kdf_instance

        # Mock HKDFExpand
        mock_hkdf_instance = MagicMock()
        mock_hkdf_instance.derive.return_value = b"mock_hkdf_key_32_bytes__"
        mock_hkdf.return_value = mock_hkdf_instance

        # Mock decrypt_cipher_string
        mock_decrypt.return_value = (b"mock_sym_key", b"mock_enc_key", b"mock_mac_key")

        secrets = BitwardenSecrets(
            email="test@example.com",
            kdfIterations=100000,
            MasterPassword=b"test_password",
            ProtectedSymmetricKey="mock_protected_symmetric_key",
            ProtectedRSAPrivateKey="mock_protected_rsa_key"
        )

        # Check PBKDF2HMAC calls
        mock_pbkdf2.assert_any_call(
            algorithm=unittest.mock.ANY,
            length=32,
            salt=b"test@example.com",
            iterations=100000,
            backend=unittest.mock.ANY
        )

        mock_pbkdf2.assert_any_call(
            algorithm=unittest.mock.ANY,
            length=32,
            salt=b"test_password",
            iterations=1,
            backend=unittest.mock.ANY
        )

        # Check HKDFExpand calls
        mock_hkdf.assert_any_call(
            algorithm=unittest.mock.ANY,
            length=32,
            info=b"enc",
            backend=unittest.mock.ANY
        )

        mock_hkdf.assert_any_call(
            algorithm=unittest.mock.ANY,
            length=32,
            info=b"mac",
            backend=unittest.mock.ANY
        )

        # Check decrypted values
        self.assertEqual(secrets.GeneratedSymmetricKey, b"mock_sym_key")
        self.assertEqual(secrets.GeneratedEncryptionKey, b"mock_enc_key")
        self.assertEqual(secrets.GeneratedMACKey, b"mock_mac_key")

        # Check base64 encoding
        self.assertEqual(secrets.MasterKey_b64, base64.b64encode(b"mock_derived_key_32_bytes__").decode("utf-8"))
        self.assertEqual(secrets.GeneratedSymmetricKey_b64, base64.b64encode(b"mock_sym_key").decode("utf-8"))
        self.assertEqual(secrets.GeneratedEncryptionKey_b64, base64.b64encode(b"mock_enc_key").decode("utf-8"))
        self.assertEqual(secrets.GeneratedMACKey_b64, base64.b64encode(b"mock_mac_key").decode("utf-8"))

        # Check RSA private key decryption
        self.assertEqual(secrets.RSAPrivateKey, b"mock_sym_key")  # Only first element is assigned

    def test_decrypt_user_key(self):
        email = "test@example.com"
        master_password = "testpassword"
        kdf_iterations = 100000
        expected = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), email.encode("utf-8"),
                                       kdf_iterations)
        result = decrypt_user_key(email, master_password, 0, kdf_iterations)
        self.assertEqual(result, expected)

    def test_decrypt_user_key_normalizes_email(self):
        expected = decrypt_user_key("test@example.com", "testpassword", 0, 1000)
        self.assertEqual(decrypt_user_key("  Test@Example.COM ", "testpassword", 0, 1000), expected)

    def test_decrypt_user_key_unsupported_kdf(self):
        with self.assertRaises(UnsupportedEncryptionError):
            decrypt_user_key("test@example.com", "testpassword", 1, 3)

    @patch("bit_vault_warden_client.bcrypt.decrypt_cipher_string")
    def test_decrypt_string(self, mock_decrypt):
        # decrypted values are returned as is, without any JSON escaping
        mock_decrypt.return_value = ('p"ass\\word\n\u00e9'.encode("utf-8"), b"", b"")
        result = decrypt_string("mock_data", b"enc_key", b"mac_key")
        self.assertEqual(result, 'p"ass\\word\n\u00e9')
        mock_decrypt.assert_called_once_with("mock_data", b"enc_key", b"mac_key")


class TestBitwardenSecretsWithRealKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vault = VaultBuilder("User@Example.com", "master password")

    def build(self, **kwargs):
        params = {
            "email": self.vault.email,
            "kdfIterations": self.vault.iterations,
            "MasterPassword": self.vault.password.encode("utf-8"),
            "ProtectedSymmetricKey": self.vault.protected_user_key,
            "ProtectedRSAPrivateKey": self.vault.protected_private_key,
        }
        params.update(kwargs)
        return BitwardenSecrets(**params)

    def test_keys_are_decrypted(self):
        secrets = self.build()
        self.assertEqual(secrets.MasterKey, self.vault.master_key)
        self.assertEqual(secrets.MasterPasswordHash, self.vault.master_password_hash)
        self.assertEqual(secrets.GeneratedSymmetricKey, self.vault.user_key)
        self.assertEqual(secrets.GeneratedEncryptionKey, self.vault.user_key[0:32])
        self.assertEqual(secrets.GeneratedMACKey, self.vault.user_key[32:64])
        self.assertTrue(secrets.RSAPrivateKey.startswith(b"0\x82"))  # DER sequence
        self.assertEqual(secrets.OrgSecrets, {})

    @patch("bit_vault_warden_client.bcrypt.PBKDF2HMAC", wraps=PBKDF2HMAC)
    def test_provided_master_key_skips_derivation(self, mock_pbkdf2):
        secrets = self.build(MasterKey=self.vault.master_key)
        self.assertEqual(secrets.GeneratedSymmetricKey, self.vault.user_key)
        # only the single iteration for the master password hash
        mock_pbkdf2.assert_called_once()
        self.assertEqual(mock_pbkdf2.call_args.kwargs["iterations"], 1)

    def test_wrong_password(self):
        with self.assertRaises(CredentialsError):
            self.build(MasterPassword=b"wrong password")

    def test_repr_does_not_expose_secrets(self):
        self.assertNotIn(self.vault.password, repr(self.build()))


if __name__ == "__main__":
    unittest.main()

import base64
import hashlib
import unittest
from unittest.mock import patch, MagicMock
from bit_vault_warden_client.bcrypt import (
    BitwardenSecrets, decrypt_user_key, get_json_escaped_string
)


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

    @patch("bit_vault_warden_client.bcrypt.decrypt_cipher_string")
    def test_get_json_escaped_string(self, mock_decrypt):
        mock_decrypt.return_value = (b"decrypted_data",)
        result = get_json_escaped_string("mock_data", b"enc_key", b"mac_key")
        self.assertEqual(result, "decrypted_data")


if __name__ == "__main__":
    unittest.main()

import json
import os.path
import unittest
from pathlib import Path
from tempfile import gettempdir
from unittest.mock import patch
from bit_vault_warden_client.client import WardenWebApi
from bit_vault_warden_client.models import WardenConfiguration, Result, WardenCacheMode
from bit_vault_warden_client.errors import CredentialsNotFoundError
from tests.models.login_data_builder import LoginDataBuilder


dcs_retval = (b"test_credential", b"encryption_key", b"mac_key")
cache_fname = 'cache.json'
json_data = {
    "profile": {"key": "fake_profile_key", "privateKey": "fake_private_key", "organizations": []},
    "folders": [],
    "collections": [],
    "ciphers": [{"organizationId": "", "data": {"name": "test_credential", "password": "fake_password"}}]
}


class TestWardenWebApi(unittest.TestCase):
    def setUp(self):
        Path(os.path.join(gettempdir(), cache_fname)).touch()
        self.client = WardenWebApi(
            WardenConfiguration(
                url="https://example.com",
                username="testuser",
                password="testpassword",
                cache_filename=cache_fname,
                https_verify=False,
                https_proxy='https://localhost:6969',
                http_proxy='http://localhost:6969',
                cache_mode=WardenCacheMode.FALLBACK,
                auth_data=LoginDataBuilder().build()
            )
        )

    def tearDown(self):
        Path(os.path.join(gettempdir(), cache_fname)).unlink(missing_ok=True)
        del self.client

    @patch("bit_vault_warden_client.client.requests.Session.post")
    @patch("bit_vault_warden_client.client.requests.Session.get")
    @patch("bit_vault_warden_client.bcrypt.decrypt_user_key", return_value=b"fake_master_key")
    @patch("bit_vault_warden_client.bcrypt.decrypt_cipher_string", return_value=dcs_retval)
    def test_fetch_credentials_from_remote(self, mock_decrypt_user_key, _, mock_get, mock_post):
        mock_post.return_value.json.return_value = {
            "kdf": 0,
            "kdfIterations": 100000,
            "Key": "fake_encrypted_key",
            "PrivateKey": "fake_encrypted_private_key",
            "access_token": "fake_token",
        }

        mock_get.return_value.json.return_value = json_data

        result = self.client.fetch_credentials_from_remote("test_credential")
        self.assertIsInstance(result, Result)
        self.assertEqual(result.password, "test_credential")

    @patch("bit_vault_warden_client.client.open", create=True)
    @patch("bit_vault_warden_client.bcrypt.decrypt_cipher_string", return_value=dcs_retval)
    def test_fetch_credentials_from_cache(self, _, mock_open):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps({
            "KDFITERATIONS": 100000,
            "DATA": json_data
        })

        result = self.client.fetch_credentials_from_cache("test_credential")
        self.assertIsInstance(result, Result)
        self.assertEqual(result.password, "test_credential")

    @patch("bit_vault_warden_client.client.open", create=True)
    @patch("bit_vault_warden_client.bcrypt.decrypt_cipher_string", return_value=dcs_retval)
    def test_fetch_credentials_from_cache_not_found(self, _, mock_open):
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps({
            "KDFITERATIONS": 100000,
            "DATA": json_data
        })

        with self.assertRaises(CredentialsNotFoundError):
            self.client.fetch_credentials_from_cache("non_existent_credential")


if __name__ == "__main__":
    unittest.main()

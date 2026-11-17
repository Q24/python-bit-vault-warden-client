import unittest
from bit_vault_warden_client.errors import CredentialsNotFoundError, CredentialsError


class TestCredentialsNotFoundError(unittest.TestCase):
    def test_error(self):
        message = "Test message"
        error = CredentialsNotFoundError(message)
        self.assertIsInstance(error, CredentialsError)
        self.assertEqual(str(error), message)


if __name__ == '__main__':
    unittest.main()

import unittest
from bit_vault_warden_client.errors import CredentialsError


class TestCredentialsError(unittest.TestCase):
    def test_error(self):
        message = "Test message"
        error = CredentialsError(message)
        self.assertIsInstance(error, Exception)
        self.assertEqual(str(error), message)


if __name__ == '__main__':
    unittest.main()

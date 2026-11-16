class CredentialsError(Exception):
    pass


class CredentialsNotFoundError(CredentialsError):
    pass


class UnsupportedEncryptionError(NotImplementedError):
    """
    Raised when the vault uses a KDF or an encryption type this client does not implement.
    """

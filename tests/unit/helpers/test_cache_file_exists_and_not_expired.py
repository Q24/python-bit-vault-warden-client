import os
from time import time
from tempfile import NamedTemporaryFile, TemporaryDirectory
import pytest
from bit_vault_warden_client.helpers import cache_file_exists_and_not_expired


def test_cache_file_exists_and_not_expired():
    with NamedTemporaryFile(delete=False) as temp_file:
        cache_file = temp_file.name

    try:
        # Case 1: File exists and is within TTL
        ttl = 10
        assert cache_file_exists_and_not_expired(cache_file, ttl) == (True, True)

        # Case 2: File exists but is expired
        os.utime(cache_file, (time() - ttl - 1, time() - ttl - 1))
        assert cache_file_exists_and_not_expired(cache_file, ttl) == (True, False)

        # Case 3: File does not exist
        os.remove(cache_file)
        assert cache_file_exists_and_not_expired(cache_file, ttl) == (False, False)

    finally:
        # Cleanup in case the file wasn't removed
        if os.path.exists(cache_file):
            os.remove(cache_file)


def test_directory_is_not_a_cache_file():
    with TemporaryDirectory() as directory:
        assert cache_file_exists_and_not_expired(directory, 10) == (False, False)


if __name__ == '__main__':
    pytest.main()

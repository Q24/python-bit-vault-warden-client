from __future__ import annotations
from os import path
from time import time


def urljoin(*args) -> str:
    """
    Joins given arguments into an url
    """
    return "/".join(filter(None, (str(x).strip('/') for x in args)))


def cache_file_exists_and_not_expired(cache_file: str, cache_ttl: int) -> tuple[bool, bool]:
    """
    Check if cache file exists and it's not expired

    :param cache_file: absolute path to cache file
    :param cache_ttl: ttl cache
    :return: tuple [bool: cache file exists, bool: cache file not expired]
    """
    try:
        if not path.isfile(cache_file):
            return False, False
        return True, path.getmtime(cache_file) > (time() - cache_ttl)
    except OSError:  # removed in between or not accessible
        return False, False

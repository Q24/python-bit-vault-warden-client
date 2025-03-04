from os import path
from time import time
from typing import Tuple


def urljoin(*args) -> str:
    """
    Joins given arguments into an url
    """
    return "/".join(filter(None, map(lambda x: str(x).strip('/'), args)))


def cache_file_exists_and_not_expired(cache_file: str, cache_ttl: int) -> Tuple[bool, bool]:
    try:
        return path.isfile(cache_file), path.getmtime(cache_file) > (time() - cache_ttl)
    except FileNotFoundError:
        return False, False

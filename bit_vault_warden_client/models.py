# pylint: disable=invalid-name,too-many-instance-attributes
from dataclasses import dataclass, field
from enum import Enum
from os.path import join as path_join
from os.path import exists as file_exists
from tempfile import gettempdir
from uuid import getnode as get_mac
from urllib.parse import urlparse


@dataclass
class Result:
    raw_data: dict = field()
    username: str = field(default='')
    password: str = field(default='')
    notes: str = field(default='')
    totp: str = field(default='')

    def __post_init__(self):
        for k, v in self.raw_data.items():
            if hasattr(self, k) and isinstance(v, str):
                setattr(self, k, v.replace("\\\\", "\\"))

    def __iter__(self):
        yield from (self.username, self.password, self.totp)

    def astuple(self) -> tuple:
        return self.username, self.password, self.totp


@dataclass
class WardenAuthData:
    scope: str = field()
    client_id: str = field()
    grant_type: str = field()
    deviceType: int = field()
    deviceName: str = field()
    username: str = field(default=None)
    password: str = field(default=None)
    deviceIdentifier: str = field(default_factory=lambda: str(get_mac()))

    def asdict(self) -> dict:
        return self.__dict__.copy()


@dataclass(frozen=True)
class PreLoginData:
    email: str = field()

    def asdict(self) -> dict:
        return self.__dict__.copy()


class WardenCacheMode(Enum):
    AGGRESSIVE = 1
    FALLBACK = 2


@dataclass(frozen=True)
class WardenConfiguration:
    url: str = field()
    username: str = field()
    password: str = field()
    auth_data: WardenAuthData = field()
    http_proxy: str = field(default=None)
    https_proxy: str = field(default=None)
    https_cafile: str = field(default=None)
    https_verify: bool = field(default=True)
    cache_ttl: int = field(default=3600)
    cache_mode: WardenCacheMode = field(default=WardenCacheMode.AGGRESSIVE)
    cache_filename: str = field(default=None)

    def __post_init__(self):
        # set cache filename attribute by default
        if self.cache_filename is None:
            object.__setattr__(self, 'cache_filename', 'bitwarden.cache')
        # invalid filenames not to escape tempdir
        if (
            self.cache_filename.startswith(("..", "./", "/", "\\")) or
            any(s in self.cache_filename for s in [':\\', '\\..\\', '..\\'])
        ):
            raise AttributeError("Invalid cache filename")
        # validate url
        _url = urlparse(self.url)
        if all([_url.scheme, _url.netloc]) is False:
            raise AttributeError(f"Invalid URL: {self.url}")
        # verify cafile exists if specified
        if self.https_cafile and not file_exists(self.https_cafile):
            raise FileNotFoundError(self.https_cafile)

    @property
    def cache_file(self):
        return path_join(gettempdir(), self.cache_filename)

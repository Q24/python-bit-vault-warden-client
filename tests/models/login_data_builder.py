from uuid import getnode
from typing import Any
from bit_vault_warden_client.models import WardenAuthData


class LoginDataBuilder:
    __defaults = {
        "username": "user1",
        "password": "pass1",
        "scope": "api offline_access",
        "client_id": "web",
        "grant_type": "password",
        "deviceType": 9,
        "deviceName": "Bitwarden-Web-API",
        "deviceIdentifier": str(getnode())
    }

    def __init__(self):
        # instance copy, so customizing one builder does not leak into other tests
        self.__data = dict(self.__defaults)

    def build(self) -> WardenAuthData:
        return WardenAuthData(**self.__data)

    def with_field(self, key: str, value: Any) -> "LoginDataBuilder":
        self.__data[key] = value
        return self

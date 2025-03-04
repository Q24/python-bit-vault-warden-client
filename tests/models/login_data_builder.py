from uuid import getnode
from typing import Any
from bit_vault_warden_client.models import WardenAuthData


class LoginDataBuilder:
    __data = {
        "username": "user1",
        "password": "pass1",
        "scope": "api offline_access",
        "client_id": "web",
        "grant_type": "password",
        "deviceType": 9,
        "deviceName": "Bitwarden-Web-API",
        "deviceIdentifier": str(getnode())
    }

    def build(self):
        return WardenAuthData(**self.__data)

    def with_field(self, key: str, value: Any):
        self.__data[key] = value

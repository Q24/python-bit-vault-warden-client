import pytest
from uuid import getnode
from tests.models.login_data_builder import LoginDataBuilder


def test_login_data_init():
    login_data = LoginDataBuilder().build()

    assert login_data.username == "user1"
    assert login_data.password == "pass1"
    assert login_data.scope == "api offline_access"
    assert login_data.client_id == "web"
    assert login_data.grant_type == "password"
    assert login_data.deviceType == 9
    assert login_data.deviceName == "Bitwarden-Web-API"
    assert login_data.deviceIdentifier == str(getnode())  # Check the MAC address


def test_login_data_asdict():
    login_data = LoginDataBuilder().build()
    login_data_dict = login_data.asdict()

    assert login_data_dict["username"] == "user1"
    assert login_data_dict["password"] == "pass1"
    assert login_data_dict["scope"] == "api offline_access"
    assert login_data_dict["deviceName"] == "Bitwarden-Web-API"


if __name__ == '__main__':
    pytest.main()

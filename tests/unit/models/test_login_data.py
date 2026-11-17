import pytest
from uuid import getnode
from bit_vault_warden_client.models import WardenAuthData
from tests.fixtures.login_data_builder import LoginDataBuilder


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


def test_login_data_default_device_identifier():
    login_data = WardenAuthData(scope="api", client_id="web", grant_type="password", deviceType=9, deviceName="x")
    assert login_data.deviceIdentifier == str(getnode())
    assert login_data.username is None
    assert login_data.password is None


def test_login_data_builder_is_isolated():
    custom = LoginDataBuilder().with_field("username", "custom").build()
    assert custom.username == "custom"
    assert LoginDataBuilder().build().username == "user1"


def test_login_data_asdict_is_a_copy():
    login_data = LoginDataBuilder().build()
    login_data.asdict()["username"] = "changed"
    assert login_data.username == "user1"


def test_login_data_repr_does_not_expose_password():
    assert "pass1" not in repr(LoginDataBuilder().build())


if __name__ == '__main__':
    pytest.main()

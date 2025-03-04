from bit_vault_warden_client.models import PreLoginData


def test_pre_login_data_init():
    pre_login_data = PreLoginData(email="user@example.com")
    assert pre_login_data.email == "user@example.com"


def test_pre_login_data_asdict():
    pre_login_data = PreLoginData(email="user@example.com")
    pre_login_data_dict = pre_login_data.asdict()
    assert pre_login_data_dict["email"] == "user@example.com"

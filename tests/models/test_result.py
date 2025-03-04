from bit_vault_warden_client.models import Result

raw_data = {
    "username": "testuser",
    "password": "testpass",
    "totp": "123456",
}

raw_data_no_totp = {
    "username": "testuser",
    "password": "testpass",
}


def test_result_init():
    result = Result(raw_data=raw_data)
    assert result.username == "testuser"
    assert result.password == "testpass"
    assert result.totp == "123456"


def test_result_string_replacement():
    data = {
        "username": "test\\\\user",
        "password": "test\\pass",
        "totp": "123\\456",
    }
    result = Result(raw_data=data)
    assert result.username == "test\\user"
    assert result.password == "test\\pass"
    assert result.totp == "123\\456"


def test_result_iteration():
    result = Result(raw_data=raw_data)
    assert tuple(result) == ("testuser", "testpass", "123456")


def test_result_astuple():
    result = Result(raw_data=raw_data_no_totp)
    assert result.astuple() == ("testuser", "testpass", "")

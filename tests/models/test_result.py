from bit_vault_warden_client.models import Result

raw_data = {
    "username": "testuser",
    "password": "testpass",
    "totp": "123456",
}

raw_data_from_137 = {
    "login": {
        "username": "testuser",
        "password": "testpass",
        "totp": "123456",
    }
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


def test_result_init_137():
    result = Result(raw_data=raw_data_from_137)
    assert result.username == "testuser"
    assert result.password == "testpass"
    assert result.totp == "123456"


def test_result_values_are_kept_intact():
    data = {
        "username": "test\\\\user",
        "password": 'te"st\\pass\u00e9',
        "totp": "123\\456",
        "notes": "line 1\nline 2",
    }
    result = Result(raw_data=data)
    assert result.username == "test\\\\user"
    assert result.password == 'te"st\\pass\u00e9'
    assert result.totp == "123\\456"
    assert result.notes == "line 1\nline 2"


def test_result_137_notes():
    result = Result(raw_data={"name": "item", "notes": "some notes", **raw_data_from_137})
    assert result.notes == "some notes"
    assert result.astuple() == ("testuser", "testpass", "123456")


def test_result_secure_note_without_login():
    # secure notes have "login": null in the 1.37 schema
    result = Result(raw_data={"name": "item", "notes": "some notes", "login": None})
    assert result.notes == "some notes"
    assert result.astuple() == ("", "", "")


def test_result_ignores_empty_values():
    result = Result(raw_data={"username": None, "password": "", "login": {"totp": None}})
    assert result.astuple() == ("", "", "")
    assert result.notes == ""


def test_result_repr_does_not_expose_secrets():
    text = repr(Result(raw_data=raw_data_from_137))
    assert "testuser" in text
    assert "testpass" not in text
    assert "123456" not in text


def test_result_iteration():
    result = Result(raw_data=raw_data)
    assert tuple(result) == ("testuser", "testpass", "123456")


def test_result_astuple():
    result = Result(raw_data=raw_data_no_totp)
    assert result.astuple() == ("testuser", "testpass", "")

import pytest
from bit_vault_warden_client.helpers import urljoin


@pytest.mark.parametrize("args, expected", [
    (('http://example.com', 'path', 'to', 'resource'), 'http://example.com/path/to/resource'),
    (('http://example.com/', 'path/', 'to/', 'resource/'), 'http://example.com/path/to/resource'),
    (('http://example.com', '/path', '/to', '/resource'), 'http://example.com/path/to/resource'),
    (('http://example.com/', '/path', 'to/', '/resource/'), 'http://example.com/path/to/resource'),
    (('http://example.com/', '/path', '', '/resource/'), 'http://example.com/path/resource'),
    (('http://example.com/', '', ''), 'http://example.com'),
    (('http://example.com',), 'http://example.com'),
    ((), ''),
    (('http://example.com', 123, 'resource'), 'http://example.com/123/resource'),
])
def test_urljoin(args, expected):
    assert urljoin(*args) == expected


if __name__ == '__main__':
    pytest.main()

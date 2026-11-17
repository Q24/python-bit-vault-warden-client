import dataclasses
import os
from tempfile import NamedTemporaryFile, gettempdir
import pytest
from bit_vault_warden_client.models import WardenConfiguration, WardenCacheMode
from tests.fixtures.login_data_builder import LoginDataBuilder

__url = 'http://localhost'
__auth_data = LoginDataBuilder().build()


def test_configuration_init():
    subject = WardenConfiguration(url=__url, username='', password='', auth_data=__auth_data)
    assert dataclasses.is_dataclass(subject) is True
    assert subject.cache_file == os.path.join(gettempdir(), 'bitwarden.cache')


def test_configuration_defaults():
    subject = WardenConfiguration(url=__url, username='', password='', auth_data=__auth_data)
    assert subject.cache_mode == WardenCacheMode.AGGRESSIVE
    assert subject.cache_ttl == 3600
    assert subject.timeout == 30
    assert subject.https_verify is True
    assert subject.https_cafile is None
    assert subject.http_proxy is None
    assert subject.https_proxy is None


def test_configuration_is_frozen():
    subject = WardenConfiguration(url=__url, username='', password='', auth_data=__auth_data)
    with pytest.raises(dataclasses.FrozenInstanceError):
        subject.url = 'http://other'


def test_configuration_repr_does_not_expose_password():
    subject = WardenConfiguration(url=__url, username='user', password='verysecure', auth_data=__auth_data)
    assert 'verysecure' not in repr(subject)


@pytest.mark.parametrize("url", ['', 'localhost', '/path/only', 'http://'])
def test_invalid_url(url):
    with pytest.raises(AttributeError, match='Invalid URL'):
        WardenConfiguration(url=url, username='', password='', auth_data=__auth_data)


@pytest.mark.parametrize("filename", [
    '../foo.bar',
    './foo.bar',
    './../foo.bar',
    '/foo.bar',
    '..foo.bar',
    'C:\\foo.bar',
    '..\\foo.bar',
    'foo/../../bar',
    'foo/..',
    '.',
    '',
])
def test_invalid_cache_filename(filename):
    with pytest.raises(AttributeError, match='Invalid cache filename'):
        WardenConfiguration(url=__url, username='', password='', auth_data=__auth_data, cache_filename=filename)


@pytest.mark.parametrize("filename", [
    'foo',
    'foo.-.bar_.baz',
    'foo.bar',
    '.foo.bar',
    'sub/foo.bar',
])
def test_valid_cache_filename(filename):
    subject = WardenConfiguration(url=__url, username='', password='', auth_data=__auth_data, cache_filename=filename)
    assert subject.cache_file == os.path.join(gettempdir(), filename)


def test_cafile_doesnt_exist():
    with pytest.raises(FileNotFoundError, match='foo'):
        WardenConfiguration(url=__url, https_cafile='foo', username='', password='', auth_data=__auth_data)


def test_cafile_exists():
    with NamedTemporaryFile(suffix='.crt') as cafile:
        subject = WardenConfiguration(
            url=__url, https_cafile=cafile.name, username='', password='', auth_data=__auth_data
        )
        assert subject.https_cafile == cafile.name

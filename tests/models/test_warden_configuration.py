import dataclasses
import pytest
from bit_vault_warden_client.models import WardenConfiguration
from tests.models.login_data_builder import LoginDataBuilder

__url = 'http://localhost'
__auth_data = LoginDataBuilder().build()


def test_result_init():
    subject = WardenConfiguration(url=__url, username='', password='', auth_data=__auth_data)
    assert dataclasses.is_dataclass(subject) is True
    assert 'bitwarden.cache' in subject.cache_file


def test_invalid_url():
    with pytest.raises(AttributeError) as context:
        WardenConfiguration(url='', username='', password='', auth_data=__auth_data)
    assert 'Invalid URL' in repr(context)


@pytest.mark.parametrize("filename", [
    '../foo.bar',
    './foo.bar',
    './../foo.bar',
    '/foo.bar',
    '..foo.bar',
    'C:\\foo.bar',
    '..\\foo.bar',
])
def test_invalid_cache_filename(filename):
    with pytest.raises(AttributeError) as context:
        WardenConfiguration(url=__url, username='', password='', auth_data=__auth_data, cache_filename=filename)
    assert 'Invalid cache filename' in repr(context)


@pytest.mark.parametrize("filename", [
    'foo',
    'foo.-.bar_.baz',
    'foo.bar',
    '.foo.bar',
])
def test_valid_cache_filename(filename):
    subject = WardenConfiguration(url=__url, username='', password='', auth_data=__auth_data, cache_filename=filename)
    assert dataclasses.is_dataclass(subject) is True


def test_cafile_doesnt_exist():
    with pytest.raises(FileNotFoundError) as context:
        WardenConfiguration(url=__url, https_cafile='foo', username='', password='', auth_data=__auth_data)
    assert "FileNotFoundError('foo')" in repr(context)

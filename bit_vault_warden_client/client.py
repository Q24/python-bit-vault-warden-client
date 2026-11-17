from __future__ import annotations
import os
import json
import hashlib
import logging
import tempfile
from base64 import b64encode
from contextlib import suppress

import requests

from bit_vault_warden_client.errors import CredentialsError, CredentialsNotFoundError, UnsupportedEncryptionError
from bit_vault_warden_client.bcrypt import (
    BitwardenSecrets, decrypt_user_key, decrypt_string, decrypt_cipher, get_cipher_keys, get_cipher_fields
)
from bit_vault_warden_client.models import WardenConfiguration, Result, PreLoginData, WardenCacheMode
from bit_vault_warden_client.helpers import urljoin, cache_file_exists_and_not_expired

logger = logging.getLogger(__name__)


class WardenWebApi:
    config: WardenConfiguration

    def __init__(self, config: WardenConfiguration):
        self.config = config
        self.__init_session()
        logger.debug('Caching mode: %s', config.cache_mode)

    def __init_session(self):
        self._session = requests.Session()

        if self.config.https_verify is False:
            self._session.verify = self.config.https_verify
        else:
            if self.config.https_cafile:
                self._session.verify = self.config.https_cafile

        proxies = {}
        if self.config.https_proxy:
            proxies.update({"https": self.config.https_proxy})
        if self.config.http_proxy:
            proxies.update({"http": self.config.http_proxy})
        if proxies:
            logger.debug('urllib will use proxy %s', proxies)
            self._session.proxies.update(proxies)

    def close(self) -> None:
        """
        Close underlying HTTP session
        """
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_) -> None:
        self.close()

    @property
    def cache_exists(self) -> bool:
        return cache_file_exists_and_not_expired(self.config.cache_file, self.config.cache_ttl)[0]

    @property
    def cache_not_expired(self) -> bool:
        return cache_file_exists_and_not_expired(self.config.cache_file, self.config.cache_ttl)[1]

    def fetch_credentials(self, query: str) -> Result | None:
        """
        Fetch credentials by its name. Get it either from remote or from cache,
        base on 'cache mode' configuration value setting.

        :param query: credential item name
        :return: Result | None
        :raises CredentialsNotFoundError: when there is no (non-deleted) item with such name
        """
        cache_exists, cache_not_expired = cache_file_exists_and_not_expired(
            self.config.cache_file,
            self.config.cache_ttl
        )

        # try cache first, if file exists and cache ttl is not expired
        # if cache ttl is expired, fetch from remote and refresh cache
        if self.config.cache_mode == WardenCacheMode.AGGRESSIVE:
            if cache_exists:
                logger.debug('Cache file exists')
                if cache_not_expired:
                    logger.debug('Cache file is not expired')
                    return self.fetch_credentials_from_cache(query)

        # ignore remote and rely only on cache
        if self.config.cache_mode == WardenCacheMode.LOCALONLY:
            if not cache_exists:
                raise RuntimeError('Cache file does not exist')
            logger.debug('Skipping remote query, relying only on cache')
            return self.fetch_credentials_from_cache(query)

        # fetch from remote; if remote is unavailable, try cache
        try:
            return self.fetch_credentials_from_remote(query)
        except requests.exceptions.RequestException as e:
            if not self.__is_remote_unavailable(e) or not self.cache_exists:
                raise
            logger.warning('Remote not reachable (%s), trying to use cache instead.', e)
            return self.fetch_credentials_from_cache(query)

    @staticmethod
    def __is_remote_unavailable(error: requests.exceptions.RequestException) -> bool:
        """
        Network failures, timeouts and server side (5xx) errors make the remote unavailable,
        client side errors (4xx) are configuration problems and must not be masked by cache.
        """
        if isinstance(error, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            return True
        response = getattr(error, 'response', None)
        return isinstance(error, requests.exceptions.HTTPError) and response is not None \
            and response.status_code >= 500

    # pylint: disable=too-many-locals
    def fetch_credentials_from_remote(self, query: str) -> Result | None:
        """
        Fetch credentials by its name from remote and refresh the cache.
        Don't use directly unless you really know what to do. Prefer to
        use fetch_credentials()

        :param query: credential item name
        :return: Result | None
        :raises CredentialsError: when remote rejects the login
        """
        prelogin_data = PreLoginData(self.config.username)

        # Pre-Login, old
        prelogin_url = urljoin(self.config.url, "/api/accounts/prelogin")

        # pylint: disable=not-callable
        prelogin_response = self._session.post(
            url=prelogin_url,
            json=prelogin_data.asdict(),
            timeout=self.config.timeout
        )

        try:
            prelogin_response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            # noinspection unresolved-references
            if exc.response.status_code == 404:
                prelogin_url = urljoin(self.config.url, "/identity/accounts/prelogin")
                prelogin_response = self._session.post(
                    url=prelogin_url,
                    json=prelogin_data.asdict(),
                    timeout=self.config.timeout
                )
                prelogin_response.raise_for_status()

        prelogin_response_data = self.__parse_response(prelogin_response)

        # Process pre-login response
        kdfs = self.__get_value(prelogin_response_data, 'kdf', 'Kdf')  # KDF type
        kdfi = self.__get_value(prelogin_response_data, 'kdfIterations', 'KdfIterations')  # KDF iterations
        master_key = decrypt_user_key(self.config.username, self.config.password, kdfs, kdfi)
        hmac = hashlib.pbkdf2_hmac("sha256", master_key, self.config.password.encode("utf-8"), 1, dklen=32)
        session_key = b64encode(hmac).decode("utf-8")

        # Build auth data for login, without altering the configured one
        auth_data = self.config.auth_data.asdict()
        auth_data.update({"username": self.config.username, "password": session_key})

        # Login
        ident_token_url = urljoin(self.config.url, "/identity/connect/token")
        session_details_response = self._session.post(
            ident_token_url,
            data=auth_data,
            timeout=self.config.timeout
        )
        session_details_data = self.__parse_response(session_details_response, is_login=True)

        # Build secrets, reusing already derived master key
        bitwarden_secrets = BitwardenSecrets(
            email=self.config.username,
            MasterPassword=self.config.password.encode('utf-8'),
            kdfIterations=kdfi,
            ProtectedSymmetricKey=self.__get_value(session_details_data, "Key", "key"),
            ProtectedRSAPrivateKey=self.__get_value(session_details_data, "PrivateKey", "privateKey"),
            MasterKey=master_key,
        )

        # Fetch warden data
        api_sync_url = urljoin(self.config.url, "/api/sync")
        headers = {"Authorization": f"Bearer {session_details_data['access_token']}"}
        api_sync_response = self._session.get(url=api_sync_url, headers=headers, timeout=self.config.timeout)
        api_sync_response_data = self.__parse_response(api_sync_response)

        self.__write_cache({'KDFITERATIONS': kdfi, 'DATA': api_sync_response_data})

        return self.__get_result_from_data(query, api_sync_response_data, bitwarden_secrets)

    def __write_cache(self, cache_data: dict) -> None:
        """
        Atomically replace the cache file. The file is readable by the owner only,
        as it holds the (encrypted) vault and must not be exposed in a shared temp dir.
        """
        cache_file = self.config.cache_file
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=os.path.dirname(cache_file),
                prefix=os.path.basename(cache_file),
                suffix='.tmp'
            )
            try:
                with os.fdopen(fd, "w", encoding='utf8') as file:
                    file.write(json.dumps(cache_data, indent=4, sort_keys=True))
                os.replace(tmp_path, cache_file)
            except BaseException:
                with suppress(OSError):
                    os.unlink(tmp_path)
                raise
            logger.debug('Cache updated')
        except OSError as e:
            logger.warning("Could not save data to cache: %s", e)

    @staticmethod
    def __get_value(data: dict, *keys: str):
        """
        Get value by first existing key, responses differ in key casing between server versions
        """
        for key in keys:
            if key in data:
                return data[key]
        raise KeyError(keys[0])

    @staticmethod
    def __parse_response(response: requests.Response, is_login: bool = False) -> dict:
        """
        :raises CredentialsError: when login is rejected
        :raises requests.exceptions.HTTPError: on any other unsuccessful response
        """
        if is_login and response.status_code in (400, 401):
            try:
                body = response.json()
            except ValueError:
                body = {}
            reason = body.get("error_description") or body.get("message") or body.get("error") or "unknown reason"
            raise CredentialsError(f"Login failed: {reason}")
        response.raise_for_status()
        return response.json()

    def fetch_credentials_from_cache(self, query: str) -> Result | None:
        """
        Fetch credentials from cache. This will try to return Result even if cache
        is expired. Don't use directly unless you really know what to do. Prefer to
        use fetch_credentials()

        :param query: credential item name
        :return: Result | None
        :raises FileNotFoundError: when cache file does not exist
        """
        cache_exists, cache_not_expired = cache_file_exists_and_not_expired(
            self.config.cache_file,
            self.config.cache_ttl
        )
        if not cache_exists:
            raise FileNotFoundError(self.config.cache_file)

        with open(self.config.cache_file, "r", encoding='utf8') as file:
            cache_contents = json.loads(file.read())

        if not cache_not_expired:
            logger.warning('Cache is expired, yet still trying to fetch credentials from it')

        bitwarden_secrets = BitwardenSecrets(
            email=self.config.username,
            MasterPassword=self.config.password.encode('utf-8'),
            kdfIterations=int(cache_contents["KDFITERATIONS"]),
            ProtectedSymmetricKey=cache_contents["DATA"]["profile"]["key"].strip(),
            ProtectedRSAPrivateKey=cache_contents["DATA"]["profile"]["privateKey"].strip()
        )

        return self.__get_result_from_data(query, cache_contents["DATA"], bitwarden_secrets)

    @staticmethod
    def __get_result_from_data(query: str, data: dict, bitwarden_secrets: BitwardenSecrets) -> Result | None:
        """
        Find the first non-deleted item matching the query (case-insensitive) and decrypt it.
        Only item names are decrypted while searching; an item which can not be decrypted
        is skipped, so it does not prevent finding the others.
        """
        normalized_query = query.lower()

        for item in data.get("ciphers") or []:
            if item.get("deletedDate") is not None:
                continue

            encrypted_name = get_cipher_fields(item).get("name")
            if not encrypted_name:
                continue

            try:
                enc_key, mac_key = get_cipher_keys(item, data, bitwarden_secrets)
                name = decrypt_string(encrypted_name, enc_key, mac_key)
            except (CredentialsError, UnsupportedEncryptionError, ValueError) as e:
                logger.warning("Skipping item '%s', it can not be decrypted: %s", item.get("id"), e)
                continue

            if name.lower() == normalized_query:
                return Result(decrypt_cipher(item, enc_key, mac_key))

        raise CredentialsNotFoundError(f"Warden dataset does not contain valid credentials for '{query}'")

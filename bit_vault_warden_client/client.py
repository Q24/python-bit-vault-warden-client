import json
import hashlib
import logging
from typing import Optional
from base64 import b64encode

import requests

from bit_vault_warden_client.errors import CredentialsNotFoundError
from bit_vault_warden_client.bcrypt import BitwardenSecrets, decrypt_bitwarden_data, decrypt_user_key
from bit_vault_warden_client.models import WardenConfiguration, Result, PreLoginData, WardenCacheMode
from bit_vault_warden_client.helpers import urljoin, cache_file_exists_and_not_expired


class WardenWebApi:
    config: WardenConfiguration
    cache_exists: bool
    cache_not_expired: bool

    def __init__(self, config: WardenConfiguration):
        self.config = config
        self.__init_session()
        self.cache_exists, self.cache_not_expired = cache_file_exists_and_not_expired(
            config.cache_file,
            config.cache_ttl
        )
        logging.debug('Caching mode: %s', config.cache_mode)

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
            logging.debug('urllib will use proxy %s', proxies)
            self._session.proxies.update(proxies)

    def fetch_credentials(self, query: str) -> Optional[Result]:
        """
        Fetch credentials by its name. Get it either from remote or from cache,
        base on 'cache mode' configuration value setting.

        :param query: credential item name
        :return: Result | None
        """
        # try cache first, if file exists and cache ttl is not expired
        # if cache ttl is expired, fetch from remote and refresh cache
        if self.config.cache_mode == WardenCacheMode.AGGRESSIVE:
            if self.cache_exists:
                logging.debug('Cache file exists')
                if self.cache_not_expired:
                    logging.debug('Cache file is not expired')
                    return self.fetch_credentials_from_cache(query)

        # fetch from remote; if remote is unavailable, try cache
        try:
            return self.fetch_credentials_from_remote(query)
        except requests.exceptions.ConnectionError:
            logging.warning('Remote not reachable, trying to use cache instead.')
            return self.fetch_credentials_from_cache(query)

    # pylint: disable=too-many-locals
    def fetch_credentials_from_remote(self, query: str) -> Optional[Result]:
        """
        Fetch credentials by its name from remote and refresh the cache.
        Don't use directly unless you really know what to do. Prefer to
        use fetch_credentials()

        :param query: credential item name
        :return: Result | None
        """
        # Pre-Login
        prelogin_url = urljoin(self.config.url, "/api/accounts/prelogin")
        prelogin_data = PreLoginData(self.config.username)
        prelogin_response = self._session.post(url=prelogin_url, json=prelogin_data.asdict())
        prelogin_response_data = prelogin_response.json()

        # Process pre-login response
        kdfs = prelogin_response_data['kdf']  # KDF sequence
        kdfi = prelogin_response_data['kdfIterations']  # KDF iterations
        enc_key = decrypt_user_key(self.config.username, self.config.password, kdfs, kdfi)
        hmac = hashlib.pbkdf2_hmac("sha256", enc_key, self.config.password.encode("utf-8"), 1, dklen=32)
        session_key = b64encode(hmac).decode("utf-8")

        # Enrich auth data for login
        self.config.auth_data.username = self.config.username
        self.config.auth_data.password = session_key

        # Login
        ident_token_url = urljoin(self.config.url, "/identity/connect/token")
        session_details_response = self._session.post(ident_token_url, data=self.config.auth_data.asdict())
        session_details_data = session_details_response.json()

        # Build secrets
        bitwarden_secrets = BitwardenSecrets(
            email=self.config.username,
            MasterPassword=self.config.password.encode('utf-8'),
            kdfIterations=kdfi,
            ProtectedSymmetricKey=session_details_data["Key"],
            ProtectedRSAPrivateKey=session_details_data["PrivateKey"]
        )

        # Fetch warden data
        api_sync_url = urljoin(self.config.url, "/api/sync")
        headers = {"Authorization": f"Bearer {session_details_data['access_token']}"}
        api_sync_response = self._session.get(url=api_sync_url, headers=headers)
        api_sync_response_data = api_sync_response.json()

        # Write to cache
        try:
            with open(self.config.cache_file, "w", encoding='utf8') as cache_file:
                cache_data = {'KDFITERATIONS': kdfi, 'DATA': api_sync_response_data}
                cache_file.write(json.dumps(cache_data, indent=4, sort_keys=True))
                logging.debug('Cache updated')
        except Exception as e:  # pylint: disable=broad-exception-caught
            logging.warning("Could not save data to cache: %s", e)

        return self.__get_result_from_data(query, api_sync_response_data, bitwarden_secrets)

    def fetch_credentials_from_cache(self, query: str) -> Optional[Result]:
        """
        Fetch credentials from cache. This will try to return Result even if cache
        is expired. Don't use directly unless you really know what to do. Prefer to
        use fetch_credentials()

        :param query: credential item name
        :return: Result | None
        """
        if not self.cache_exists:
            raise FileNotFoundError(self.config.cache_file)

        with open(self.config.cache_file, "r", encoding='utf8') as file:
            cache_contents = json.loads(file.read())

        if not self.cache_not_expired:
            logging.warning('Cache is expired, yet still trying to fetch credentials from it')

        bitwarden_secrets = BitwardenSecrets(
            email=self.config.username,
            MasterPassword=self.config.password.encode('utf-8'),
            kdfIterations=int(cache_contents["KDFITERATIONS"]),
            ProtectedSymmetricKey=cache_contents["DATA"]["profile"]["key"].strip(),
            ProtectedRSAPrivateKey=cache_contents["DATA"]["profile"]["privateKey"].strip()
        )

        return self.__get_result_from_data(query, cache_contents["DATA"], bitwarden_secrets)

    @staticmethod
    def __get_result_from_data(query: str, data: dict, bitwarden_secrets: BitwardenSecrets) -> Optional[Result]:
        decrypted_data = decrypt_bitwarden_data(data, bitwarden_secrets)

        for item in json.loads(decrypted_data)["ciphers"]:
            if item["data"]["name"].lower() == query.lower():
                if "deletedDate" not in item or item["deletedDate"] is None:
                    return Result(item["data"])

        raise CredentialsNotFoundError(f"Warden dataset does not contain valid credentials for '{query}'")

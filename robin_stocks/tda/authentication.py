from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet
from robin_stocks._secure_storage import (delete_private_file,
                                          ensure_private_directory,
                                          load_private_json,
                                          write_private_json)
from robin_stocks.tda.globals import CACHE_NAME, DATA_DIR_NAME, LEGACY_CACHE_NAME
from robin_stocks.tda.helper import (request_data, set_login_state,
                                     update_session)
from robin_stocks.tda.urls import URLS


def _data_dir():
    return Path.home().joinpath(DATA_DIR_NAME)


def _cache_path():
    return _data_dir().joinpath(CACHE_NAME)


def _legacy_cache_path():
    return _data_dir().joinpath(LEGACY_CACHE_NAME)


def _serialize_cache(cipher_suite, client_id, authorization_token, refresh_token,
                     authorization_timestamp, refresh_timestamp):
    return {
        'authorization_token': cipher_suite.encrypt(authorization_token.encode()).decode(),
        'refresh_token': cipher_suite.encrypt(refresh_token.encode()).decode(),
        'client_id': cipher_suite.encrypt(client_id.encode()).decode(),
        'authorization_timestamp': authorization_timestamp.isoformat(),
        'refresh_timestamp': refresh_timestamp.isoformat(),
    }


def _write_cache(cache_path, cipher_suite, client_id, authorization_token,
                 refresh_token, authorization_timestamp, refresh_timestamp):
    ensure_private_directory(cache_path.parent)
    write_private_json(
        cache_path,
        _serialize_cache(
            cipher_suite,
            client_id,
            authorization_token,
            refresh_token,
            authorization_timestamp,
            refresh_timestamp,
        ),
    )


def _load_cache(cache_path, cipher_suite):
    cache_data = load_private_json(
        cache_path,
        required_keys=(
            'authorization_token',
            'refresh_token',
            'client_id',
            'authorization_timestamp',
            'refresh_timestamp',
        ),
    )

    return {
        'access_token': cipher_suite.decrypt(
            cache_data['authorization_token'].encode()).decode(),
        'refresh_token': cipher_suite.decrypt(
            cache_data['refresh_token'].encode()).decode(),
        'client_id': cipher_suite.decrypt(cache_data['client_id'].encode()).decode(),
        'authorization_timestamp': datetime.fromisoformat(
            cache_data['authorization_timestamp']),
        'refresh_timestamp': datetime.fromisoformat(cache_data['refresh_timestamp']),
    }


def clear_cache():
    """Deletes stored TD Ameritrade session material from disk."""
    cleared = False
    for path in (_cache_path(), _legacy_cache_path()):
        if path.exists():
            delete_private_file(path)
            cleared = True
    return cleared


def login_first_time(encryption_passcode, client_id, authorization_token, refresh_token):
    """ Stores log in information in a private JSON cache on the computer. After being used once,
    user can call login() to automatically read in information from that cache and refresh
    authorization tokens when needed.

    :param encryption_passcode: Encryption key created by generate_encryption_passcode().
    :type encryption_passcode: str
    :param client_id: The Consumer Key for the API account.
    :type client_id: str
    :param authorization_token: The authorization code returned from post request to https://developer.tdameritrade.com/authentication/apis/post/token-0
    :type authorization_token: str
    :param refresh_token: The refresh code returned from post request to https://developer.tdameritrade.com/authentication/apis/post/token-0
    :type refresh_token: str

    """
    if type(encryption_passcode) is str:
        encryption_passcode = encryption_passcode.encode()
    cipher_suite = Fernet(encryption_passcode)
    _write_cache(
        _cache_path(),
        cipher_suite,
        client_id,
        authorization_token,
        refresh_token,
        datetime.now(),
        datetime.now(),
    )


def login(encryption_passcode):
    """ Set the authorization token so the API can be used. Gets a new authorization token
    every 30 minutes using the refresh token. Gets a new refresh token every 60 days.

    :param encryption_passcode: Encryption key created by generate_encryption_passcode().
    :type encryption_passcode: str
    
    """
    if type(encryption_passcode) is str:
        encryption_passcode = encryption_passcode.encode()
    cipher_suite = Fernet(encryption_passcode)
    cache_path = _cache_path()
    if not cache_path.exists():
        if _legacy_cache_path().exists():
            raise FileExistsError(
                "Legacy insecure TDA pickle cache detected. "
                "Delete {0} and call login_first_time() again so a JSON cache can be created.".format(
                    _legacy_cache_path()
                )
            )
        raise FileExistsError(
            "Please Call login_first_time() to create the encrypted JSON cache file.")

    cache_data = _load_cache(cache_path, cipher_suite)
    access_token = cache_data['access_token']
    refresh_token = cache_data['refresh_token']
    client_id = cache_data['client_id']
    authorization_timestamp = cache_data['authorization_timestamp']
    refresh_timestamp = cache_data['refresh_timestamp']
    # Authorization tokens expire after 30 mins. Refresh tokens expire after 90 days,
    # but you need to request a fresh authorization and refresh token before it expires.
    authorization_delta = timedelta(seconds=1800)
    refresh_delta = timedelta(days=60)
    url = URLS.oauth()
    # If it has been longer than 60 days. Get a new refresh and authorization token.
    # Else if it has been longer than 30 minutes, get only a new authorization token.
    if (datetime.now() - refresh_timestamp > refresh_delta):
        payload = {
            "grant_type": "refresh_token",
            "access_type": "offline",
            "refresh_token": refresh_token,
            "client_id": client_id
        }
        data, _ = request_data(url, payload, True)
        if "access_token" not in data and "refresh_token" not in data:
            raise ValueError(
                "Refresh token is no longer valid. Call login_first_time() to get a new refresh token.")
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]
        _write_cache(
            cache_path,
            cipher_suite,
            client_id,
            access_token,
            refresh_token,
            datetime.now(),
            datetime.now(),
        )
    elif (datetime.now() - authorization_timestamp > authorization_delta):
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id
        }
        data, _ = request_data(url, payload, True)
        if "access_token" not in data:
            raise ValueError(
                "Refresh token is no longer valid. Call login_first_time() to get a new refresh token.")
        access_token = data["access_token"]
        _write_cache(
            cache_path,
            cipher_suite,
            client_id,
            access_token,
            refresh_token,
            datetime.now(),
            refresh_timestamp,
        )
    # Store authorization token in session information to be used with API calls.
    auth_token = "Bearer {0}".format(access_token)
    update_session("Authorization", auth_token)
    update_session("apikey", client_id)
    set_login_state(True)
    return auth_token


def generate_encryption_passcode():
    """ Returns an encryption key to be used for logging in.

    :returns: Returns a byte object to be used with cryptography.

    """
    return Fernet.generate_key().decode()

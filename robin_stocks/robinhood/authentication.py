import getpass
import os
import secrets
import time
from pathlib import Path

from robin_stocks._secure_storage import (delete_private_file,
                                          ensure_private_directory,
                                          load_private_json,
                                          write_private_json)
from robin_stocks.robinhood.helper import *
from robin_stocks.robinhood.urls import *

CACHE_SUFFIX = ".json"
LEGACY_CACHE_SUFFIX = ".pickle"
_CACHE_KEYS = ("access_token", "device_token", "refresh_token", "token_type")


def _resolve_cache_dir(pickle_path=""):
    if pickle_path:
        cache_dir = Path(pickle_path)
        if not cache_dir.is_absolute():
            cache_dir = Path.cwd().joinpath(cache_dir)
        return cache_dir
    return Path.home().joinpath(".tokens")


def _resolve_cache_paths(pickle_path="", pickle_name=""):
    cache_dir = _resolve_cache_dir(pickle_path)
    cache_stem = "robinhood" + pickle_name
    cache_path = cache_dir.joinpath(cache_stem + CACHE_SUFFIX)
    legacy_cache_path = cache_dir.joinpath(cache_stem + LEGACY_CACHE_SUFFIX)
    return cache_path, legacy_cache_path


def _warn_on_legacy_cache(legacy_cache_path):
    if legacy_cache_path.exists():
        print(
            "WARNING: Ignoring legacy insecure session cache {0}. "
            "Log in again to create a JSON cache or delete the file manually.".format(
                legacy_cache_path.name
            ),
            file=get_output(),
        )


def _load_cached_session(cache_path):
    cache_data = load_private_json(cache_path, required_keys=_CACHE_KEYS)
    for key in _CACHE_KEYS:
        if not isinstance(cache_data[key], str):
            raise ValueError(
                "Cached Robinhood session value {0} must be stored as a string.".format(
                    key
                )
            )
    return cache_data


def _write_cached_session(cache_path, token_type, access_token, refresh_token, device_token):
    ensure_private_directory(cache_path.parent)
    write_private_json(
        cache_path,
        {
            "token_type": token_type,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "device_token": device_token,
        },
    )


def clear_stored_session(pickle_path="", pickle_name=""):
    """Deletes stored Robinhood session material from disk."""
    cache_path, legacy_cache_path = _resolve_cache_paths(pickle_path, pickle_name)
    cleared = False

    for path in (cache_path, legacy_cache_path):
        if path.exists():
            delete_private_file(path)
            cleared = True

    return cleared

def generate_device_token():
    """Generates a cryptographically secure device token."""
    rands = [secrets.randbelow(256) for _ in range(16)]
    hexa = [str(hex(i + 256)).lstrip("0x")[1:] for i in range(256)]
    token = ""
    for i, r in enumerate(rands):
        token += hexa[r]
        if i in [3, 5, 7, 9]:
            token += "-"
    return token


def _get_sherrif_id(data):
    """Extracts the sheriff verification ID from the response."""
    if "id" in data:
        return data["id"]
    raise Exception("Error: No verification ID returned in user-machine response")


def _validate_sherrif_id(device_token: str, workflow_id: str):
    """Handles Robinhood's verification workflow, including email, SMS, and app-based approvals."""
    print("Starting verification process...")
    pathfinder_url = "https://api.robinhood.com/pathfinder/user_machine/"
    machine_payload = {'device_id': device_token, 'flow': 'suv', 'input': {'workflow_id': workflow_id}}
    machine_data = request_post(url=pathfinder_url, payload=machine_payload, json=True)

    machine_id = _get_sherrif_id(machine_data)
    inquiries_url = f"https://api.robinhood.com/pathfinder/inquiries/{machine_id}/user_view/"

    start_time = time.time()
    
    while time.time() - start_time < 120:  # 2-minute timeout
        time.sleep(5)
        inquiries_response = request_get(inquiries_url)

        if not inquiries_response:  # Handle case where response is None
            print("Error: No response from Robinhood API. Retrying...")
            continue

        if "context" in inquiries_response and "sheriff_challenge" in inquiries_response["context"]:
            challenge = inquiries_response["context"]["sheriff_challenge"]
            challenge_type = challenge["type"]
            challenge_status = challenge["status"]
            challenge_id = challenge["id"]
            if challenge_type == "prompt":
                print("Check robinhood app for device approvals method...")
                prompt_url = f"https://api.robinhood.com/push/{challenge_id}/get_prompts_status/"
                while True:
                    time.sleep(5)
                    prompt_challenge_status = request_get(url=prompt_url)
                    if prompt_challenge_status["challenge_status"] == "validated":
                        break
                break

            if challenge_status == "validated":
                print("Verification successful!")
                break  # Stop polling once verification is complete

            if challenge_type in ["sms", "email"] and challenge_status == "issued":
                user_code = input(f"Enter the {challenge_type} verification code sent to your device: ")
                challenge_url = f"https://api.robinhood.com/challenge/{challenge_id}/respond/"
                challenge_payload = {"response": user_code}
                challenge_response = request_post(url=challenge_url, payload=challenge_payload)

                if challenge_response.get("status") == "validated":
                    break

    # **Now poll the workflow status to confirm final approval**
    inquiries_url = f"https://api.robinhood.com/pathfinder/inquiries/{machine_id}/user_view/"
    
    retry_attempts = 5  # Allow up to 5 retries in case of 500 errors
    while time.time() - start_time < 120:  # 2-minute timeout 
        try:
            inquiries_payload = {"sequence": 0, "user_input": {"status": "continue"}}
            inquiries_response = request_post(url=inquiries_url, payload=inquiries_payload,json=True)
            if "type_context" in inquiries_response and inquiries_response["type_context"]["result"] == "workflow_status_approved":
                print("Verification successful!")
                return
            else:
                time.sleep(5)  # **Increase delay between requests to prevent rate limits**
        except requests.exceptions.RequestException as e:
            time.sleep(5)
            print(f"API request failed: {e}")
            retry_attempts -= 1
            if retry_attempts == 0:
                raise TimeoutError("Max retries reached. Assuming login approved and proceeding.")
            print("Retrying workflow status check...")
            continue

        if not inquiries_response:  # Handle None response
            time.sleep(5)
            print("Error: No response from Robinhood API. Retrying...")
            retry_attempts -= 1
            if retry_attempts == 0:
                raise TimeoutError("Max retries reached. Assuming login approved and proceeding.")
            continue

        workflow_status = inquiries_response.get("verification_workflow", {}).get("workflow_status")

        if workflow_status == "workflow_status_approved":
            print("Workflow status approved! Proceeding with login...")
            return
        elif workflow_status == "workflow_status_internal_pending":
            print("Still waiting for Robinhood to finalize login approval...")
        else:
            retry_attempts -= 1
            if retry_attempts == 0:
                raise TimeoutError("Max retries reached. Assuming login approved and proceeding.")

    raise TimeoutError("Timeout reached. Assuming login is approved and proceeding.")



def login(username=None, password=None, expiresIn=86400, scope='internal', store_session=False, mfa_code=None, pickle_path="", pickle_name=""):
    """Handles the login process to Robinhood, including multi-factor authentication, session persistence, and verification handling."""
    print("Starting login process...")
    device_token = generate_device_token()
    cache_path, legacy_cache_path = _resolve_cache_paths(pickle_path, pickle_name)
    creds_file = cache_path.name

    url = login_url()
    login_payload = {
        'client_id': 'c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS',
        'expires_in': expiresIn,
        'grant_type': 'password',
        'password': password,
        'scope': scope,
        'username': username,
        'device_token': device_token,
        'try_passkeys': False,
        'token_request_path': '/login',
        'create_read_only_secondary_token': True,
    }

    if mfa_code:
        login_payload['mfa_code'] = mfa_code

    if store_session and cache_path.exists():
        try:
            cache_data = _load_cached_session(cache_path)
            access_token = cache_data['access_token']
            token_type = cache_data['token_type']
            refresh_token = cache_data['refresh_token']
            login_payload['device_token'] = cache_data['device_token']
            set_login_state(True)
            update_session('Authorization', '{0} {1}'.format(token_type, access_token))
            res = request_get(
                positions_url(), 'pagination', {'nonzero': 'true'}, jsonify_data=False
            )
            res.raise_for_status()
            return {
                'access_token': access_token,
                'token_type': token_type,
                'expires_in': expiresIn,
                'scope': scope,
                'detail': 'logged in using authentication in {0}'.format(creds_file),
                'backup_code': None,
                'refresh_token': refresh_token,
            }
        except Exception as exc:
            print(
                "ERROR: Could not load stored Robinhood session from {0}: {1}. "
                "Logging in normally.".format(creds_file, exc),
                file=get_output(),
            )
            set_login_state(False)
            update_session('Authorization', None)
    elif store_session:
        _warn_on_legacy_cache(legacy_cache_path)

    # **Attempt to login normally**
    if not username:
        username = input("Robinhood username: ")
        login_payload['username'] = username
    if not password:
        password = getpass.getpass("Robinhood password: ")
        login_payload['password'] = password

    data = request_post(url, login_payload)

    if data:
        try:
            if 'verification_workflow' in data:
                print("Verification required, handling challenge...")
                workflow_id = data['verification_workflow']['id']
                _validate_sherrif_id(device_token, workflow_id)

                # Reattempt login after verification
                data = request_post(url, login_payload)

            if 'access_token' in data:
                token = '{0} {1}'.format(data['token_type'], data['access_token'])
                update_session('Authorization', token)
                set_login_state(True)

            if store_session:
                _write_cached_session(
                    cache_path,
                    data['token_type'],
                    data['access_token'],
                    data['refresh_token'],
                    login_payload['device_token'],
                )
            return data
        except Exception as e:
            print(f"Error during login verification: {e}")

    print("Login failed. Check credentials and try again.")
    return None


@login_required
def logout(clear_cache=False, pickle_path="", pickle_name=""):
    """Logs out from Robinhood by clearing session data."""
    set_login_state(False)
    update_session('Authorization', None)
    if clear_cache:
        clear_stored_session(pickle_path=pickle_path, pickle_name=pickle_name)
    print("Logged out successfully.")

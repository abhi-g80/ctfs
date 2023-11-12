# Socket client to connect and solve 500 addition problems
# and retrieve the flag.

import re
import socket
import time
import argparse


RE_PROB = r"What is the answer to (\d+) \+ (\d+)?"
RE_FLAG = r"(247CTF\{\w+\})"

sym = ["-", "\\", "|", "/"]


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple socket client for solving 500 addition problems",
    )
    parser.add_argument("host", metavar="host")
    parser.add_argument(
        "-p",
        "--port",
        metavar="port",
        help="port to connect on (default: %(default)s)",
        default=50500,
    )
    parser.add_argument(
        "-s",
        "--sleep",
        metavar="sleep",
        help="sleep between each request (default: %(default)s)",
        default=1,
    )
    args = parser.parse_args()
    return args


def run_client(addr: str, port: int, sleep: float, buffer: int = 1024) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((addr, port))
        c = 0
        flag = "no flag found"
        while True:
            print(f"solving problems {sym[c%4]}", end="\r")
            c += 1
            data = s.recv(buffer)
            match_ = re.search(RE_FLAG, data.decode("utf-8"))
            if match_:
                # flag found
                flag = match_.groups()[0]
                break
            match_ = re.search(RE_PROB, data.decode("utf-8"))
            if match_:
                # prob found
                sum_ = str(int(match_.groups()[0]) + int(match_.groups()[1]))
                s.send((sum_ + "\r\n").encode("utf-8"))
            time.sleep(sleep)
        return flag


if __name__ == "__main__":
    args = parser()
    flag = run_client(args.host, args.port, float(args.sleep))
    print(f"\033[Kflag: {flag}")

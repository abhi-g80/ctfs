# Socket client to solve the an impossible number challenge
#
# Run as follows:
#
# poetry run python main.py <host> -p <port>

import socket
import argparse


KEY = 2147483647


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple socket client for solving the `an impossible number` challenge",
    )
    parser.add_argument("host", metavar="host")
    parser.add_argument(
        "-p",
        "--port",
        metavar="port",
        help="port to connect on (default: %(default)s)",
        default=50468,
    )
    args = parser.parse_args()
    return args


def run_client(addr: str, port: int, buffer: int = 1024) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((addr, port))
        s.send(f"{KEY}\r\n".encode("utf-8"))
        data = s.recv(buffer)
        if "CTF" in data.decode("UTF-8"):
            return data.decode("utf-8")
        return "flag not found"


if __name__ == "__main__":
    args = parser()
    flag = run_client(args.host, args.port)
    print(f"\033[Kflag: {flag}")

# Python script to find the flag hidden in the binary
#
# Run as follows:
#
# poetry run python main.py <binary filename>
#
# The idea is to keep a buffer of length 6 and try to match the
# string '247CTF'. Once found, keep reading into a ans string
# until we hit a '}'. That is the flag we want.

import argparse
from collections import deque


FLAG_HEADER = "247CTF"


def solve(filename: str) -> None:
    with open(filename, mode="rb") as f:
        content = f.read()
    window = len(FLAG_HEADER)
    w = deque()
    ans = ""
    flag = False
    for idx in range(len(content)):
        if content[idx] == 0:  # ignore nulls
            continue
        w.append(content[idx])
        if flag:
            ans += chr(content[idx])
            if ans[-1] == "}":
                print(f"Flag: {FLAG_HEADER}{ans}")
                break
        while len(w) > window:
            w.popleft()
        if len(w) == window:
            s = "".join([chr(i) for i in w])
            if s == FLAG_HEADER:
                flag = True


def solve_with_bytes(filename: str) -> None:
    with open(filename, mode="rb") as f:
        content = f.read()

    filtered = bytes(b for b in content if b != 0)
    header = FLAG_HEADER.encode()
    header_idx = filtered.find(header)
    if header_idx == -1:
        print("Flag not found")
        return
    start = header_idx - len(header)
    end = filtered.find(b"}", start)
    if end == -1:
        print(f"Flag is malformed, start: {start}")
    flag = filtered[start : end + 1].decode(errors="ignore")
    print("Flag: ", flag)


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Python script to find flag in the binary for 'the more the merrier' challenge",
    )
    parser.add_argument("binary", metavar="binary_name")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parser()
    solve(args.binary)
    solve_with_bytes(args.binary)

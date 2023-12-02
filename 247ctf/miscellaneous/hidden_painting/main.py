# Python script to plot and save a file containing flag
#
# Run as follows:
#
# poetry run python main.py <path to secret_map.txt> --save <path to output file>

import io
import matplotlib.pyplot as plt
import argparse


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Python script to plot and save a file containing flag",
    )
    parser.add_argument("file", metavar="secret_map", type=argparse.FileType("r"))
    parser.add_argument(
        "--save",
        metavar="file",
        help="save output (default: %(default)s)",
        default="output.png",
    )
    args = parser.parse_args()
    return args


def run(secrets_file: io.TextIOWrapper, save_file: str) -> None:
    print(f"{type(secrets_file)}")
    contents = [c.strip("\n").split() for c in secrets_file.readlines()]
    coordinates = [(int(c[0], 0), int(c[1], 0)) for c in contents]
    print(f"total coordinates: {len(coordinates)}")
    plt.rcParams["figure.figsize"] = [10, 120]
    plt.rcParams["font.size"] = 1
    x, y = zip(*coordinates)
    plt.scatter(x, y)
    plt.savefig(save_file, bbox_inches="tight")


if __name__ == "__main__":
    args = parser()
    run(args.file, args.save)
    print(f"\033[Kflag: saved at {args.save}")

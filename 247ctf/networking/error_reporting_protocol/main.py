# Read ICMP payload from pcapfile and retrieve the flag
# Flag is present in the jpeg file

import argparse

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP


SENDFLAG = "Send the flag!"


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read and extract ICMP payload from pcap",
    )
    parser.add_argument("pcap", metavar="pcap")
    parser.add_argument(
        "--ofile",
        metavar="output file",
        help="output file to write (default: %(default)s)",
        default="output.jpeg",
    )
    args = parser.parse_args()
    return args


def write(name: str, bytes_: bytes):
    with open(name, "wb") as fn:
        fn.write(bytes_) 


def process_pcap(pcapfile: str) -> bytes:
    flag = False
    cap_bytes = b""
    inc_src, inc_dst = "", ""
    for (pkt_data, _) in RawPcapReader(pcapfile):
        ether_pkt = Ether(pkt_data)
        if not ether_pkt.haslayer(ICMP):
            continue
        ip = ether_pkt[IP]
        icmp = ether_pkt[ICMP]
        if flag and ip.src == inc_src and ip.dst == inc_dst:
            cap_bytes += icmp.payload.load
        if icmp.payload.load == bytes(SENDFLAG.encode("utf-8")):
            inc_src = ip.dst
            inc_dst = ip.src
            flag = True
            continue
    return cap_bytes


def main(pcapfile: str, outfile: str) -> None:
    print(f"Reading and extracting data from: {pcapfile}") 
    bytes_from_pcap = process_pcap(pcapfile)

    print(f"Captured {len(bytes_from_pcap)} bytes")
    print(f"Writing to file: {outfile}")
    write(outfile, bytes_from_pcap)

    print("Done!")


if __name__ == "__main__":
    args = parser()
    main(args.pcap, args.ofile)

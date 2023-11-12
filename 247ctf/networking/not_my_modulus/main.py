# Get the public certificate exchanged in pcap and match
# the modulus with the list of available private keys

import os
import argparse

from collections import namedtuple

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP
from scapy.layers.tls.handshake import TLSCertificate
from scapy.layers.tls.record import TLS

from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import FILETYPE_PEM


PacketData = namedtuple("PacketData", "data metadata")


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract and match pub/priv certificates",
    )
    parser.add_argument("pcap", metavar="pcap", help="pcap file containing pub key")
    parser.add_argument(
        "path", metavar="path", help="folder path containing private keys"
    )
    parser.add_argument(
        "--file",
        metavar="<filename>",
        help="output file to write (default: %(default)s)",
        default="cert.pem",
    )
    args = parser.parse_args()
    return args


def get_public_key_modulus(key: bytes) -> int:
    cert = load_certificate(FILETYPE_PEM, key)
    return cert.get_pubkey().to_cryptography_key().public_numbers().n  # type: ignore


def get_private_key_modulus(key: bytes) -> int:
    pkey = load_privatekey(FILETYPE_PEM, key)
    return pkey.to_cryptography_key().private_numbers()._public_numbers.n  # type: ignore


def get_cert_bytes(packets: list[PacketData]) -> bytes:
    cert_bytes = b""
    for packet in packets:
        pkt = packet.data
        if not TCP in pkt:
            continue
        if len(pkt[TCP].payload) == 0:
            continue
        tls_layer = TLS(pkt[TCP].load)
        if TLSCertificate in tls_layer:
            cert_bytes = tls_layer[TLSCertificate].certs[0][1].pem
            break
    return cert_bytes


def find_matching_private_key(path: str, pub_mod: int):
    matching_prv_key_file = "no such private key file found"
    for file in os.listdir(path):
        if file.endswith(".key"):
            keyfile = f"{path}/{file}"
            with open(keyfile, "rb") as f:
                file_bytes = f.read()
                prv_mod = get_private_key_modulus(file_bytes)
                if prv_mod == pub_mod:
                    # found
                    matching_prv_key_file = keyfile
    return matching_prv_key_file


def main(pcap: str, path: str) -> None:
    print(f"Reading from pcap file: {pcap} and keys: {path}")
    packets = [PacketData(Ether(d), m) for d, m in RawPcapReader(pcap)]
    cert = get_cert_bytes(packets)
    print(f"Extracted cert of length: {len(cert)}")
    pub_mod = get_public_key_modulus(cert)
    print(f"Public key modulus: {pub_mod:x}")
    print("Finding matching key file...")
    file = find_matching_private_key(path, pub_mod)
    print(f"Matching private key file: {file}")


if __name__ == "__main__":
    args = parser()
    main(args.pcap, args.path)

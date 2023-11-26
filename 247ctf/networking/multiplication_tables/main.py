# Get the public certificate exchanged in pcap and match
# the modulus with the list of available private keys
#
# Run as follows:
#
# poetry run main.py multiplication_tables.pcap -f ./myprivatekey.pem
#
# Then run tshark to get the flag:
#
# tshark -r multiplication_tables.pcap -o "tls.keys_list: <ip>,<port>,http,myprivatekey.pem -z "follow,ssl,ascii,1"

import argparse

from collections import namedtuple

import requests

from Crypto.PublicKey import RSA

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP
from scapy.layers.tls.handshake import TLSCertificate
from scapy.layers.tls.record import TLS

from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import FILETYPE_PEM


PacketData = namedtuple("PacketData", "data metadata")
RSApq = namedtuple("RSApq", "p q")


FACTORDB_API = "http://factordb.com/api"


def get_packets(pcap: str) -> list[PacketData]:
    return [PacketData(Ether(d), m) for d, m in RawPcapReader(pcap)]


def invmod(x: int, m: int) -> int:
    a, b, u = 0, m, 1
    while x > 0:
        x, a, b, u = b % x, u, x, a - (b // x) * u
    # if b == 1:
    #     return a%m
    return a % m if b == 1 else a


def get_factors(n: int) -> RSApq:
    response = requests.get(FACTORDB_API, params={"query": n})
    response.raise_for_status()

    factors = response.json()["factors"]
    return RSApq(int(factors[0][0]), int(factors[1][0]))


def create_priv_key(n: int, e: int, d: int, p: int, q: int) -> RSA.RsaKey:
    return RSA.construct((n, e, d, p, q))


def get_phi(p: int, q: int) -> int:
    if p == q:
        return p * p - p
    return (p - 1) * (q - 1)


def write_bytes_to_file(filename: str, b: bytes) -> None:
    with open(filename, "wb") as f:
        f.write(b)


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract public key from pcap and try to create private key",
    )
    parser.add_argument("pcap", metavar="pcap", help="pcap file containing pub key")
    parser.add_argument(
        "--file",
        metavar="file",
        help="dump private key file (default: %(default)s)",
        default="privatekey.pem",
    )
    args = parser.parse_args()
    return args


def get_public_key_exponent(key: bytes) -> int:
    cert = load_certificate(FILETYPE_PEM, key)
    return cert.get_pubkey().to_cryptography_key().public_numbers().e  # type: ignore


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


def main(pcap: str, filename: str) -> None:
    print(f"Reading from pcap file: {pcap}")

    packets = get_packets(pcap)
    cert = get_cert_bytes(packets)

    print(f"Extracted cert of length: {len(cert)}")

    pub_mod = get_public_key_modulus(cert)

    print(f"Public key modulus of length: {len(str(pub_mod))}")

    exponent = get_public_key_exponent(cert)

    print(f"Public key exponent: {exponent}")
    print("Trying to fetch factors from factordb API...")

    r = get_factors(pub_mod)

    print(f"Factors length: {len(str(r.p))} and {len(str(r.q))}")

    phi = get_phi(r.p, r.q)
    d = invmod(exponent, phi)

    print(f"RSA d length: {len(str(d))}")
    print("Creating Private key")

    rsa_key = create_priv_key(pub_mod, exponent, d, r.p, r.q)

    print(f"Writing private key to file: {filename}")

    write_bytes_to_file(filename, rsa_key.export_key())

    print("Done!")


if __name__ == "__main__":
    args = parser()
    main(args.pcap, args.file)

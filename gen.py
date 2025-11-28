#!/usr/bin/env python3
import argparse
import hashlib
import hmac

parser = argparse.ArgumentParser()
parser.add_argument("-m", dest="hashname", type=str, default="md5", help="Hash algorithm")
parser.add_argument("-p", dest="password", type=str, required=True, help="Password")
args = parser.parse_args()

Ci = bytes.fromhex("a0613ec7445c462a13f6ffbba65085fe")
Ni = bytes.fromhex("9ad2da7c2b87fe3b4dfcc422d35ea86e7cedadebc653e58df84d0e55ffd51b72")
g_x = bytes.fromhex(
    "ee75ea8fbe83f87fde2d83700a9c6f6808af36f84147babd38dccf1000f7d82f"
    "433bd6f49d1a4d974a8c2f2537bcf5cf9d8732c22da7da98650895585276c317"
    "ebdcab2f1049843c22519f1f107a3b99005e428a9517c299cf373e3438d31358"
    "e222f2a9e150cc3da9d50090f4c4d2800a07680de75c1ef5a3096079b56d78c0"
)
Cr = bytes.fromhex("baf00945c9f5796ca2ebe3c8e492b4b4")
Nr = bytes.fromhex("6476695c1cc3cc35f641c924faa57696804e809f4101b618426ca10c7edd41a3")
g_y = bytes.fromhex(
    "2478d31ad28bce3f62a30dfe8209f61ce1939894c33978bcee7768fe7e0218b2"
    "e8123a389c5647bdf242495baf8862ef19693b9f5c32b33ae9d1a4c2f29ec9255"
    "4ab4bcc58653b10956a277dd78661b14006abd63e334e186e7db7d1f39ac2427c"
    "32200c9d36bc8dd7ac2a3364d6c13ff7b6a2086961f0048ae7ae919d624520"
)
SAi = bytes.fromhex("2cc74410c9e829d3d9c1f02190140372")
IDr = bytes.fromhex("3e6ce2b75b609e9295946bdf8e8569a4")

EXPECTED_HASH = bytes.fromhex("6711fab905453ab664c9ebe1dbe135b329f4f0ef")

DATA1 = Ni + Nr
DATA2 = g_y + g_x + Cr + Ci + SAi + IDr

def digest_factory(name):
    return lambda: hashlib.new(name)

skeyid = hmac.new(args.password.encode(), DATA1, digest_factory(args.hashname)).digest()

HASH = hmac.new(skeyid, DATA2, digest_factory(args.hashname)).digest()

out = "*".join(map(lambda x: x.hex(), [Ni, Nr, g_x, g_y, Ci, Cr, SAi, IDr, HASH]))
print(out)

with open("test.txt", "w", encoding="utf-16") as f:
    f.write(out)

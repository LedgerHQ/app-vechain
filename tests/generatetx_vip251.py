# pyenv local 3.10
# Generates an APDU for a VIP-251 (Galactica / EIP-1559-style) VeChain transaction
# and prints both the raw RLP and the SIGN APDU for use with Speculos.
#
# Run with: /tmp/vechain-tx-venv/bin/python tests/generatetx_vip251.py
import argparse
from enum import IntEnum

from thor_devkit.cry import blake2b256, secp256k1
from thor_devkit.rlp import (
    BlobKind,
    BytesKind,
    ComplexCodec,
    CompactFixedBlobKind,
    DictWrapper,
    HomoListWrapper,
    NoneableFixedBlobKind,
    NumericKind,
)

# VIP-251 transaction prefix byte (TransactionType = 0x51)
VIP251_TYPE_PREFIX = 0x51

# Mirror of EIP1559_RLP_FIELDS in vechain-sdk-js
# (packages/core/src/transaction/Transaction.ts)
_params_vip251 = [
    ("chainTag", NumericKind(1)),
    ("blockRef", CompactFixedBlobKind(8)),
    ("expiration", NumericKind(4)),
    (
        "clauses",
        HomoListWrapper(
            codec=DictWrapper(
                [
                    ("to", NoneableFixedBlobKind(20)),
                    ("value", NumericKind(32)),
                    ("data", BlobKind()),
                ]
            )
        ),
    ),
    ("maxPriorityFeePerGas", NumericKind(32)),
    ("maxFeePerGas", NumericKind(32)),
    ("gas", NumericKind(8)),
    ("dependsOn", NoneableFixedBlobKind(32)),
    ("nonce", NumericKind(8)),
    ("reserved", HomoListWrapper(codec=BytesKind())),
]
VIP251Codec = ComplexCodec(DictWrapper(_params_vip251))

CLA = 0xE0
MAX_APDU_LEN = 255


class P1(IntEnum):
    P1_START = 0x00
    P1_MORE = 0x80


class P2(IntEnum):
    P2_LAST = 0x00


class InsType(IntEnum):
    INS_SIGN = 0x04


def get_packed_path_bytes(path: str) -> bytes:
    components = path.split("/")
    packed = bytearray()
    for c in components:
        if c.startswith("m"):
            continue
        idx = int(c[:-1]) + 0x80000000 if c.endswith("'") else int(c)
        packed.extend(idx.to_bytes(4, "big"))
    return bytes(bytearray.fromhex("05") + packed)


def split_message(message: bytes, max_size: int) -> list[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


def encode_vip251(tx_body: dict) -> bytes:
    return bytes([VIP251_TYPE_PREFIX]) + VIP251Codec.encode(tx_body)


def generate_apdus(path: str, encoded_tx: bytes) -> list[str]:
    payload = get_packed_path_bytes(path) + encoded_tx
    chunks = split_message(payload, MAX_APDU_LEN)
    out = []
    for idx, chunk in enumerate(chunks):
        p1_byte = P1.P1_START if idx == 0 else P1.P1_MORE
        out.append(
            (bytes([CLA, InsType.INS_SIGN, p1_byte, P2.P2_LAST, len(chunk)]) + chunk).hex()
        )
    return out


def hex_to_int(s: str) -> int:
    return int(s, 16) if s.startswith("0x") else int(s)


parser = argparse.ArgumentParser()
parser.add_argument("--path", default="m/44'/818'/0'/0/0")
parser.add_argument("--chaintag", default="0xaa", help="0x4a main / 0x27 test / 0xaa solo")
parser.add_argument("--blockref", default="0xabe47d18daa1301d")
parser.add_argument("--expiration", type=int, default=0x2D0)
parser.add_argument("--maxpriority", default="0x3b9aca00", help="1 gwei default")
parser.add_argument("--maxfee", default="0x9502f9000", help="~40 gwei default")
parser.add_argument("--gas", type=int, default=21000)
parser.add_argument("--dependson", default=None)
parser.add_argument("--nonce", default="0x1234")
args = parser.parse_args()

body = {
    "chainTag": hex_to_int(args.chaintag),
    "blockRef": args.blockref,
    "expiration": args.expiration,
    "clauses": [
        {
            "to": "0x5fb35692c9a5025a995beceaebccf2304b2b3383",
            "value": "44800000000000000000",
            "data": "0xc2db2c4200000000000000000000000000000000000000000000000000000000ee6b4b6d",
        },
        {
            "to": "0x5fb35692c9a5025a995beceaebccf2304b2b3383",
            "value": "54800000000000000000",
            "data": "0xc2db2c4200000000000000000000000000000000000000000000000000000000ee6b4b6d",
        },
    ],
    "maxPriorityFeePerGas": hex_to_int(args.maxpriority),
    "maxFeePerGas": hex_to_int(args.maxfee),
    "gas": args.gas,
    "dependsOn": args.dependson,
    "nonce": hex_to_int(args.nonce),
    "reserved": [],
}

raw_tx = encode_vip251(body)
print(f"tx (with 0x51 prefix): {raw_tx.hex()}")
print()

for i, apdu in enumerate(generate_apdus(args.path, raw_tx)):
    print(f"{i+1} APDU: {apdu}")

# Off-chain signature for reference (uses the same hardcoded private key as
# generatetx.py so you can compare). The actual signature on Speculos will differ
# because Speculos uses its default seed, not this private key.
PRIV = bytes.fromhex("C3346001F58ADFFB5928F52DD2B4680E22DD01917F5E233FC8ABB6BCCA46C15F")
signing_hash = blake2b256([raw_tx])[0]
sig = secp256k1.sign(signing_hash, PRIV)
print()
print(f"signing hash:   {signing_hash.hex()}")
print(f"ref signature:  {sig.hex()}")

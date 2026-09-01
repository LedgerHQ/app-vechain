# pyenv local 3.10
# thor_devkit (rlp 1.2.0) conflict with legacy/apdu_generator.py (rlp <0.6.0)
import argparse
import random
from enum import IntEnum

from thor_devkit import cry, transaction
from thor_devkit.rlp import (
    BlobKind,
    BytesKind,
    CompactFixedBlobKind,
    DictWrapper,
    HomoListWrapper,
    NoneableFixedBlobKind,
    NumericKind,
)

_params = [
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
    ("gasPriceCoef", NumericKind(1)),
    ("gas", NumericKind(8)),
    ("dependsOn", NoneableFixedBlobKind(32)),
    ("nonce", NumericKind(8)),
    ("reserved", HomoListWrapper(codec=BytesKind())),
]
# Unsigned Tx Wrapper
UnsignedTxWrapper = DictWrapper(_params)

CLA = 0xE0
MAX_APDU_LEN = 255


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for maximum APDU number.
    P1_MAX = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80


class InsType(IntEnum):
    INS_GET_PUBLIC_KEY = 0x02
    INS_GET_APP_CONFIGURATION = 0x06
    INS_SIGN = 0x04
    INS_SIGN_PERSONAL_MESSAGE = 0x08
    INS_SIGN_CERTIFICATE = 0x09


class Errors(IntEnum):
    SW_TRANSACTION_CANCELLED = 0x6985
    SW_NON_ZERO_AMOUNT = 0x6A87
    SW_UNKNOWN_DESTINATION = 0x6A88


def get_packed_path_bytes(path: str) -> bytes:
    components = path.split("/")
    packed_path = bytearray()

    for component in components:
        if component.startswith("m"):
            continue
        if component.endswith("'"):  # Hardened key
            index = int(component[:-1]) + 0x80000000
        else:
            index = int(component)
        packed_path.extend(index.to_bytes(4, byteorder="big"))

    packed_path = bytearray.fromhex("05") + packed_path
    return bytes(packed_path)


def split_message(message: bytes, max_size: int) -> list[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


def split_tx(path: str, tx: transaction.Transaction):
    return split_message(get_packed_path_bytes(path) + tx.encode(), MAX_APDU_LEN)


def generateAPDUs(path, tx: transaction.Transaction) -> list[str]:
    messages = split_tx(path, tx)
    codesAPDU = []
    for idx, msg in enumerate(messages):
        codesAPDU.append(
            (
                bytes(
                    [
                        CLA,
                        InsType.INS_SIGN,
                        P1.P1_START if idx == 0 else P2.P2_MORE,
                        P2.P2_LAST,
                        len(msg),
                    ]
                )
                + msg
            ).hex()
        )
    return codesAPDU


def randomHex(length, prefix=True):
    start = "0x" if prefix else ""
    # fmt: off
    return start + "".join(
        [
            random.choice(
                ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
                # ["a"]
            )
            for idx in range(0, int(length) * 2)
        ]
    )
    # fmt: on


parser = argparse.ArgumentParser()
parser.add_argument("--path", help="BIP 32 path to sign with")
parser.add_argument("--chaintag", help="Chaintag")
parser.add_argument("--blockref", help="Block reference, hex encoded")
parser.add_argument("--expiration", help="Expiration (# of blocks)")

parser.add_argument("--gaspricecoef", help="Network gas price coef")
parser.add_argument("--gas", help="Gas limit", default="21000")
parser.add_argument("--dependson", help="Tx ID, hex encoded")
parser.add_argument("--nonce", help="Nonce associated to the account")


parser.add_argument("--amount", help="Amount to send in ether")
parser.add_argument("--to", help="Destination address")
parser.add_argument("--data", help="Data to add, hex encoded")
parser.add_argument("--length", help="byte length of random data to add to each clause")
parser.add_argument("--clauses", help="number of clauses")


args = parser.parse_args()

if args.chaintag is None:
    args.chaintag = int("0xaa", 16)

if args.expiration is None:
    args.expiration = 0x2D0

if args.gaspricecoef is None:
    args.gaspricecoef = 128

if args.gas is None:
    args.gas = 21000

if args.nonce is None:
    args.nonce = "0x1234"

if args.data is None:
    # ! empty string returns error
    args.data = "0x00"
    if args.length is not None:
        args.data = randomHex(args.length)

args.clauses = 2
args.to = [
    "0xd6FdBEB6d0FBC690DaBD352cF93b2f8D782A46B5",
    "0xDEADBEB6d0FBC690DaBD352cF93b2f8D782A46B5",
]
if args.clauses is None:
    args.clauses = 1
else:
    args.clauses = int(args.clauses)
    # disabled because args.clauses is set to 2 above
    # if args.clauses > 2:
    #     [args.to.append("0xd6FdBEB6d0FBC690DaBD352cF93b2f8D782A46B5") for _ in range(0, args.clauses-2)]

args.amount = 500
if args.amount is None:
    args.amount = random.randint(1, 9) * (10**5)
args.blockref = "0xabe47d18daa1301d"

# See: https://docs.vechain.org/thor/learn/transaction-model.html#model

# pylint: disable=line-too-long
# used for the test
# body = {
#     "chainTag": int('0x4a', 16), # 0x4a/0x27/0xa4 See: https://docs.vechain.org/others/miscellaneous.html#network-identifier
#     "blockRef": '0x00000000aabbccdd',
#     "expiration": 32,
#     "clauses": [
#           {
#               "to":"0x07479F2710d16a0bACbE6C25b9b32447364C0A33",
#               "data":"0x00" + "1"*500,
#               "value":"133147841714334850862"
#           },
#           {
#               "to":"0x1c8Adf6d8E6302d042b1f09baD0c7f65dE3660eA",
#               "data":"0x8b4dfa75fbbbb8f06fc95406de4591d302ec0e3d3892c4c5e542e01a150eceb2a982762c000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df427000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df427",  # noqa: E501
#               "value":0
#           }
#       ],
#     "gasPriceCoef": 128,
#     "gas": 21000,
#     "dependsOn": None,
#     "nonce": 12345678
# }
# pylint: enable=line-too-long
body = {
    "chainTag": args.chaintag,  # 0x4a/0x27/0xa4 See: https://docs.vechain.org/others/miscellaneous.html#network-identifier
    "blockRef": args.blockref,
    "expiration": int(args.expiration),
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
    # [{"to":args.to[i], "value":args.amount, "data":args.data} for i in range(0, args.clauses)],
    "gasPriceCoef": int(args.gaspricecoef),
    "gas": int(args.gas),
    "dependsOn": args.dependson,
    "nonce": int(args.nonce, 16),
}
# Construct an unsigned transaction.
tx_body = transaction.Transaction(body)
derivation_path: str = "m/44'/818'/0'/0/0"
print(f"tx: {tx_body.encode().hex()}")
print()
for i, codeAPDU in enumerate(generateAPDUs(derivation_path, tx_body)):
    print(f"{i + 1} APDU: {codeAPDU}")

print()
tx_body.set_signature(
    cry.secp256k1.sign(
        tx_body.get_signing_hash(),
        bytes.fromhex("C3346001F58ADFFB5928F52DD2B4680E22DD01917F5E233FC8ABB6BCCA46C15F"),
    )
)
print(f"signature: {tx_body.get_signature().hex()}")

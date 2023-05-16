#!/usr/bin/env python
"""
*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*   (c) 2018 Totient Labs
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""
from ledgerblue.comm import getDongle
import argparse
import struct
from decimal import Decimal

from ledger import _send_tx_to_ledger
from vetBase import Transaction, UnsignedTransaction, Clause
from rlp import encode
from rlp.utils import decode_hex, encode_hex, str_to_bytes, binascii, struct
from bip32 import bip32_path_message


def parse_bip32_path(path):
    if len(path) == 0:
        return ""
    result = ""
    elements = path.split('/')
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0]))
        else:
            result = result + struct.pack(">I", 0x80000000 | int(element[0]))
    return result


def _decimal_to_bytes(i):
    if i is None or i == 0:
        return ""
    hex_basic = hex(int(i))[2:]
    hex_basic = hex_basic.replace("L", "")
    if len(hex_basic) % 2 == 1:
        hex_basic = "0{}".format(hex_basic)
    return decode_hex(hex_basic)


parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to sign with")
parser.add_argument('--chaintag', help="Chaintag")
parser.add_argument('--blockref', help="Block reference, hex encoded")
parser.add_argument('--expiration', help="Expiration (# of blocks)")

parser.add_argument('--gaspricecoef', help="Network gas price coef")
parser.add_argument('--gas', help="Gas limit", default='21000')
parser.add_argument('--dependson', help="Tx ID, hex encoded")
parser.add_argument('--nonce', help="Nonce associated to the account")


parser.add_argument('--amount', help="Amount to send in ether")
parser.add_argument('--to', help="Destination address")
parser.add_argument('--data', help="Data to add, hex encoded")


args = parser.parse_args()

if args.chaintag is None:
    args.chaintag = 154

if args.expiration is None:
    args.expiration = 720

if args.gaspricecoef is None:
    args.gaspricecoef = 128

if args.gas is None:
    args.gas = 21000

if args.dependson is None:
    args.dependson = ""
else:
    args.dependson = decode_hex(args.dependson[2:])

if args.nonce is None:
    args.nonce = "0x1234567890"
args.nonce = decode_hex(args.nonce[2:])

if args.data is None:
    args.data = ""
else:
    args.data = decode_hex(args.data[2:])

args.amount = _decimal_to_bytes(Decimal(args.amount) * 10**18)

tx = Transaction(
    chaintag=int(args.chaintag),
    blockref=decode_hex(args.blockref[2:]),
    expiration=int(args.expiration),
    gaspricecoef=int(args.gaspricecoef),
    gas=int(args.gas),
    dependson=args.dependson,
    nonce=args.nonce,
    clauses=[
        Clause(to=decode_hex(args.to[2:]), value=args.amount, data=args.data),
    ],
    reserved=[]
)

encodedTx = encode(tx, UnsignedTransaction)

donglePath = bip32_path_message(args.path)

dongle = getDongle(True)
result = _send_tx_to_ledger(donglePath + encodedTx, dongle)

signature = result[0:65]

tx = Transaction(
    chaintag=tx.chaintag,
    blockref=tx.blockref,
    expiration=tx.expiration,
    gaspricecoef=tx.gaspricecoef,
    gas=tx.gas,
    dependson=tx.dependson,
    nonce=tx.nonce,
    clauses=[Clause(to=clause.to, value=clause.value, data=clause.data) for clause in tx.clauses],
    reserved=tx.reserved,
    signature=signature
)

print("Signed transaction " + encode_hex(encode(tx)))

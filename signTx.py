#!/usr/bin/env python
"""
*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
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
from decimal import Decimal
from vetBase import Transaction, UnsignedTransaction, Clause
from rlp import encode
from rlp.utils import decode_hex, encode_hex, str_to_bytes, binascii, struct
from bip32 import bip32_path_message

APDU_MAX_DATA_BYTES = 150
APDU_PREFIX_SIGN_TX_INITIAL = binascii.unhexlify('e0040000')
APDU_PREFIX_SIGN_TX_CONTINUED = binascii.unhexlify('e0048000')


def _split_message(message):
    return [message[i:i + APDU_MAX_DATA_BYTES] for i in range(0, len(message), APDU_MAX_DATA_BYTES)]


def _apdu(prefix, data):
    if len(data) == 0:
        return prefix

    if len(data) > APDU_MAX_DATA_BYTES:
        print("APDU data too long: {}".format(len(data)))
        return None

    return prefix + struct.pack(">B", len(data)) + data


def _send_tx_to_ledger(message, dongle):
    result = None
    initial_message = True
    for message in _split_message(message):
        prefix = APDU_PREFIX_SIGN_TX_INITIAL if initial_message else APDU_PREFIX_SIGN_TX_CONTINUED
        apdu = _apdu(prefix, message)
        result = dongle.exchange(apdu)
        initial_message = False

    print("Result: {}".format(result))
    return result


def _int_to_bytes(i):
    if i is None or i == 0:
        return ""
    hex_basic = hex(i)[2:]
    if len(hex_basic) % 2 == 1:
        hex_basic = "0{}".format(hex_basic)
    return decode_hex(hex_basic)


chaintag = 207
blockref = "0x030b04b452c5a8"
expiration = 720
gaspricecoef = 128
gas = 21000
dependson = 0
nonce = "0xc1dc42b4e7"

amount = 0  # Decimal('0.1') * 10**18
to = "0x0000000000000000000000000000456e65726779"
data = "0xa9059cbb" +\
      "0000000000000000000000001e57E7d3f11821B3EFACd4C2b109B65bc78e316c" +\
      "0000000000000000000000000000000000000000000000000de0b6b3a7640000"

tx = Transaction(
    chaintag=int(chaintag),
    blockref=decode_hex(blockref[2:]),
    expiration=int(expiration),
    gaspricecoef=int(gaspricecoef),
    gas=int(gas),
    dependson="",
    nonce=decode_hex(nonce[2:]),
    clauses=[Clause(to=decode_hex(to[2:]), value=_int_to_bytes(amount), data=decode_hex(data[2:]))],
    reserved=[]
)

encodedTx = encode(tx, UnsignedTransaction)

donglePath = bip32_path_message()
# apdu = "e0040000".decode('hex') + chr(len(donglePath) + len(encodedTx)) + donglePath + encodedTx

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

print "Signed transaction " + encode_hex(encode(tx))

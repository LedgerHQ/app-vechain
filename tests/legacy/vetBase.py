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

from rlp.sedes import big_endian_int, binary, Binary, CountableList
from rlp import Serializable

try:
    from Crypto.Hash import keccak

    def sha3_256(x):
        return keccak.new(digest_bits=256, data=x).digest()
except ImportError:
    import sha3 as _sha3

    def sha3_256(x):
        return _sha3.sha3_256(x).digest()


address = Binary.fixed_length(20, allow_empty=True)


def sha3(seed):
    return sha3_256(str(seed))


class Clause(Serializable):
    fields = [("to", address), ("value", binary), ("data", binary)]


class Transaction(Serializable):
    fields = [
        ("chaintag", big_endian_int),
        ("blockref", binary),
        ("expiration", big_endian_int),
        ("clauses", CountableList(Clause)),
        ("gaspricecoef", big_endian_int),
        ("gas", big_endian_int),
        ("dependson", binary),
        ("nonce", binary),
        ("reserved", CountableList(binary)),
        ("signature", binary),
    ]


# UnsignedTransaction = Transaction.exclude(['signature'])
UnsignedTransaction = Transaction

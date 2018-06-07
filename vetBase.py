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

from rlp.sedes import big_endian_int, binary, Binary, List, CountableList
from rlp import Serializable

try:
	from Crypto.Hash import keccak
	sha3_256 = lambda x: keccak.new(digest_bits=256, data=x).digest()
except:
	import sha3 as _sha3
	sha3_256 = lambda x: _sha3.sha3_256(x).digest()
address = Binary.fixed_length(20, allow_empty=True)

def sha3(seed):
	return sha3_256(str(seed))

class Clause(Serializable):
	fields = [
		('to', address),
		('value', big_endian_int),
		('data', binary)
	]

	def __init__(self, to, value, data):
		super(Clause, self).__init__(to, value, data)

class Transaction(Serializable):
	fields = [
		('chaintag', big_endian_int),
		('blockref', binary),
		('expiration', big_endian_int),
		('clauses', CountableList(Clause)),
		('gaspricecoef', big_endian_int),
		('gas', big_endian_int),
		('dependson', binary),
		('nonce', binary),
		('reserved', CountableList(binary)),
		('signature', binary),
	]

	def __init__(self, chaintag, blockref, expiration, clauses, gaspricecoef, gas, dependson, nonce, reserved, signature=""):
		super(Transaction, self).__init__(chaintag, blockref, expiration, clauses, gaspricecoef, gas, dependson, nonce, reserved, signature)

UnsignedTransaction = Transaction.exclude(['signature'])

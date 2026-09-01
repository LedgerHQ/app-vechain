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

import argparse
import struct

from ledgerblue.comm import getDongle


def parse_bip32_path(path):
    if len(path) == 0:
        return ""
    res = ""
    elements = path.split("/")
    for pathElement in elements:
        element = pathElement.split("'")
        if len(element) == 1:
            res = res + struct.pack(">I", int(element[0]))
        else:
            res = res + struct.pack(">I", 0x80000000 | int(element[0]))
    return res


parser = argparse.ArgumentParser()
parser.add_argument("--path", help="BIP 32 path to retrieve")
args = parser.parse_args()

if args.path is None:
    args.path = "44'/818'/0'/0/0"

donglePath = parse_bip32_path(args.path)
apdu = bytes.fromhex("e0020100") + bytes([len(donglePath) + 1]) + bytes([len(donglePath) // 4]) + donglePath

dongle = getDongle(True)
result = dongle.exchange(bytes(apdu))
offset = 1 + result[0]
address = result[offset + 1 : offset + 1 + result[offset]]

print(f"Public key {result[1 : 1 + result[0]].hex()}")
print(f"Address 0x{address!s}")

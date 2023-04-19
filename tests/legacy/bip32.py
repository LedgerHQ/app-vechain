#!/usr/bin/env python
"""
*******************************************************************************
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

import struct

DEFAULT_VET_BIP32_PATH = "44'/818'/0'/0/0"


def _parse_bip32_path(path):
    if len(path) == 0:
        return b''
    result = b''
    for pathElement in path.split('/'):
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0]))
        else:
            result = result + struct.pack(">I", 0x80000000 | int(element[0]))
    return result


def bip32_path_message(path=None):
    if path is None:
        path = DEFAULT_VET_BIP32_PATH
    dongle_path = _parse_bip32_path(path)
    return struct.pack(">B", int(len(dongle_path) / 4)) + dongle_path

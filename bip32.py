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


def bip32_path_message(path=DEFAULT_VET_BIP32_PATH):
    dongle_path = _parse_bip32_path(path)
    return struct.pack(">B", int(len(dongle_path) / 4)) + dongle_path

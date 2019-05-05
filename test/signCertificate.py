from ledgerblue.comm import getDongle
import argparse
import struct
import codecs
from hashlib import blake2b


def parse_bip32_path(path):
    if len(path) == 0:
        return b''
    result = b''
    elements = path.split('/')
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack('>I', int(element[0]))
        else:
            result = result + struct.pack('>I', 0x80000000 | int(element[0]))
    return result


parser = argparse.ArgumentParser()
parser.add_argument('--path', help='BIP 32 path to retrieve')
parser.add_argument('--message', help="Message to sign", required=True)
args = parser.parse_args()

if args.path == None:
	args.path = "44'/818'/0'/0/0"
donglePath = parse_bip32_path(args.path)

args.message = args.message.encode()
h = blake2b(digest_size=32)
h.update(args.message)
print('Blake2b certificate: ' + codecs.encode(h.digest(), 'hex').decode())

encodedTx = struct.pack(">I", len(args.message))
encodedTx += args.message

apdu = codecs.decode(b'e0090000', 'hex') + chr(len(donglePath) + 1 + len(encodedTx)).encode() + chr(len(donglePath) // 4).encode() + donglePath + encodedTx

dongle = getDongle(False)
result = dongle.exchange(apdu)
print('Signed certificate: ' + codecs.encode(result, 'hex').decode())

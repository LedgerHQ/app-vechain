import argparse
import struct
from decimal import Decimal
from vetBase import Transaction, UnsignedTransaction, Clause
from rlp import encode
from rlp.utils import decode_hex


def parse_bip32_path(path):
    if len(path) == 0:
        return ""
    result = ""
    elements = path.split('/')
    for path_element in elements:
        element = path_element.split('\'')
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
    args.chaintag = 0xAA

if args.expiration is None:
    args.expiration = 0x2D0

if args.gaspricecoef is None:
    args.gaspricecoef = 128

if args.gas is None:
    args.gas = 21000

if args.dependson is None:
    args.dependson = ""
else:
    args.dependson = decode_hex(args.dependson[2:])

if args.nonce is None:
    args.nonce = "0x1234"
args.nonce = decode_hex(args.nonce[2:])

if args.data is None:
    args.data = "0xaa55"
else:
    args.data = decode_hex(args.data[2:])

args.to = "0xd6FdBEB6d0FBC690DaBD352cF93b2f8D782A46B5"
args.to2 = "0xDEADBEB6d0FBC690DaBD352cF93b2f8D782A46B5"
args.amount = 5
args.amount = _decimal_to_bytes(Decimal(args.amount) * 10**18)
args.blockref = "0xabe47d18daa1301d"


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
        Clause(to=decode_hex(args.to2[2:]), value=args.amount, data=args.data)
           ],
    reserved=[]
)

encodedTx = encode(tx, UnsignedTransaction)

print("APDU: "+str(encodedTx.hex()))

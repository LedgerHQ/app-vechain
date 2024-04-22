# pyenv local 3.10
# thor_devkit (rlp 1.2.0) conflict with legacy/apdu_generator.py (rlp <0.6.0) 
from thor_devkit import cry, transaction, rlp
from thor_devkit.rlp import DictWrapper, HomoListWrapper, ComplexCodec, NumericKind, CompactFixedBlobKind, NoneableFixedBlobKind, BlobKind, BytesKind
import random
import argparse
from copy import deepcopy

_params = [
    ("chainTag", NumericKind(1)),
    ("blockRef", CompactFixedBlobKind(8)),
    ("expiration", NumericKind(4)),
    ("clauses", HomoListWrapper(codec=DictWrapper([
        ("to", NoneableFixedBlobKind(20)),
        ("value", NumericKind(32)),
        ("data", BlobKind())
    ]))),
    ("gasPriceCoef", NumericKind(1)),
    ("gas", NumericKind(8)),
    ("dependsOn", NoneableFixedBlobKind(32)),
    ("nonce", NumericKind(8)),
    ("reserved", HomoListWrapper(codec=BytesKind()))
]
# Unsigned Tx Wrapper
UnsignedTxWrapper = DictWrapper(_params)

def randomHex(length, prefix=True):
    start = "0x" if prefix else ""
    return start+ "".join([random.choice(
        ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
        # ["a"]
        ) for i in range(0, int(length)*2)])

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
parser.add_argument('--length', help="byte length of random data to add to each clause")
parser.add_argument('--clauses', help="number of clauses")


args = parser.parse_args()

if args.chaintag is None:
    args.chaintag =  int('0xaa', 16)

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
args.to = ["0xd6FdBEB6d0FBC690DaBD352cF93b2f8D782A46B5","0xDEADBEB6d0FBC690DaBD352cF93b2f8D782A46B5"]
if args.clauses is None:
    args.clauses = 1
else:
    args.clauses = int(args.clauses) 
    if args.clauses > 2:
        [args.to.append("0xd6FdBEB6d0FBC690DaBD352cF93b2f8D782A46B5") for _ in range(0, args.clauses-2)]

args.amount = 500
if args.amount is None:
    args.amount = random.randint(1, 9) * (10**5)
args.blockref = "0xabe47d18daa1301d"

clauses= [{"to":args.to[i], "value":args.amount, "data":args.data} for i in range(0, args.clauses)]
# See: https://docs.vechain.org/thor/learn/transaction-model.html#model

# used for the test
# body = {
#     "chainTag": int('0x4a', 16), # 0x4a/0x27/0xa4 See: https://docs.vechain.org/others/miscellaneous.html#network-identifier
#     "blockRef": '0x00000000aabbccdd',
#     "expiration": 32,
#     "clauses": [{"to":"0x07479F2710d16a0bACbE6C25b9b32447364C0A33","data":"0x00" + "1"*500,"value":"133147841714334850862"},{"to":"0x1c8Adf6d8E6302d042b1f09baD0c7f65dE3660eA","data":"0x8b4dfa75fbbbb8f06fc95406de4591d302ec0e3d3892c4c5e542e01a150eceb2a982762c000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df427000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df427","value":0}],
#     "gasPriceCoef": 128,
#     "gas": 21000,
#     "dependsOn": None,
#     "nonce": 12345678
# }
body = {
    "chainTag": args.chaintag, # 0x4a/0x27/0xa4 See: https://docs.vechain.org/others/miscellaneous.html#network-identifier
    "blockRef": args.blockref,
    "expiration": int(args.expiration),
    "clauses": clauses,
    "gasPriceCoef": int(args.gaspricecoef),
    "gas": int(args.gas),
    "dependsOn": args.dependson,
    "nonce": int(args.nonce, 16)
}
# Construct an unsigned transaction.
tx = transaction.Transaction(body)
txHex = tx.encode().hex()
print("tx long: ", len(txHex))
print("tx : ", txHex)
raw_hash, _ = cry.blake2b256([bytes.fromhex(txHex)])
hash_thor_devkit = tx.get_signing_hash()
assert raw_hash == hash_thor_devkit
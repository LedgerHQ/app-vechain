"""Print APDU hex strings ready to copy-paste into the Speculos web UI
`send` text box (http://127.0.0.1:5001) to drive the EIP-712 flows manually.

Usage:
    docker exec -u root speculos-vechain \
        python3 /app/tests/print_speculos_apdus.py
"""
from __future__ import annotations

from Cryptodome.Hash import keccak
from eth_account.messages import encode_typed_data

from generate_eip712 import build_eip712_apdus


def eip712_digest(typed_data: dict) -> bytes:
    """Return the actual EIP-712 final digest signed on-device:
        keccak256(0x1901 || domainSeparator || hashStruct(message))

    Note: `encode_typed_data(...).body` only returns hashStruct(message),
    not the final 0x1901-prefixed digest.
    """
    msg = encode_typed_data(full_message=typed_data)
    h = keccak.new(digest_bits=256)
    h.update(b"\x19" + msg.version + msg.header + msg.body)
    return h.digest()

CLA = 0xE0
INS_GET_APP_CONFIG = 0x06
INS_GET_PUBLIC_KEY = 0x02
INS_SIGN_EIP_712 = 0x0C
INS_DEF = 0x1A
INS_IMPL = 0x1C

PATH_HEX = (
    "058000002C8000033280000000"  # 5 derivations + 44' + 818' + 0'
    "0000000000000000"            # 0 + 0
)


def apdu(ins_byte: int, p1_byte: int, p2_byte: int, data_hex: str = "") -> str:
    payload = bytes.fromhex(data_hex)
    return (f"{CLA:02x}{ins_byte:02x}{p1_byte:02x}{p2_byte:02x}"
            f"{len(payload):02x}{data_hex}")


def keccak256(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def section(title: str) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


# ---------------------------------------------------------------------------
# 0) Configuration probe
# ---------------------------------------------------------------------------
section("0) GET_APP_CONFIGURATION (no settings required)")
print(apdu(INS_GET_APP_CONFIG, 0x00, 0x00))
print()
print("expected: 4 bytes flags|major|minor|patch + 9000 status word")
print("flags bit 0=data, 1=multi-clause, 2=eip712, 3=blind712")

# ---------------------------------------------------------------------------
# 1) Public key
# ---------------------------------------------------------------------------
section("1) GET_PUBLIC_KEY for m/44'/818'/0'/0/0")
print(apdu(INS_GET_PUBLIC_KEY, 0x00, 0x00, PATH_HEX))

# ---------------------------------------------------------------------------
# 2) v0 BLIND SIGN
# ---------------------------------------------------------------------------
section("2) SIGN EIP-712 v0 (blind)")
print("Requires: 'EIP-712 signing' AND 'Blind sign 712' settings ON")
print()

# Reuse the same payload as test_sign_eip712_v0_cmd.py so the digest matches.
domain_separator = bytes.fromhex(
    "06c37168a7db5138defc7866392bb87a741f9b3d104deb5094588ce041cae335"
)
hash_struct = bytes.fromhex(
    "06fdde0306fdde0306fdde0306fdde0306fdde0306fdde0306fdde0306fdde03"
)
expected_digest = keccak256(b"\x19\x01" + domain_separator + hash_struct)
v0_data = PATH_HEX + domain_separator.hex() + hash_struct.hex()
print(apdu(INS_SIGN_EIP_712, 0x00, 0x00, v0_data))
print()
print(f"expected on-device digest: {expected_digest.hex()}")
print("Review will show 'Blind signing' warning + Domain hash + Message hash")

# ---------------------------------------------------------------------------
# 3) v1 CLEAR SIGN -- minimal flat typed-data
# ---------------------------------------------------------------------------
section("3) SIGN EIP-712 v1 (clear sign, FLAT struct)")
print("Requires: 'EIP-712 signing' setting ON")
print("Send the APDUs below in order, then approve the review screen.")
print()

flat_typed_data = {
    "domain": {
        "name": "VeChain Example",
        "version": "1",
        "chainId": 100009,
    },
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "Authentication": [
            {"name": "user", "type": "address"},
            {"name": "timestamp", "type": "string"},
        ],
    },
    "primaryType": "Authentication",
    "message": {
        "user": "0x000000000000000000000000000000000000dead",
        "timestamp": "2026-05-18T15:22:00Z",
    },
}

defs, impls = build_eip712_apdus(flat_typed_data)
for p2, body in defs:
    print(apdu(INS_DEF, 0x00, p2, body.hex()))
for p1, p2, body in impls:
    print(apdu(INS_IMPL, p1, p2, body.hex()))
print(apdu(INS_SIGN_EIP_712, 0x00, 0x01, PATH_HEX))

ref_digest = eip712_digest(flat_typed_data)
print()
print(f"expected on-device digest: {ref_digest.hex()}")

# ---------------------------------------------------------------------------
# 4) v1 CLEAR SIGN -- nested struct (Mail / Person from EIP-712 spec)
# ---------------------------------------------------------------------------
section("4) SIGN EIP-712 v1 (clear sign, NESTED struct)")
print("Same setting requirement as flat case. Showcases hash-context stack.")
print()

nested_typed_data = {
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 100009,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"},
        ],
    },
    "primaryType": "Mail",
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!",
    },
}

defs2, impls2 = build_eip712_apdus(nested_typed_data)
for p2, body in defs2:
    print(apdu(INS_DEF, 0x00, p2, body.hex()))
for p1, p2, body in impls2:
    print(apdu(INS_IMPL, p1, p2, body.hex()))
print(apdu(INS_SIGN_EIP_712, 0x00, 0x01, PATH_HEX))

ref_digest2 = eip712_digest(nested_typed_data)
print()
print(f"expected on-device digest: {ref_digest2.hex()}")

# ---------------------------------------------------------------------------
# 5) v1 CLEAR SIGN -- dynamic array of nested struct
# ---------------------------------------------------------------------------
section("5) SIGN EIP-712 v1 (clear sign, ARRAY of struct)")
print("Showcases push/pop of array hasher + struct hasher together.")
print()

array_typed_data = {
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 100009,
    },
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
        ],
        "Group": [
            {"name": "name", "type": "string"},
            {"name": "members", "type": "Person[]"},
        ],
    },
    "primaryType": "Group",
    "message": {
        "name": "VeChain core team",
        "members": [
            {"name": "Alice", "wallet": "0x000000000000000000000000000000000000aaaa"},
            {"name": "Bob",   "wallet": "0x000000000000000000000000000000000000bbbb"},
            {"name": "Carol", "wallet": "0x000000000000000000000000000000000000cccc"},
        ],
    },
}

defs3, impls3 = build_eip712_apdus(array_typed_data)
for p2, body in defs3:
    print(apdu(INS_DEF, 0x00, p2, body.hex()))
for p1, p2, body in impls3:
    print(apdu(INS_IMPL, p1, p2, body.hex()))
print(apdu(INS_SIGN_EIP_712, 0x00, 0x01, PATH_HEX))

ref_digest3 = eip712_digest(array_typed_data)
print()
print(f"expected on-device digest: {ref_digest3.hex()}")

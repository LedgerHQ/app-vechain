"""All-in-one demo: pick a scenario (flat / nested / array / v0), regenerate
the APDU sequence, and print one line per APDU. Pipe into batch_send_apdus.py
to drive the device end-to-end.

Usage:
    python3 tests/run_eip712_demo.py flat   | python3 tests/batch_send_apdus.py --setup --auto-approve -
    python3 tests/run_eip712_demo.py nested | python3 tests/batch_send_apdus.py --setup --auto-approve -
    python3 tests/run_eip712_demo.py array  | python3 tests/batch_send_apdus.py --setup --auto-approve -
    python3 tests/run_eip712_demo.py v0     | python3 tests/batch_send_apdus.py --setup --auto-approve -
"""
from __future__ import annotations

import sys

from generate_eip712 import build_eip712_apdus

PATH_HEX = "058000002C80000332800000000000000000000000"

CLA = "e0"
INS_SIGN = "0c"
INS_DEF = "1a"
INS_IMPL = "1c"


def apdu(ins_str: str, p1_byte: int, p2_byte: int, data_hex: str = "") -> str:
    payload = bytes.fromhex(data_hex)
    return (f"{CLA}{ins_str}{p1_byte:02x}{p2_byte:02x}"
            f"{len(payload):02x}{data_hex}")


SCENARIOS = {
    "flat": {
        "domain": {"name": "VeChain Example", "version": "1", "chainId": 100009},
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
    },
    "nested": {
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
    },
    "array": {
        "domain": {"name": "Ether Mail", "version": "1", "chainId": 100009},
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
    },
}


def emit_v1(typed_data: dict) -> None:
    defs, impls = build_eip712_apdus(typed_data)
    for p2, body in defs:
        print(apdu(INS_DEF, 0x00, p2, body.hex()))
    for p1, p2, body in impls:
        print(apdu(INS_IMPL, p1, p2, body.hex()))
    print(apdu(INS_SIGN, 0x00, 0x01, PATH_HEX))


def emit_v0() -> None:
    domain_separator = bytes.fromhex(
        "06c37168a7db5138defc7866392bb87a741f9b3d104deb5094588ce041cae335")
    hash_struct = bytes.fromhex(
        "06fdde0306fdde0306fdde0306fdde0306fdde0306fdde0306fdde0306fdde03")
    print(apdu(INS_SIGN, 0x00, 0x00,
               PATH_HEX + domain_separator.hex() + hash_struct.hex()))


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    scenario = sys.argv[1]
    if scenario == "v0":
        emit_v0()
        return 0
    if scenario in SCENARIOS:
        emit_v1(SCENARIOS[scenario])
        return 0
    print(f"unknown scenario: {scenario}. Use one of: flat, nested, array, v0",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

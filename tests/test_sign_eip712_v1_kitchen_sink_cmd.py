"""Kitchen-sink EIP-712 v1 test that exercises every primitive type the
firmware supports but no other test exercises in a real signing round-trip:

* `bool`              — `encode_boolean` (src/eip712/encode_field.c)
* `int256` (negative) — `encode_int` sign-extension padding with 0xFF
* `bytes4`            — `TYPE_SOL_BYTES_FIX` with size != 32
* `bytes` (dynamic)   — `TYPE_SOL_BYTES_DYN`, hashed as keccak256(value)
* `uint256[3]`        — fixed-size array (`ARRAY_FIXED_SIZE` path)

Putting them all in a single struct also stresses the display-pair budget
(5 fields, well under EIP712_MAX_DISPLAY_PAIRS=24) and proves that the
five type-encoding branches coexist in one signing transaction.
"""
import pytest

from Cryptodome.Hash import keccak
from eth_account.messages import encode_typed_data
from ragger.backend import SpeculosBackend
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey

from utils import enable_eip712_settings
from vechain_client import VechainClient, Errors, InsType, unpack_get_public_key_response
from generate_eip712 import build_eip712_apdus

PATH: str = "m/44'/818'/0'/0/0"

TYPED_DATA = {
    "domain": {
        "name": "VeChain KitchenSink",
        "version": "1",
        "chainId": 100009,
    },
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "Action": [
            {"name": "active",   "type": "bool"},
            {"name": "delta",    "type": "int256"},
            {"name": "selector", "type": "bytes4"},
            {"name": "payload",  "type": "bytes"},
            {"name": "amounts",  "type": "uint256[3]"},
        ],
    },
    "primaryType": "Action",
    "message": {
        "active":   True,
        "delta":    -42,
        "selector": "0xa9059cbb",
        "payload":  "0xdeadbeefcafebabe",
        "amounts":  [1, 2, 3],
    },
}


def expected_digest_from_eth_account() -> bytes:
    msg = encode_typed_data(full_message=TYPED_DATA)
    h = keccak.new(digest_bits=256)
    h.update(b"\x19" + msg.version + msg.header + msg.body)
    return h.digest()


def enable_eip712_setting(scenario_navigator: NavigateWithScenario) -> None:
    if not enable_eip712_settings(scenario_navigator.backend.device,
                                  scenario_navigator.navigator,
                                  also_blind=False):
        pytest.skip("EIP-712 settings nav not implemented for this device")


def stream_typed_data(client: VechainClient) -> None:
    defs, impls = build_eip712_apdus(TYPED_DATA)
    for p2, body in defs:
        client.exchange(InsType.INS_EIP712_SEND_STRUCT_DEF, 0x00, p2, body)
    for p1, p2, body in impls:
        client.exchange(InsType.INS_EIP712_SEND_STRUCT_IMPL, p1, p2, body)


def test_sign_eip712_v1_kitchen_sink(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    enable_eip712_setting(scenario_navigator)

    response = client.get_public_key(path=PATH).data
    _, public_key = unpack_get_public_key_response(response)

    stream_typed_data(client)

    with client.sign_eip712_v1(path=PATH):
        scenario_navigator.review_approve(
            test_name="test_sign_eip712_v1_kitchen_sink",
            custom_screen_text="Sign typed data")

    rapdu = client.get_async_response()
    assert rapdu is not None and rapdu.status == Errors.SW_SUCCESS

    if isinstance(backend, SpeculosBackend):
        digest = expected_digest_from_eth_account()
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        assert vk.verify_digest(signature=rapdu.data[:64], digest=digest)

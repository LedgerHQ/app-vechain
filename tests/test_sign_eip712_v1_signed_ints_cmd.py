"""Targeted EIP-712 v1 test for signed-integer (`intN`) handling.

Covers:
* `int8`   — boundary values (+127, -1, -128)
* `int128` — mid-range (+12345, -67890)
* `int256` — small (-42), max negative-ish (-2^255)

Validates both:
1. Signature path: device digest must match `eth_account.encode_typed_data`
   for every signed value (proves `encode_int` sign-extension + the
   typeHash on `int8` / `int128` / `int256` all line up with the spec).
2. Display path: the snapshot UI must render negative values with a leading
   '-' sign (regression test for the `format_int` fix in
   `src/eip712/ui_logic.c`). Positive values keep the same rendering as
   `uint256`.
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

INT256_MIN = -(2 ** 255)

TYPED_DATA = {
    "domain": {
        "name": "VeChain SignedInts",
        "version": "1",
        "chainId": 100009,
    },
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "SignedRange": [
            {"name": "i8_max_pos", "type": "int8"},
            {"name": "i8_neg_one", "type": "int8"},
            {"name": "i8_min",     "type": "int8"},
            {"name": "i128_pos",   "type": "int128"},
            {"name": "i128_neg",   "type": "int128"},
            {"name": "i256_small_neg", "type": "int256"},
            {"name": "i256_min",       "type": "int256"},
        ],
    },
    "primaryType": "SignedRange",
    "message": {
        "i8_max_pos":     127,
        "i8_neg_one":     -1,
        "i8_min":         -128,
        "i128_pos":       12345,
        "i128_neg":       -67890,
        "i256_small_neg": -42,
        "i256_min":       INT256_MIN,
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


def test_sign_eip712_v1_signed_ints(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    enable_eip712_setting(scenario_navigator)

    response = client.get_public_key(path=PATH).data
    _, public_key = unpack_get_public_key_response(response)

    stream_typed_data(client)

    with client.sign_eip712_v1(path=PATH):
        scenario_navigator.review_approve(
            test_name="test_sign_eip712_v1_signed_ints",
            custom_screen_text="Sign typed data")

    rapdu = client.get_async_response()
    assert rapdu is not None and rapdu.status == Errors.SW_SUCCESS

    if isinstance(backend, SpeculosBackend):
        digest = expected_digest_from_eth_account()
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        assert vk.verify_digest(signature=rapdu.data[:64], digest=digest)

"""Functional tests for INS_SIGN_EIP_712 P2=0x01 (clear sign on-device).

Streams a flat typed-data structure (Authentication: address user, string
timestamp) through SEND_STRUCT_DEFINITION + SEND_STRUCT_IMPLEMENTATION, then
asks the device to sign and verifies the signature against eth_account's
encode_typed_data digest.
"""
import pytest

from Cryptodome.Hash import keccak
from eth_account.messages import encode_typed_data
from ragger.backend import RaisePolicy, SpeculosBackend
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey

from utils import enable_eip712_settings
from vechain_client import VechainClient, Errors, EIP712P2, InsType, unpack_get_public_key_response
from generate_eip712 import build_eip712_apdus

PATH: str = "m/44'/818'/0'/0/0"

TYPED_DATA = {
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
        "timestamp": "2026-05-15T15:00:00Z",
    },
}


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def expected_digest_from_eth_account() -> bytes:
    """Compute the actual EIP-712 final digest matching the device's keccak.

    Note: encode_typed_data(...).body is `hashStruct(message)`, NOT the
    final 0x1901-prefixed digest. The device returns a signature over
    keccak256(0x1901 || domainSeparator || hashStruct), so we have to
    reproduce that here.
    """
    msg = encode_typed_data(full_message=TYPED_DATA)
    h = keccak.new(digest_bits=256)
    h.update(b"\x19" + msg.version + msg.header + msg.body)
    return h.digest()


def enable_eip712_setting(scenario_navigator: NavigateWithScenario) -> None:
    """Enable the EIP-712 master switch (sufficient for v1 clear-sign)."""
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


def test_sign_eip712_v1(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    enable_eip712_setting(scenario_navigator)

    response = client.get_public_key(path=PATH).data
    _, public_key = unpack_get_public_key_response(response)

    stream_typed_data(client)

    with client.sign_eip712_v1(path=PATH):
        scenario_navigator.review_approve(
            test_name="test_sign_eip712_v1",
            custom_screen_text="Sign typed data")

    rapdu = client.get_async_response()
    assert rapdu is not None and rapdu.status == Errors.SW_SUCCESS

    if isinstance(backend, SpeculosBackend):
        digest = expected_digest_from_eth_account()
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        assert vk.verify_digest(signature=rapdu.data[:64], digest=digest)


def test_sign_eip712_v1_disabled_returns_error(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    client = VechainClient(backend)

    rapdu = client.exchange(InsType.INS_EIP712_SEND_STRUCT_DEF,
                            0x00,
                            EIP712P2.EIP712_DEF_NAME,
                            b"EIP712Domain")
    # Setting OFF -> condition not satisfied
    assert rapdu.status == 0x6985


def test_sign_eip712_v1_cancel(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    enable_eip712_setting(scenario_navigator)
    stream_typed_data(client)

    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    with client.sign_eip712_v1(path=PATH):
        scenario_navigator.review_reject(test_name="test_sign_eip712_v1_cancel")

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == Errors.SW_TRANSACTION_CANCELLED
    assert len(rapdu.data) == 0

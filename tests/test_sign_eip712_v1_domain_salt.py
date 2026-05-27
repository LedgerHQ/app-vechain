"""Functional test for EIP-712 v1 clear-sign with the optional `bytes32 salt`
field in the `EIP712Domain`.

EIP-712 defines `salt` as an optional 5th field of the domain used to
disambiguate identical domains. The firmware does not have a dedicated
branch for it: `salt` flows through the normal `TYPE_SOL_BYTES_FIX` path
(see `src/eip712/encode_field.c::encode_bytes` and
`src/eip712/format_hash_field_type.c`), so this test serves both as a
regression guard for that code path and as a coverage signal for
`bytes32` fields inside the message body.
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

DOMAIN_SALT = "0xdeadbeef" + "00" * 28

TYPED_DATA = {
    "domain": {
        "name": "VeChain Vault",
        "version": "1",
        "chainId": 100009,
        "verifyingContract": "0x0000000000000000000000000000000000000B3F",
        "salt": DOMAIN_SALT,
    },
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
            {"name": "salt", "type": "bytes32"},
        ],
        "Withdraw": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
        ],
    },
    "primaryType": "Withdraw",
    "message": {
        "to": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
        "amount": 1_000_000_000_000_000_000,
        "nonce": 42,
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


def test_sign_eip712_v1_domain_salt(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    enable_eip712_setting(scenario_navigator)

    response = client.get_public_key(path=PATH).data
    _, public_key = unpack_get_public_key_response(response)

    stream_typed_data(client)

    with client.sign_eip712_v1(path=PATH):
        scenario_navigator.review_approve(
            test_name="test_sign_eip712_v1_domain_salt",
            custom_screen_text="Sign typed data")

    rapdu = client.get_async_response()
    assert rapdu is not None and rapdu.status == Errors.SW_SUCCESS

    if isinstance(backend, SpeculosBackend):
        digest = expected_digest_from_eth_account()
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        assert vk.verify_digest(signature=rapdu.data[:64], digest=digest)

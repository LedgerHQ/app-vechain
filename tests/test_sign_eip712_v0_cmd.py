"""Functional tests for INS_SIGN_EIP_712 P2=0x00 (blind sign).

Sends a 64-byte payload (domainSeparator || hashStruct) to the device, navigates
through the warning + review screens, then verifies the returned signature
against the device public key on Speculos.
"""
import pytest

from Cryptodome.Hash import keccak
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ragger.backend import RaisePolicy, SpeculosBackend
from ragger.navigator import NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from utils import ROOT_SCREENSHOT_PATH, enable_eip712_settings
from vechain_client import VechainClient, Errors, unpack_get_public_key_response

# Reference EIP-712 typed-data: a minimal Permit-style message used as a known
# good blind-sign payload. The actual domainSeparator and hashStruct values
# below were computed off-chain with eth_account.
DOMAIN_SEPARATOR = bytes.fromhex(
    "06c37168a7db5138defc7866392bb87a741f9b3d104deb5094588ce041cae335")
HASH_STRUCT = bytes.fromhex(
    "06fdde0306fdde0306fdde0306fdde0306fdde0306fdde0306fdde0306fdde03")

PATH: str = "m/44'/818'/0'/0/0"


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def expected_digest(domain_separator: bytes, hash_struct: bytes) -> bytes:
    return keccak256(b"\x19\x01" + domain_separator + hash_struct)


def enable_eip712_setting(scenario_navigator: NavigateWithScenario) -> None:
    """Enable both `EIP-712 signing` (master switch) and `Blind sign 712`
    (v0 variant) in the device settings menu so the v0 sign APDU is accepted.
    """
    if not enable_eip712_settings(scenario_navigator.backend.device,
                                  scenario_navigator.navigator,
                                  also_blind=True):
        pytest.skip("EIP-712 settings nav not implemented for this device")


def test_sign_eip712_v0(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    # Make sure the EIP-712 setting is enabled in the device storage.
    enable_eip712_setting(scenario_navigator)

    # Read the public key for later signature validation
    response = client.get_public_key(path=PATH).data
    _, public_key = unpack_get_public_key_response(response)

    with client.sign_eip712_v0(path=PATH,
                               domain_separator=DOMAIN_SEPARATOR,
                               hash_struct=HASH_STRUCT):
        if backend.device.is_nano:
            # Multi-page nbgl_useCaseChoice on Nano: navigate past the icon +
            # subtitle pages and the "Cancel" (confirmText) page, land on
            # "I understand, continue" (rejectText), then BOTH_CLICK to
            # proceed to the review flow.
            scenario_navigator.navigator.navigate_and_compare(
                ROOT_SCREENSHOT_PATH,
                "test_sign_eip712_v0",
                [
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                ])
        else:
            scenario_navigator.review_approve_with_warning(
                test_name="test_sign_eip712_v0",
                custom_screen_text="Sign typed data")

    rapdu = client.get_async_response()
    assert rapdu is not None and rapdu.status == Errors.SW_SUCCESS

    if isinstance(backend, SpeculosBackend):
        digest = expected_digest(DOMAIN_SEPARATOR, HASH_STRUCT)
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        assert vk.verify_digest(signature=rapdu.data[:64], digest=digest)


def test_sign_eip712_v0_disabled_returns_error(scenario_navigator: NavigateWithScenario) -> None:
    """When the EIP-712 setting is OFF (default), the device must reject the
    request with SW_CONDITIONS_NOT_SATISFIED before any UI is shown."""
    backend = scenario_navigator.backend
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    client = VechainClient(backend)

    rapdu = client.exchange(0x0C, 0x00, 0x00, bytes(64))
    # 0x6985 corresponds to SWO_CONDITIONS_NOT_SATISFIED
    assert rapdu.status in (0x6985, Errors.SW_TRANSACTION_CANCELLED)


def test_sign_eip712_v0_cancel(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    enable_eip712_setting(scenario_navigator)

    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    with client.sign_eip712_v0(path=PATH,
                               domain_separator=DOMAIN_SEPARATOR,
                               hash_struct=HASH_STRUCT):
        if backend.device.is_nano:
            # Land on "Cancel" (now confirmText, third page) and BOTH_CLICK
            # to reject.
            scenario_navigator.navigator.navigate_and_compare(
                ROOT_SCREENSHOT_PATH,
                "test_sign_eip712_v0_cancel",
                [
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK,
                ])
        else:
            scenario_navigator.review_reject_with_warning(
                test_name="test_sign_eip712_v0_cancel")

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == Errors.SW_TRANSACTION_CANCELLED
    assert len(rapdu.data) == 0

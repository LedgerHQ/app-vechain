import pytest
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.backend import SpeculosBackend, RaisePolicy
from ragger.backend.interface import BackendInterface
from ragger.navigator.navigation_scenario import NavigateWithScenario
from vechain_client import VechainClient, unpack_get_public_key_response, Errors


# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_public_key_no_confirm(backend: BackendInterface):
    if not isinstance(backend, SpeculosBackend):
        pytest.skip("Skipped as this test is only for Speculos")
    client = VechainClient(backend)

    for path in ["m/44'/818'/0'/0/0", "m/44'/1'/0/0/0"]:
        response = client.get_public_key(path=path).data
        _, public_key = unpack_get_public_key_response(response)
        ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
        assert public_key.hex() == ref_public_key


 # In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_public_key_confirm(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    if not isinstance(backend, SpeculosBackend):
        pytest.skip("Skipped as this test is only for Speculos")

    client = VechainClient(backend)

    for path in ["m/44'/818'/0'/0/0"]:
        # Send the get pub key instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.get_public_key_with_confirmation(path=path):
            scenario_navigator.address_review_approve()

        response = client.get_async_response()
        assert response and response.status == Errors.SW_SUCCESS

        _, public_key = unpack_get_public_key_response(response.data)
        ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
        assert public_key.hex() == ref_public_key


# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
def test_get_public_confirm_refused(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    client = VechainClient(backend)

    for path in ["m/44'/818'/0'/0/0"]:
        # Send the get pub key instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.get_public_key_with_confirmation(path=path):
            scenario_navigator.address_review_reject()

        response = client.get_async_response()
        assert response and response.status == Errors.SW_TRANSACTION_CANCELLED

        # Assert that we have received a refusal
        assert len(response.data) == 0

from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.backend import SpeculosBackend, RaisePolicy
from ragger.navigator import NavInsID, NavIns
from utils import ROOT_SCREENSHOT_PATH
from vechain_client import VechainClient, unpack_get_public_key_response, Errors

# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_public_key_no_confirm(backend):
    if isinstance(backend, SpeculosBackend):
        for path in ["m/44'/818'/0'/0/0", "m/44'/1'/0/0/0"]:
            client = VechainClient(backend)
            response = client.get_public_key(path=path).data
            _, public_key = unpack_get_public_key_response(response)
            ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
            assert public_key.hex() == ref_public_key


 # In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_public_key_confirm(firmware, backend, navigator, test_name):
    if isinstance(backend, SpeculosBackend):
        for path in ["m/44'/818'/0'/0/0"]:
            client = VechainClient(backend)

            # Send the get pub key instruction.
            # As it requires on-screen validation, the function is asynchronous.
            # It will yield the result when the navigation is done
            with client.get_public_key_with_confirmation(path=path):

                # Validate the on-screen request by performing the navigation appropriate for this device
                if firmware.device.startswith("nano"):
                    navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                            [NavInsID.BOTH_CLICK],
                                                            "Approve",
                                                            ROOT_SCREENSHOT_PATH,
                                                            test_name)
                else:
                    instructions = [
                        NavInsID.USE_CASE_REVIEW_TAP,
                        NavIns(NavInsID.TOUCH, (200, 335)),
                        NavInsID.USE_CASE_ADDRESS_CONFIRMATION_EXIT_QR,
                        NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                        NavInsID.USE_CASE_STATUS_DISMISS
                    ]
                    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                                test_name,
                                                instructions)

            response = client.get_async_response().data
            _, public_key = unpack_get_public_key_response(response)
            ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
            assert public_key.hex() == ref_public_key

# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
def test_get_public_confirm_refused(firmware, backend, navigator, test_name):
    for path in ["m/44'/818'/0'/0/0"]:
        client = VechainClient(backend)

        # Send the get pub key instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.get_public_key_with_confirmation(path=path):
            # Disable raising when trying to unpack an error APDU
            backend.raise_policy = RaisePolicy.RAISE_NOTHING

            # Validate the on-screen request by performing the navigation appropriate for this device
            if firmware.device.startswith("nano"):
                navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                        [NavInsID.BOTH_CLICK],
                                                        "Reject",
                                                        ROOT_SCREENSHOT_PATH,
                                                        test_name)
            else:
                instructions = [
                    NavInsID.USE_CASE_REVIEW_REJECT,
                    NavInsID.USE_CASE_STATUS_DISMISS]

                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                            test_name,
                                            instructions)

        response = client.get_async_response()

        # Assert that we have received a refusal
        assert response.status == Errors.SW_TRANSACTION_CANCELLED
        assert len(response.data) == 0

# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
def test_get_public_confirm_refused_2(firmware, backend, navigator, test_name):
    if firmware.device.startswith("stax"):
        for path in ["m/44'/818'/0'/0/0"]:
            client = VechainClient(backend)

            # Send the get pub key instruction.
            # As it requires on-screen validation, the function is asynchronous.
            # It will yield the result when the navigation is done
            with client.get_public_key_with_confirmation(path=path):
                # Disable raising when trying to unpack an error APDU
                backend.raise_policy = RaisePolicy.RAISE_NOTHING

                # Validate the on-screen request by performing the navigation appropriate for this device
                instructions = [
                    NavInsID.USE_CASE_REVIEW_TAP,
                    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL,
                    NavInsID.USE_CASE_STATUS_DISMISS]

                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                            test_name,
                                            instructions)

            response = client.get_async_response()

            # Assert that we have received a refusal
            assert response.status == Errors.SW_TRANSACTION_CANCELLED
            assert len(response.data) == 0

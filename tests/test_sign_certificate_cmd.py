import struct
from hashlib import blake2b
from ragger.backend import RaisePolicy, SpeculosBackend
from ragger.navigator import NavInsID
from utils import ROOT_SCREENSHOT_PATH, check_signature_validity
from vechain_client import VechainClient, Errors, unpack_get_public_key_response

 # Certificate to sign (Json format)
CERTIFICATE_TO_SIGN = str({
                            'purpose': 'identification',
                            'payload': {
                                'type': 'text',
                                'content': 'fyi'
                            },
                            'domain': 'localhost',
                            'timestamp': 15035330,
                        })

# The path used for all tests
path: str = "m/44'/818'/0'/0/0"

# In this test we send to the device a certificate to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_certificate(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    message_encoded = CERTIFICATE_TO_SIGN.encode()

    # compute the reference hash for certificate
    hash_cert = blake2b(digest_size=32)
    hash_cert.update(message_encoded)
    hash_cert = hash_cert.digest().hex()
    hash_part_to_check = hash_cert[:4]

    # prepare the message to send
    message_bytes = struct.pack(">I", len(message_encoded))
    message_bytes += message_encoded

    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_certificate(path=path, data=message_bytes):

        # Validate the on-screen request by performing the navigation appropriate for this device
        if firmware.device.startswith("nano"):
            # check that the certificate hash computed on device is the same as the
            # reference one (check only the first displayed digits)
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      str(hash_part_to_check).upper(),
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name,
                                                      screen_change_after_last_instruction=False)

            navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                            [NavInsID.BOTH_CLICK],
                                            "Sign",
                                            screen_change_before_first_instruction=False)
        else:
            # check that the certificate hash computed on device is the same as the
            # reference one (check only the first displayed digits)
            navigator.navigate_until_text_and_compare(NavInsID.USE_CASE_REVIEW_TAP,
                                                      [NavInsID.USE_CASE_REVIEW_TAP,
                                                       NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                       NavInsID.USE_CASE_STATUS_DISMISS],
                                                      str(hash_part_to_check).upper(),
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data

    if isinstance(backend, SpeculosBackend):
        assert check_signature_validity(public_key, response, message_encoded)


# In this test we send to the device a certificate to sign and cancel it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_certificate_cancel(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    message_encoded = CERTIFICATE_TO_SIGN.encode()

    # compute the reference hash for certificate
    hash_cert = blake2b(digest_size=32)
    hash_cert.update(message_encoded)
    hash_cert = hash_cert.digest().hex()
    hash_part_to_check = hash_cert[:4]

    # prepare the message to send
    message_bytes = struct.pack(">I", len(message_encoded))
    message_bytes += message_encoded

    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    if firmware.device.startswith("nano"):
        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_certificate(path=path, data=message_bytes):
            # check that the certificate hash computed on device is the same as the
            # reference one (check only the first disapled digitis)
            navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                            [NavInsID.BOTH_CLICK],
                                            str(hash_part_to_check).upper(),
                                            screen_change_after_last_instruction=False)

            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                        [NavInsID.BOTH_CLICK],
                                                        "Cancel",
                                                        ROOT_SCREENSHOT_PATH,
                                                        test_name,
                                                        screen_change_before_first_instruction=False)

        # The device as yielded the result, parse it and ensure that the signature is correct
        response = client.get_async_response()

        # Assert that we have received a refusal
        assert response.status == Errors.SW_TRANSACTION_CANCELLED
        assert len(response.data) == 0

    else:
        instructions_list = [
            [
                NavInsID.USE_CASE_REVIEW_REJECT,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ],
            [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_REJECT,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ],
            [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_REJECT,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ],
            [
                NavInsID.USE_CASE_REVIEW_REJECT,
                NavInsID.USE_CASE_CHOICE_REJECT,
                NavInsID.USE_CASE_REVIEW_REJECT,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
        ]

        for i, instructions in enumerate(instructions_list):
            # Send the sign device instruction.
            # As it requires on-screen validation, the function is asynchronous.
            # It will yield the result when the navigation is done
            with client.sign_message(path=path, data=message_bytes):
                # Validate the on-screen request by performing the navigation appropriate for this device
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name + f"/part{i}", instructions)

            # The device as yielded the result, parse it and ensure that the signature is correct
            response = client.get_async_response()

            # Assert that we have received a refusal
            assert response.status == Errors.SW_TRANSACTION_CANCELLED
            assert len(response.data) == 0

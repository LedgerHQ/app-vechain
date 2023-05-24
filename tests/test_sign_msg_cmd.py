import struct
from hashlib import blake2b
from ragger.backend import RaisePolicy, SpeculosBackend
from ragger.navigator import NavInsID
from utils import ROOT_SCREENSHOT_PATH,check_signature_validity
from vechain_client import VechainClient, Errors, unpack_get_public_key_response

 # Message to sign (plain text format)
MESSAGE_TO_SIGN = "Hello Ledger !"

REF_MESSAGE_SIGNATURE = bytes.fromhex("7fb1187fe1699224ce4121765ccec1d7ee7885f098da7c66697ea9642df4179c66705366600613981702db18e52c037f5d9940113d362678576351fe23d84a9f01")

# The path used for all tests
path: str = "m/44'/818'/0'/0/0"

def toPersonalMessage(msg):
    return b"\x19VeChain Signed Message:\n"+str(len(msg)).encode()+msg.encode()

# In this test we send to the device a message to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_message(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    message_encoded = MESSAGE_TO_SIGN.encode()
    # prepare the message to send
    message_bytes = struct.pack(">I", len(message_encoded))
    message_bytes += message_encoded

    hash_msg = blake2b(digest_size=32)
    hash_msg.update(toPersonalMessage(MESSAGE_TO_SIGN))
    hash_msg = hash_msg.digest().hex()
    hash_part_to_check = hash_msg[:4]

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_message(path=path, data=message_bytes):
        # Validate the on-screen request by performing the navigation appropriate for this device
        if firmware.device.startswith("nano"):
            # check that the message hash computed on device is the same as the
            # calculated one (check only the first displayed digits)
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
            navigator.navigate_until_text_and_compare(NavInsID.USE_CASE_REVIEW_TAP,
                                                      [NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                       NavInsID.USE_CASE_STATUS_DISMISS, 
                                                       NavInsID.WAIT_FOR_HOME_SCREEN],
                                                      "Hold to sign",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data

    if isinstance(backend, SpeculosBackend):
        assert check_signature_validity(public_key, response, toPersonalMessage(MESSAGE_TO_SIGN))


# In this test we send to the device a message to sign and cancel it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_message_cancel(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    message_encoded = MESSAGE_TO_SIGN.encode()

    # prepare the message to send
    message_bytes = struct.pack(">I", len(message_encoded))
    message_bytes += message_encoded

    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    if firmware.device.startswith("nano"):

        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_message(path=path, data=message_bytes):
            # Validate the on-screen request by performing the navigation appropriate for this device
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                    [NavInsID.BOTH_CLICK],
                                                    "Cancel",
                                                    ROOT_SCREENSHOT_PATH,
                                                    test_name)
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

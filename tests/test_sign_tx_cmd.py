from ragger.navigator import NavInsID, NavIns
from ragger.backend import RaisePolicy, SpeculosBackend
from utils import ROOT_SCREENSHOT_PATH
from vechain_client import VechainClient, Errors

# Tests inputs (transactions) have been generated with tests/legacy/apdu_generator.py

# Input
# chaintag = 0xAA
# expiration = 0x2D0
# gaspricecoef = 128
# gas = 21000
# dependson = ""
# nonce = "0x1234"
# data = ""
# to = "0xd6FdBEB6d0FBC690DaBD352cF93b2f8D782A46B5"
# amount = 5
# blockref = "0xabe47d18daa1301d"
# transaction message
transaction : bytes = bytes.fromhex("f83a81aa88aae47d18daa1301d8202d0e0df94d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000080818082520880821234c080")


# Input
# chaintag = 0xAA
# expiration = 0x2D0
# gaspricecoef = 128
# gas = 21000
# dependson = ""
# nonce = "0x1234"
# clause 1
# to = "0xd6FdBEB6d0FBC690DaBD352cF93b2f8D782A46B5"
# amount = 5
# data = "0xaa55" (empty for third case)
# clause 2 (removed for second case)
# to = "0xDEADBEB6d0FBC690DaBD352cF93b2f8D782A46B5"
# amount = 5
# data = "0xaa55"
# blockref = "0xabe47d18daa1301d"
# transaction message
transaction_multi_clauses_and_data  = [
    # first use case - with data and multi-clauses
    bytes.fromhex("f86781aa88abe47d18daa1301d8202d0f84ce594d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000086307861613535e594deadbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000086307861613535818082520880821234c080"),
    # second use case - with data
    bytes.fromhex("f84081aa88abe47d18daa1301d8202d0e6e594d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000086307861613535818082520880821234c080"),
    # third use case - with multi-clauses
    bytes.fromhex("f85b81aa88abe47d18daa1301d8202d0f840df94d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000080df94deadbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000080818082520880821234c080")
]

# Output
# reference signatures
ref_signature : bytes = bytes.fromhex("10094cc079e75d21ce30c38b2a70d4bb59efb4a0d0ea5655a4286f33debee884063c0aa9a16285098a0e8958cf39d808119dab71c45983044b4c5ef171fe26e500")
ref_signature_multi_clauses_and_data  = [
    bytes.fromhex("fdc2f80ee9f9537e51a948f54607dfea36f45cab4a9075b0a9a799d51e42573337970486d7d5a2dc4b9584478be253d6523997302d1c6fa4a91d1aceb8b894b500"),
    bytes.fromhex("0be58416adebb54644214ca00da097b8ab90351322b7483a05489121666bd0423d94c50a8300549c06a59c9df72fb7c563f7afa42cb474824dc8f771781ecd3701"),
    bytes.fromhex("7c2ded7fa33d2179e54da07093bf36fd20a7e909f1cbf2dd09b24f45d2fb0682439104576d635aaac3783f5ecb349fd3d6fc26364832554c5ef886ccf97d765500")
]


# The path used for all tests
path: str = "m/44'/818'/0'/0/0"

# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_short_tx(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(path=path, transaction=transaction):

        # Validate the on-screen request by performing the navigation appropriate for this device
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Accept",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)
        else:
            navigator.navigate_until_text_and_compare(NavInsID.USE_CASE_REVIEW_TAP,
                                                      [NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                       NavInsID.USE_CASE_STATUS_DISMISS],
                                                      "Hold to sign",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data

    if isinstance(backend, SpeculosBackend):
        assert ref_signature == response


# In this test se send to the device a transaction to sign and reject it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_short_tx_reject(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    if firmware.device.startswith("nano"):

        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_tx(path=path, transaction=transaction):
            # Validate the on-screen request by performing the navigation appropriate for this device
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                    [NavInsID.BOTH_CLICK],
                                                    "Reject",
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
            with client.sign_tx(path=path, transaction=transaction):
                # Validate the on-screen request by performing the navigation appropriate for this device
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name + f"/part{i}", instructions)

            # The device as yielded the result, parse it and ensure that the signature is correct
            response = client.get_async_response()

            # Assert that we have received a refusal
            assert response.status == Errors.SW_TRANSACTION_CANCELLED
            assert len(response.data) == 0


# In this test we send to the device a transaction (including multiple clauses and data)
# to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_short_tx_data_and_multiple_clauses(firmware, backend, navigator, test_name):
    if not isinstance(backend, SpeculosBackend):
        input("Please confirm that multi-clauses and contract data are enabled in app settings?")

    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    if firmware.device.startswith("nano"):
        # first activate multiple cause and data settings
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK
        ]

        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions,
                                    screen_change_before_first_instruction=False)

        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_tx(path=path, transaction=transaction_multi_clauses_and_data[0]):

            navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                            [NavInsID.BOTH_CLICK],
                                            "Data present",
                                            screen_change_before_first_instruction=False)
            navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                            [NavInsID.BOTH_CLICK],
                                            "Multiple Clauses",
                                            screen_change_before_first_instruction=False)

            navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                            [NavInsID.BOTH_CLICK],
                                            "Accept",
                                            screen_change_before_first_instruction=False)

        # The device as yielded the result, parse it and ensure that the signature is correct
        response = client.get_async_response().data
        if isinstance(backend, SpeculosBackend):
            assert ref_signature_multi_clauses_and_data[0] == response
    else:
        settings_instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (200, 113)),
            NavIns(NavInsID.TOUCH, (200, 261)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            NavInsID.WAIT_FOR_HOME_SCREEN
        ]

        # instructions could be changed if data displayed in the future
        # will be different for each use case
        instructions_list = [
            # data and multi-clauses enabled
            [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
            ],
            # contract data enabled
            [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
            ],
            # multi-clauses enabled
            [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
            ]
        ]

        # first enable the correct settings
        navigator.navigate(settings_instructions, screen_change_before_first_instruction=False)

        for i, instructions in enumerate(instructions_list):

            # Send the sign device instruction.
            # As it requires on-screen validation, the function is asynchronous.
            # It will yield the result when the navigation is done
            with client.sign_tx(path=path, transaction=transaction_multi_clauses_and_data[i]):

                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name + f"/part{i}", instructions)

            # The device as yielded the result, parse it and ensure that the signature is correct
            response = client.get_async_response().data
            if isinstance(backend, SpeculosBackend):
                assert ref_signature_multi_clauses_and_data[i] == response

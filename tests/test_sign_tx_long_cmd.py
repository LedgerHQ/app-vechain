from ragger.navigator import NavInsID, NavIns
from ragger.backend import RaisePolicy, SpeculosBackend
from utils import ROOT_SCREENSHOT_PATH
from vechain_client import VechainClient, Errors

# Tests inputs (transactions) have been generated with tests/generatetx.py
# Input
transaction : bytes = bytes.fromhex("f9031c4a84aabbccdd20f90307f902869407479f2710d16a0bacbe6c25b9b32447364c0a33890737cc289778dddf2eb9026474694a2b0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df4270000000000000000000000000000000000000000000000000000000001e13380908bc8a800a879eed6fd7ad92f2e64e2d4c334369f6b1dba40fbd63f1b325252000000000000000000000000abac49445584c8b6c1472b030b1076ac3901d7cf000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b64617364647361647361640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a48b95dd716280e7a998b7589052db6949b458c5ed03f823d180e677665d1afc17aa34c6ce00000000000000000000000000000000000000000000000000000000000002bf00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000014105199a26b10e55300cb71b46c5b5e867b7df42700000000000000000000000000000000000000000000000000000000000000000000000000000000f87c941c8adf6d8e6302d042b1f09bad0c7f65de3660ea80b8648b4dfa75fbbbb8f06fc95406de4591d302ec0e3d3892c4c5e542e01a150eceb2a982762c000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df427000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df42781808252088083bc614ec0")

# Output
ref_signature : bytes = bytes.fromhex("1f21dfc758d989d8901f84d912135790486b8fa83b6676b87656932a0f02beb375f4dc7c971b2ec51367ecdce05088559af3b88134ad1048a10c09155fb5464100")

# The path used for all tests
path: str = "m/44'/818'/0'/0/0"

# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is long and will be sent in multiple chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_long_tx(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    # As it requires on-screen validation, the function is asynchronous 
    # Instructions are different between nano and stax.
    # Both will yield the result when the navigation is done
    if firmware.device.startswith("nano"):
        # enable data and multi-clauses
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, [
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
        ], screen_change_before_first_instruction=False)
        
        # send the transaction
        with client.sing_tx_long(path=path, transaction=transaction):
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

    else:
        # enable data and multi-clauses
        navigator.navigate([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.USE_CASE_SETTINGS_NEXT,
            NavIns(NavInsID.TOUCH, (200, 113)),
            NavIns(NavInsID.TOUCH, (200, 261)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            NavInsID.WAIT_FOR_HOME_SCREEN
        ], screen_change_before_first_instruction=False)

        # send the transaction
        with client.sing_tx_long(path=path, transaction=transaction):
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, [
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_CHOICE_CONFIRM,
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_CONFIRM,
            NavInsID.USE_CASE_STATUS_DISMISS,
            NavInsID.WAIT_FOR_HOME_SCREEN,
        ])
    
    # The device has yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    
    # check the signature
    if isinstance(backend, SpeculosBackend):
        assert ref_signature == response
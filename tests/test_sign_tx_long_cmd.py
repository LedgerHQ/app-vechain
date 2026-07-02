from ragger.navigator import NavInsID
from ragger.backend import SpeculosBackend
from ragger.navigator.navigation_scenario import NavigateWithScenario
from utils import ROOT_SCREENSHOT_PATH, settingEnables
from vechain_client import VechainClient, Errors

# Tests inputs (transactions) have been generated with tests/generatetx.py
# Input
# pylint: disable=line-too-long
transaction: bytes = bytes.fromhex(
    "f9031c4a84aabbccdd20f90307f902869407479f2710d16a0bacbe6c25b9b32447364c0a33890737cc289778dddf2eb9026474694a2b0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df4270000000000000000000000000000000000000000000000000000000001e13380908bc8a800a879eed6fd7ad92f2e64e2d4c334369f6b1dba40fbd63f1b325252000000000000000000000000abac49445584c8b6c1472b030b1076ac3901d7cf000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b64617364647361647361640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a48b95dd716280e7a998b7589052db6949b458c5ed03f823d180e677665d1afc17aa34c6ce00000000000000000000000000000000000000000000000000000000000002bf00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000014105199a26b10e55300cb71b46c5b5e867b7df42700000000000000000000000000000000000000000000000000000000000000000000000000000000f87c941c8adf6d8e6302d042b1f09bad0c7f65de3660ea80b8648b4dfa75fbbbb8f06fc95406de4591d302ec0e3d3892c4c5e542e01a150eceb2a982762c000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df427000000000000000000000000105199a26b10e55300cb71b46c5b5e867b7df42781808252088083bc614ec0"
)
transaction2: bytes = bytes.fromhex(
    "f9011b81aa88abe47d18daa1301d8202d0f90100f87e94d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b58201f4b86483812fdc931978362b25662863360a4122c7f3096d2bc9b319dba1d5c8a71867d3d6c80a6c885aba673a14e22abb2b977dcc38d9704d6f6992c9c6259ac0f197ab2452bbe8a0ff6ccef8efc8d466e3d59013a5f961823382e001ebebfc196acbbe97eb12f87e94deadbeb6d0fbc690dabd352cf93b2f8d782a46b58201f4b86483812fdc931978362b25662863360a4122c7f3096d2bc9b319dba1d5c8a71867d3d6c80a6c885aba673a14e22abb2b977dcc38d9704d6f6992c9c6259ac0f197ab2452bbe8a0ff6ccef8efc8d466e3d59013a5f961823382e001ebebfc196acbbe97eb12818082520880821234c0"
)
# Output
ref_signature: bytes = bytes.fromhex(
    "1f21dfc758d989d8901f84d912135790486b8fa83b6676b87656932a0f02beb375f4dc7c971b2ec51367ecdce05088559af3b88134ad1048a10c09155fb5464100"
)
ref_signature2: bytes = bytes.fromhex(
    "ddc9bd29343f67c6193c16bcca77e27ef63da70ad476a177593319a56e1b68ba1ee0daf7120dca4fb43ded2fd963bac1ed0568494ad73ff08541fea554eb80db01"
)
# pylint: enable=line-too-long
# The path used for all tests
path: str = "m/44'/818'/0'/0/0"


# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is long and will be sent in multiple chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_long_tx(scenario_navigator: NavigateWithScenario):
    # Use the app interface instead of raw interface
    backend = scenario_navigator.backend
    client = VechainClient(backend)
    navigator = scenario_navigator.navigator
    settingEnables(backend.device, navigator)

    if backend.device.is_nano:
        instructions = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    else:
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM]

    with client.sing_tx_long(path=path, transaction=transaction):
        navigator.navigate_and_compare(
            ROOT_SCREENSHOT_PATH,
            f"{scenario_navigator.test_name}_1/warning",
            instructions,
            screen_change_after_last_instruction=False,
        )
        scenario_navigator.review_approve(test_name=f"{scenario_navigator.test_name}_1")

    # The device has yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # check the signature
    if isinstance(backend, SpeculosBackend):
        assert ref_signature == response.data

    with client.sing_tx_long(path=path, transaction=transaction2):
        navigator.navigate_and_compare(
            ROOT_SCREENSHOT_PATH,
            f"{scenario_navigator.test_name}_2/warning",
            instructions,
            screen_change_after_last_instruction=False,
        )
        scenario_navigator.review_approve(test_name=f"{scenario_navigator.test_name}_2")

    # The device has yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # check the signature
    if isinstance(backend, SpeculosBackend):
        assert ref_signature2 == response.data

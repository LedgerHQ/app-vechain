from operator import is_
from ledgered.devices import Device, DeviceType
from ragger.navigator import NavInsID, NavIns
from ragger.backend import RaisePolicy, SpeculosBackend
from ragger.logger import get_default_logger
from utils import ROOT_SCREENSHOT_PATH, check_signature_validity,settingEnables
from vechain_client import VechainClient, Errors, unpack_get_public_key_response

transaction : bytes = bytes.fromhex("51f83e2788014c77760591ab6864e0df9475a6a29db80bd8a64d3d4b19b29d09bb2245a97f880de0b6b3a7640000808086095e27d758008252088084e788d52ec0")
# The path used for all tests
path: str = "m/44'/818'/0'/0/0"

# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_galattica_tx_short_tx(device:Device, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)
    logger = get_default_logger()
    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)
    logger.info(f"Public key: {public_key.hex()}")

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(path=path, transaction=transaction):

        # Validate the on-screen request by performing the navigation appropriate for this device
        if device.is_nano:
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Accept",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)
        else:
            navigator.navigate([
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ])

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    logger.info(f"Response: {response.hex()}")
    logger.info(f"Check: {check_signature_validity(public_key, response, transaction)}")
    
    if isinstance(backend, SpeculosBackend):
        assert check_signature_validity(public_key, response, transaction)

from ragger.backend import SpeculosBackend
from ragger.logger import get_default_logger
from ragger.navigator.navigation_scenario import NavigateWithScenario
from utils import check_signature_validity
from vechain_client import Errors, VechainClient, unpack_get_public_key_response

# pylint: disable=line-too-long
transaction: bytes = bytes.fromhex(
    "51f83e2788014c77760591ab6864e0df9475a6a29db80bd8a64d3d4b19b29d09bb2245a97f880de0b6b3a7640000808086095e27d758008252088084e788d52ec0"
)
# pylint: enable=line-too-long
# The path used for all tests
path: str = "m/44'/818'/0'/0/0"


# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_galactica_tx_short_tx(scenario_navigator: NavigateWithScenario):
    # Use the app interface instead of raw interface
    backend = scenario_navigator.backend
    client = VechainClient(backend)
    logger = get_default_logger()
    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)
    logger.info("Public key: %s", public_key.hex())

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(path=path, transaction=transaction):
        scenario_navigator.review_approve()

    # The device as yielded the result, parse it and ensure that the signature is correct
    response1 = client.get_async_response()
    assert response1 and response1.status == Errors.SW_SUCCESS

    logger.info("Response: %s", response1.data.hex())
    logger.info("Check: %s", check_signature_validity(public_key, response1.data, transaction))

    if isinstance(backend, SpeculosBackend):
        assert check_signature_validity(public_key, response1.data, transaction)

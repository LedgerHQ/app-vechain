import struct
from ragger.backend import RaisePolicy, SpeculosBackend
from ragger.navigator.navigation_scenario import NavigateWithScenario
from utils import check_signature_validity
from vechain_client import VechainClient, Errors, unpack_get_public_key_response

# Message to sign (plain text format)
MESSAGE_TO_SIGN = "Hello Ledger !"

# pylint: disable=line-too-long
REF_MESSAGE_SIGNATURE = bytes.fromhex(
    "7fb1187fe1699224ce4121765ccec1d7ee7885f098da7c66697ea9642df4179c66705366600613981702db18e52c037f5d9940113d362678576351fe23d84a9f01"
)
# pylint: enable=line-too-long

# The path used for all tests
path: str = "m/44'/818'/0'/0/0"


def toPersonalMessage(msg):
    return b"\x19VeChain Signed Message:\n" + str(len(msg)).encode() + msg.encode()


# In this test we send to the device a message to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_message(scenario_navigator: NavigateWithScenario):
    # Use the app interface instead of raw interface
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    message_encoded = MESSAGE_TO_SIGN.encode()
    # prepare the message to send
    message_bytes = struct.pack(">I", len(message_encoded))
    message_bytes += message_encoded

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_message(path=path, data=message_bytes):
        scenario_navigator.review_approve()

    # The device as yielded the result, parse it and ensure that the signature is correct
    response1 = client.get_async_response()
    assert response1 and response1.status == Errors.SW_SUCCESS

    if isinstance(backend, SpeculosBackend):
        assert check_signature_validity(
            public_key, response1.data, toPersonalMessage(MESSAGE_TO_SIGN)
        )


# In this test we send to the device a message to sign and cancel it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_message_cancel(scenario_navigator: NavigateWithScenario):
    # Use the app interface instead of raw interface
    backend = scenario_navigator.backend
    client = VechainClient(backend)

    # prepare the message to send
    message_encoded = MESSAGE_TO_SIGN.encode()
    message_bytes = struct.pack(">I", len(message_encoded))
    message_bytes += message_encoded

    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    with client.sign_message(path=path, data=message_bytes):
        scenario_navigator.review_reject()

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response()

    # Assert that we have received a refusal
    assert response and response.status == Errors.SW_TRANSACTION_CANCELLED
    assert len(response.data) == 0


# In this test we generated some random message for the device to sign and validate it on screen.
def test_sign_random_message(scenario_navigator: NavigateWithScenario):
    messages = [
        "psst ouch although oof industry until phew",
        "personify trifling lest brr judgementally phew daintily healthily",
        "how clear-cut wherever lest",
        "smart below dishwasher during",
        "ew elaborate invalidate aha impediment hiccough",
        "hm giving when ton prospect",
        "waterski abate truthfully lest neatly which careful",
        "unless wave vitality orderly whose awesome sharply",
        "quadruple unnecessarily shelter pro yippee",
        "yuck needily minus dismal",
        "meh toward wonderfully leading squiggly",
        "psst inasmuch prune baseboard guilder",
        "for instead leading upon closely oh fooey correctly",
        "geez direct pace slowly rapidly whimsical",
        "approval phooey yield than yuck once vacantly so",
        "meanwhile during zowie miracle",
        "abaft utterly despite tailor unless apprehension poll",
        "cruelly alongside youthful furthermore ouch longingly troubleshoot",
        "when aw very fondly wrapping until ugh",
        "drafty irritating supposing violet athwart ugh landing until",
        "whereas graduate skateboard adjust outside whether anyone",
        "unwilling beside above wherever now aha duh",
        "standardize keep psst yearningly",
        "sweatshirt ancestor lily aw toward eek pfft traumatic",
        "colorless smoking after against pointed anti",
        "around phew contract major alfalfa",
        "educated roasted zowie since",
        "lest judgementally yearly scoop woot zowie supposing",
        "fancy ouch patio whoa curtain prize",
        "ample burn-out denote scream",
        "terrific phooey anti weepy marginalize incline from although",
        "icecream early that hence defiant aside amid",
        "hastily who while absent",
        "defog loosely livid essential usually tattered",
        "well whenever ick sophisticated yowza handgun inveigh down",
        "but onto daily gosh recompense twine bah crumble",
        "duh grizzled instead vice incidentally attitude sociable",
        "yowza fig range whoever",
        "phooey but if because ack patiently painfully athwart",
        "famously boo throughout powerfully inside or zowie but",
    ]

    # Use the app interface instead of raw interface
    backend = scenario_navigator.backend
    client = VechainClient(backend)
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

    for i, msg in enumerate(messages):
        # as stax tests takes more time, run the first 5 tests only
        if i > 4 and backend.device.touchable:
            break

        # prepare the message to send
        message_encoded = msg.encode()
        message_bytes = struct.pack(">I", len(message_encoded))
        message_bytes += message_encoded

        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_message(path=path, data=message_bytes):
            scenario_navigator.review_approve(do_comparison=i == 0)

        # The device as yielded the result, parse it and ensure that the signature is correct
        response1 = client.get_async_response()
        assert response1 and response1.status == Errors.SW_SUCCESS

        if isinstance(backend, SpeculosBackend):
            assert check_signature_validity(
                public_key, response1.data, toPersonalMessage(msg)
            )

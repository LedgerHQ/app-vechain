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

    # get public key from device
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
            navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name,[
                NavInsID.SWIPE_CENTER_TO_RIGHT,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ])
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
                NavInsID.SWIPE_CENTER_TO_RIGHT,
                NavInsID.USE_CASE_REVIEW_REJECT,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ],
            [
                NavInsID.SWIPE_CENTER_TO_RIGHT,
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
            with client.sign_certificate(path=path, data=message_bytes):
                # Validate the on-screen request by performing the navigation appropriate for this device
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name + f"/part{i}", instructions)

            # The device as yielded the result, parse it and ensure that the signature is correct
            response = client.get_async_response()

            # Assert that we have received a refusal
            assert response.status == Errors.SW_TRANSACTION_CANCELLED
            assert len(response.data) == 0

# In this test we generated some random certificate for the device to sign and validate it on screen.
def test_sign_random_certificate(firmware, backend, navigator, test_name):
    certificates = [
        '{"domain":"oblong-nephew.name","payload":{"content":"pressurise once opossum oof","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"elastic-fairy.com","payload":{"content":"over separately evergreen anenst","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}', 
        '{"domain":"jovial-head.com","payload":{"content":"pish before optimal dramatic scrummage","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"quirky-ethics.com","payload":{"content":"self-assured ack after usually","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"tinted-toothpaste.biz","payload":{"content":"approve utterly amid forbid instead","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"recent-disembodiment.org","payload":{"content":"stretcher promise exist for","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"incomplete-athletics.com","payload":{"content":"orchid ouch discipline ethical memorize","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"jealous-training.com","payload":{"content":"frivolous ultimately wherever a","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"confused-fragrance.org","payload":{"content":"ack nearer provided boo","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"worn-kit.biz","payload":{"content":"mortified voluntarily delouse plagiarise likely","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"bossy-alternative.biz","payload":{"content":"why ferociously step-father sans","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"utilized-blessing.name","payload":{"content":"accouter pro violation violently prestigious","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"serious-way.com","payload":{"content":"colorfully helpfully gator as","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"odd-application.name","payload":{"content":"unless pfft apud astride","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"incomplete-dip.org","payload":{"content":"pro quietly even abaft","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"velvety-running.biz","payload":{"content":"kite excluding besides disgusting after","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"sane-sculpture.info","payload":{"content":"euphoric gadzooks telecommute but","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}',
        '{"domain":"closed-nightgown.net","payload":{"content":"pooh incidentally boo trouble ill-fated","type":"text"},"purpose":"identification","signer":"0xf077b491b355e64048ce21e3a6fc4751eeea77fa","timestamp":1545035330}'
    ]
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)


    for i, cert in enumerate(certificates):
        # as stax tests takes more time, run the first 5 tests only
        if i>4 and firmware.device.startswith("stax"):
            break

        message_encoded = cert.encode()
        # compute the reference hash for certificate
        hash_cert = blake2b(digest_size=32)
        hash_cert.update(message_encoded)
        hash_cert = hash_cert.digest().hex()
        hash_part_to_check = hash_cert[:4]

        # prepare the message to send
        message_bytes = struct.pack(">I", len(message_encoded))
        message_bytes += message_encoded

        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_certificate(path=path, data=message_bytes):
            # Validate the on-screen request by performing the navigation appropriate for this device
            if firmware.device.startswith("nano"):
                # check that the certificate hash computed on device is the same as the
                # reference one (check only the first displayed digits)
                navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                                        [NavInsID.BOTH_CLICK],
                                                        str(hash_part_to_check).upper(),
                                                        screen_change_after_last_instruction=False)

                navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                                [NavInsID.BOTH_CLICK],
                                                "Sign",
                                                screen_change_before_first_instruction=False)
            else:
                # working with stax and flex 
                navigator.navigate([
                    NavInsID.SWIPE_CENTER_TO_RIGHT,
                    NavInsID.USE_CASE_REVIEW_TAP,
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ])


        # The device as yielded the result, parse it and ensure that the signature is correct
        response = client.get_async_response().data

        if isinstance(backend, SpeculosBackend):
            assert check_signature_validity(public_key, response, message_encoded)

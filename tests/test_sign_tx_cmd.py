from ragger.navigator import NavInsID, NavIns
from ragger.backend import RaisePolicy, SpeculosBackend
from utils import ROOT_SCREENSHOT_PATH, check_signature_validity
from vechain_client import VechainClient, Errors, unpack_get_public_key_response

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
transaction : bytes = bytes.fromhex("f83a81aa88aae47d18daa1301d8202d0e0df94d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000080818082520880821234c0")

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
    bytes.fromhex("f86781aa88abe47d18daa1301d8202d0f84ce594d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000086307861613535e594deadbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000086307861613535818082520880821234c0"),
    # second use case - with data
    bytes.fromhex("f84081aa88abe47d18daa1301d8202d0e6e594d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000086307861613535818082520880821234c0"),
    # third use case - with multi-clauses
    bytes.fromhex("f85b81aa88abe47d18daa1301d8202d0f840df94d6fdbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000080df94deadbeb6d0fbc690dabd352cf93b2f8d782a46b5884563918244f4000080818082520880821234c0")
]

# The path used for all tests
path: str = "m/44'/818'/0'/0/0"

# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_short_tx(firmware, backend, navigator, test_name):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

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
        assert check_signature_validity(public_key, response, transaction)


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

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

    if firmware.device.startswith("nano"):
        # first activate multiple cause and data settings
        # instructions = [
        #     NavInsID.RIGHT_CLICK,
        #     NavInsID.BOTH_CLICK,
        #     NavInsID.BOTH_CLICK,
        #     NavInsID.RIGHT_CLICK,
        #     NavInsID.BOTH_CLICK,
        #     NavInsID.RIGHT_CLICK,
        #     NavInsID.BOTH_CLICK,
        #     NavInsID.RIGHT_CLICK,
        #     NavInsID.BOTH_CLICK,
        #     NavInsID.RIGHT_CLICK,
        #     NavInsID.BOTH_CLICK
        # ]

        # navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions,
        #                             screen_change_before_first_instruction=False)

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
            assert check_signature_validity(public_key, response, transaction_multi_clauses_and_data[0])
    else:
        # settings_instructions = [
        #     NavInsID.USE_CASE_HOME_SETTINGS,
        #     NavInsID.USE_CASE_SETTINGS_NEXT,
        #     NavIns(NavInsID.TOUCH, (200, 113)),
        #     NavIns(NavInsID.TOUCH, (200, 261)),
        #     NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        #     NavInsID.WAIT_FOR_HOME_SCREEN
        # ]

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
                NavInsID.WAIT_FOR_HOME_SCREEN,
            ],
            # contract data enabled
            [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
                NavInsID.WAIT_FOR_HOME_SCREEN,
            ],
            # multi-clauses enabled
            [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
                NavInsID.WAIT_FOR_HOME_SCREEN,
            ]
        ]

        # first enable the correct settings
        # navigator.navigate(settings_instructions, screen_change_before_first_instruction=False)

        for i, instructions in enumerate(instructions_list):

            # Send the sign device instruction.
            # As it requires on-screen validation, the function is asynchronous.
            # It will yield the result when the navigation is done
            with client.sign_tx(path=path, transaction=transaction_multi_clauses_and_data[i]):

                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name + f"/part{i}", instructions)

            # The device as yielded the result, parse it and ensure that the signature is correct
            response = client.get_async_response().data
            if isinstance(backend, SpeculosBackend):
                assert check_signature_validity(public_key, response, transaction_multi_clauses_and_data[i])

# In this test we send to the device random generated transaction to sign and validate it on screen
def test_sign_random_simple_tx(firmware, backend, navigator, test_name):
    txs = [
        'f8427e888fc9b6cceea74fcc8484df2b87e1e094ca689c9be100f3c33a6cf433c7b2fbf2606d2fed890952fac0b477300000806b84fb69fe498088a8b73b51157004bcc0',
        'f863178814a276444ba8be3784b19aed17e1e094975eaec9b853710fbacc7d73a6528692c790be7b8901236efcbcbb3400008081a8846d9de477a093181b4974bb8419648b78a59cb026fb3ba5f0e7665d385a9acae97e67f2dee28836e16caf7c133448c0',
        'f8620e889df4c273d0513155843335247ae1e094e927936902a62508dcee35f36c59e9690ec5e2a889022b1c8c1227a00000801c84ea4703b2a09c7fc4ac11bd7fbdbbe81b66bf6f760bc34180ed3b14b20445562c1ae0fa1c5f882dd2ca2fe278039fc0',
        'f84481ce88428beaf7404ccc70840a74f6e3e1e094fdfe21df626c6af14f9bbe7e53cc7198e5ae4db9890d7f91b4bdd044000080818c8427cf7b3d8088ef63bfca70d8db32c0',
        'f86481c988873dacceb067d12c84fbb5b540e1e094176712a8053860214384ce89c59edc51990e74f789096ebc2e1bc5f80000808182846bce3e86a0f4ee070825de58e54d9a65a76a874af31b69fde84d7541675a40b3d016d57e3488f4d1a2edd9666af1c0',
        'f86481c18834bcaf520fe6ec098424d796dbe1e094579331a366aca831ede25e10e811d45119cbb2b6890b38b3bb4459dc00008081ed84a4684320a085e109e16167fb0f19450705b5b92ffd968ffb7ce571c7cd699c369c5ee6ceb8881bd71c1ba0b4af21c0',
        'f8435088c8853c5d66d03043844b77afa0e1e0944566b994796e43e5eac4011265a117a417652721890c77e4256863d800008081d38420fda4db80886ffc9cb81efb3043c0',
        'f8622888dfe1936fe115604084d5f78c9fe1e0946832aa7d7263120bb04582cab40bb46133a8f7a0890a5aa85009e39c0000803684e635b719a035245e2d1771112cefe291558ac422767aa6512049cb80695bd4c19cc181d4ee881a9f8b2a06119f5ac0',
        'f86381a88884320304671ed98e84294c2c9ae1e094f2ae4251e622a1afcf1af4af75da238b74026648890813ca56906d340000805d84ee5d8ee0a0f7b5fcb6513584b9ea667aabde37aed84ba115297445e1e7c4a12f0e7a54a4588806e3bc43cc40c295c0',
        'f843818488ab84102aafa0551584e71b795de1e094d9aa93a4c4c8e6dd4db58f84de4e4d479fbb93de890c16bf267ed01c0000807784f770cc2f8088e5f721e4ede09f1ac0'
    ]
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

    for i, tx in enumerate(txs):
        # as stax tests takes more time, run the first 5 tests only
        if i>4 and firmware.device.startswith("stax"):
            break

        encoded = bytes.fromhex(tx)
        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_tx(path=path, transaction=encoded):
            # Validate the on-screen request by performing the navigation appropriate for this device
            if firmware.device.startswith("nano"):
                navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                                        [NavInsID.BOTH_CLICK],
                                                        "Accept")
            else:
                navigator.navigate_until_text(NavInsID.USE_CASE_REVIEW_TAP,
                                                        [NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                        NavInsID.USE_CASE_STATUS_DISMISS],
                                                        "Hold to sign")

        # The device as yielded the result, parse it and ensure that the signature is correct
        response = client.get_async_response().data

        if isinstance(backend, SpeculosBackend):
            assert check_signature_validity(public_key, response, encoded)

# In this test we send to the device random generated transaction to sign and validate it on screen
def test_sign_random_data_tx(firmware, backend, navigator, test_name):
    txs = [
        'f863038820312dee7d65ae3b84350a0c41e2e194361ea685786b149f9c24441270bd1dacaa77634d89075f610f70ed20000081dd5484e4423593a0a8d00c66645ce492bd96f9ee4413c7456e5505918b519361d03c240b066b8f93883fc812c0aab1ef9ec0',
        'f86581c1880f0cb57503bcedd284f8802e37e2e19412f52ba49f646de3990b103428a71ca7adc2c46c8901a055690d9db8000081dd81bb84e91b5398a0763d0e6145ef2796985ff2c7dbef8d8568565f1a85045e7750f3085ea050f4e988eef7c7bb3754113ac0',
        'f8638088eaf4bb5cf327332f848cdb6e62e2e194e9b4a82d24e25ef4f3c2d86e7f534798490014c389076d41c6249484000081dd7184ea40a1eba05e2487d9dcfbdea79cf1861d65624116486cc5bf647bb5d7f92647433cfbdd5e8802b057b0a3fad815c0',
        'f844819888f12ffcf4b9cf05fc84141ae73be2e194112b92aab7cbd8de92c62968d3fb3c868d5c3ee38903afb087b87690000081dd4c84490a6ff780886ea995750faafb77c0',
        'f86481bc882e7c3f301deaaefd840ca96561e2e194e46e6f82694e8dc277e0ab2272a1a9dcc4d1507c890805e99fdcc5d0000081dd4184a3e1e8e9a0baa86d8a405891a18eb7985324f0e5d7d69e10532449214624d9f4830032358888c0238d90002645fcc0'
    ]
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

    # first activate multiple cause and data settings
    # if firmware.device.startswith("nano"):
    #     instructions = [
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK
    #     ]

    #     navigator.navigate(instructions, screen_change_before_first_instruction=False)
    # else:
    #     settings_instructions = [
    #         NavInsID.USE_CASE_HOME_SETTINGS,
    #         NavInsID.USE_CASE_SETTINGS_NEXT,
    #         NavIns(NavInsID.TOUCH, (200, 113)),
    #         NavIns(NavInsID.TOUCH, (200, 261)),
    #         NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
    #         NavInsID.WAIT_FOR_HOME_SCREEN
    #     ]
    #     navigator.navigate(settings_instructions, screen_change_before_first_instruction=False)

    for _, tx in enumerate(txs):
        encoded = bytes.fromhex(tx)
        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_tx(path=path, transaction=encoded):
            # Validate the on-screen request by performing the navigation appropriate for this device
            if firmware.device.startswith("nano"):
                navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                                [NavInsID.BOTH_CLICK],
                                                "Data present",
                                                screen_change_before_first_instruction=False)
                navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                                        [NavInsID.BOTH_CLICK],
                                                        "Accept",
                                                        screen_change_before_first_instruction=False)
            else:
                navigator.navigate([ NavInsID.USE_CASE_REVIEW_TAP,NavInsID.USE_CASE_CHOICE_CONFIRM])
                navigator.navigate_until_text(NavInsID.USE_CASE_REVIEW_TAP,
                                                        [NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                        NavInsID.USE_CASE_STATUS_DISMISS],
                                                        "Hold to sign",
                                                        screen_change_before_first_instruction=False)

        # The device as yielded the result, parse it and ensure that the signature is correct
        response = client.get_async_response().data

        if isinstance(backend, SpeculosBackend):
            assert check_signature_validity(public_key, response, encoded)

# In this test we send to the device random generated transaction to sign and validate it on screen
def test_sign_random_multi_clause_tx(firmware, backend, navigator, test_name):
    txs = [
        'f86681e2880e59815845390282841c65ac49f842e09424b1bbd76f700fae1d736d7c537cc96ec2be7c32890719fd7deea82c000080e0942a9c6ecd335aa760fb99c3c276353094bde34a0389019274b259f6540000808192843913fb3080888f21637f05dab2fac0',
        'f88581cb88e4c6e1417e96d1cf8440db74edf842e094a118111565bf2ee6d2b90e3a55e6f298540d2566890bfafdb9178154000080e0943db9897787c1c25286f20cfba98dc371105d17a78903782dace9d9000000801984af58c954a0ab98a30da49a3f914ccd8f6f448666c35cbdf209f7a8638f98768df878e003ba88f30d157c556de7cec0',
        'f8857788f60d1375f3eb119684533463a2f842e094aab17c3037bdb00daf5984b35280160579765be38901ae361fc1451c000080e09400e701a79a897d018142cc8f232528d8217070a589089e917994f71c00008081818443bf4f8ba0ea94b093830b112163d8baec31c431e9762a81b02063a46ee331ae3a141828ea88c80af759dac2145dc0'
    ]
    # Use the app interface instead of raw interface
    client = VechainClient(backend)

    # get public key from device
    response = client.get_public_key(path=path).data
    _, public_key = unpack_get_public_key_response(response)

    # first activate multiple cause and data settings
    # if firmware.device.startswith("nano"):
    #     instructions = [
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK,
    #         NavInsID.RIGHT_CLICK,
    #         NavInsID.BOTH_CLICK
    #     ]

    #     navigator.navigate(instructions, screen_change_before_first_instruction=False)
    # else:
    #     settings_instructions = [
    #         NavInsID.USE_CASE_HOME_SETTINGS,
    #         NavInsID.USE_CASE_SETTINGS_NEXT,
    #         NavIns(NavInsID.TOUCH, (200, 113)),
    #         NavIns(NavInsID.TOUCH, (200, 261)),
    #         NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
    #         NavInsID.WAIT_FOR_HOME_SCREEN
    #     ]
    #     navigator.navigate(settings_instructions, screen_change_before_first_instruction=False)

    for _, tx in enumerate(txs):
        encoded = bytes.fromhex(tx)
        # Send the sign device instruction.
        # As it requires on-screen validation, the function is asynchronous.
        # It will yield the result when the navigation is done
        with client.sign_tx(path=path, transaction=encoded):
            # Validate the on-screen request by performing the navigation appropriate for this device
            if firmware.device.startswith("nano"):
                navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                                [NavInsID.BOTH_CLICK],
                                                "Multiple Clauses",
                                                screen_change_before_first_instruction=False)
                navigator.navigate_until_text(NavInsID.RIGHT_CLICK,
                                                        [NavInsID.BOTH_CLICK],
                                                        "Accept",
                                                        screen_change_before_first_instruction=False)
            else:
                navigator.navigate([ NavInsID.USE_CASE_REVIEW_TAP,NavInsID.USE_CASE_CHOICE_CONFIRM])
                navigator.navigate_until_text(NavInsID.USE_CASE_REVIEW_TAP,
                                                        [NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                        NavInsID.USE_CASE_STATUS_DISMISS],
                                                        "Hold to sign",
                                                        screen_change_before_first_instruction=False)

        # The device as yielded the result, parse it and ensure that the signature is correct
        response = client.get_async_response().data

        if isinstance(backend, SpeculosBackend):
            assert check_signature_validity(public_key, response, encoded)

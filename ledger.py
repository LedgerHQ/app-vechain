import traceback

from ledgerblue.commException import CommException
from rlp import encode
from rlp.utils import binascii, struct

from bip32 import bip32_path_message
from vetBase import Transaction

APDU_PREFIX_SIGN_TX_INITIAL = binascii.unhexlify('e0040000')
APDU_PREFIX_SIGN_TX_CONTINUED = binascii.unhexlify('e0048000')
APDU_PREFIX_APP_VERSION = binascii.unhexlify('e0060000')
APDU_MAX_DATA_BYTES = 150


def _split_message(message):
    return [message[i:i + APDU_MAX_DATA_BYTES] for i in range(0, len(message), APDU_MAX_DATA_BYTES)]


def _apdu(prefix, data):
    if len(data) == 0:
        return prefix

    if len(data) > APDU_MAX_DATA_BYTES:
        print("APDU data too long: {}".format(len(data)))
        return None

    return prefix + struct.pack(">B", len(data)) + data


def _send_tx_to_ledger(message, dongle):
    result = None
    initial_message = True
    for message in _split_message(message):
        prefix = APDU_PREFIX_SIGN_TX_INITIAL if initial_message else APDU_PREFIX_SIGN_TX_CONTINUED
        apdu = _apdu(prefix, message)
        result = dongle.exchange(apdu)
        initial_message = False

    print("Result: {}".format(result))
    return result


def _send_single_to_ledger(prefix, message, dongle):
    apdu = _apdu(prefix, message)
    result = dongle.exchange(apdu, timeout=1000)

    print("Result: {}".format(result))
    return result


def verify(tx, dongle):
    encoded_path = bip32_path_message()

    # EIP 155 (CHAIN_ID = 1)
    tx.v = 0x01
    tx.r = 0x00
    tx.s = 0x00
    encoded_tx = encode(tx, Transaction)

    result = _send_tx_to_ledger(encoded_path + encoded_tx, dongle)

    v = result[0]
    r = int(binascii.hexlify(result[1:1 + 32]), 16)
    s = int(binascii.hexlify(result[1 + 32: 1 + 32 + 32]), 16)

    if v not in {37, 38}:
        raise IncorrectTxFormatException()

    return Transaction(tx.nonce, tx.gasprice, tx.startgas, tx.to, tx.value, tx.data, v, r, s)


def app_version(dongle):
    try:
        result = _send_single_to_ledger(APDU_PREFIX_APP_VERSION, b'', dongle)
    except CommException:
        return None  # Ledger is in Dashboard
    except IOError:
        dongle.close()
        return None  # Ledger switched App, reconnect
    except:
        traceback.print_exc()
        return None  # Unknown Exception, log

    major = result[1]
    minor = result[2]
    patch = result[3]

    return "{}.{}.{}".format(major, minor, patch)


def error_code_to_message(error_code):
    return {
        0x6a88: "LEDGER_UNKNOWN_DESTINATION",
        0x6a87: "LEDGER_NON_ZERO_AMOUNT",
        0x6985: "LEDGER_TRANSACTION_CANCELLED",
    }.get(error_code, "UNRECOGNIZED_ERROR_CODE_{}".format(("%04x" % error_code).upper()))


class IncorrectTxFormatException(Exception):
    pass

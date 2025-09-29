from pathlib import Path
from hashlib import blake2b

from ledgered.devices import Device, DeviceType
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

# Check if a signature of a given message is valid
def check_signature_validity(public_key: bytes, signature: bytes, message: bytes) -> bool:
    pk: VerifyingKey = VerifyingKey.from_string(
        public_key,
        curve=SECP256k1,
    )

    digest = blake2b(message, digest_size=32).digest()
    return pk.verify_digest(signature=signature[:64],digest=digest)

def settingEnables(device: Device, navigator, NavInsID, NavIns):
    if device.is_nano:
        navigator([
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

    elif device.type == DeviceType.STAX:
        navigator([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (200, 113)),
            NavIns(NavInsID.TOUCH, (200, 261)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            NavInsID.WAIT_FOR_HOME_SCREEN
        ], screen_change_before_first_instruction=False)
    elif device.type == DeviceType.FLEX:
        navigator([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (200, 113)),
            NavIns(NavInsID.TOUCH, (200, 300)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            NavInsID.WAIT_FOR_HOME_SCREEN
        ], screen_change_before_first_instruction=False)
    elif device.type == DeviceType.APEX_P:
        navigator([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (150, 114)),
            NavIns(NavInsID.TOUCH, (150, 231)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            NavInsID.WAIT_FOR_HOME_SCREEN
        ], screen_change_before_first_instruction=False)
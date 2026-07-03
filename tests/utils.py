import re
from hashlib import blake2b
from pathlib import Path

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ledgered.devices import Device, DeviceType
from ragger.navigator import Navigator, NavIns, NavInsID

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


# Check if a signature of a given message is valid
def check_signature_validity(public_key: bytes, signature: bytes, message: bytes) -> bool:
    pk: VerifyingKey = VerifyingKey.from_string(
        public_key,
        curve=SECP256k1,
    )

    digest = blake2b(message, digest_size=32).digest()
    return pk.verify_digest(signature=signature[:64], digest=digest)


def settingEnables(device: Device, navigator: Navigator) -> None:
    if device.is_nano:
        navigator.navigate(
            [
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                NavInsID.BOTH_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
            ],
            screen_change_before_first_instruction=False,
        )

    elif device.type == DeviceType.STAX:
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavIns(NavInsID.TOUCH, (200, 113)),
                NavIns(NavInsID.TOUCH, (200, 261)),
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
                NavInsID.WAIT_FOR_HOME_SCREEN,
            ],
            screen_change_before_first_instruction=False,
        )
    elif device.type == DeviceType.FLEX:
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavIns(NavInsID.TOUCH, (200, 113)),
                NavIns(NavInsID.TOUCH, (200, 300)),
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
                NavInsID.WAIT_FOR_HOME_SCREEN,
            ],
            screen_change_before_first_instruction=False,
        )
    elif device.type == DeviceType.APEX_P:
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavIns(NavInsID.TOUCH, (150, 114)),
                NavIns(NavInsID.TOUCH, (150, 231)),
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
                NavInsID.WAIT_FOR_HOME_SCREEN,
            ],
            screen_change_before_first_instruction=False,
        )


def verify_version(version: str) -> None:
    """Verify the app version, based on defines in Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d*)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def _read_makefile() -> list[str]:
    """Read lines from the parent Makefile"""

    parent = Path(__file__).parent.parent.resolve()
    makefile = f"{parent}/Makefile"
    with open(makefile, encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines

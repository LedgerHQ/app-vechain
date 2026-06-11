from pathlib import Path
from hashlib import blake2b
import re

from ragger.navigator import Navigator, NavInsID, NavIns
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

def enable_eip712_settings(device: Device, navigator: Navigator,
                           also_blind: bool = True) -> bool:
    """Enable `EIP-712 signing` (and optionally `Blind sign 712`) via the
    Settings menu. Supports Nano (RIGHT/BOTH click sequence) and touchscreen
    targets (TOUCH coords extrapolated from the first two switches that are
    already calibrated in `settingEnables`).
    """
    if device.is_nano:
        seq: list[NavInsID | NavIns] = [
            NavInsID.RIGHT_CLICK,   # home -> "Settings" header
            NavInsID.BOTH_CLICK,    # enter Settings (page: Contract data)
            NavInsID.RIGHT_CLICK,   # -> Multi-clauses
            NavInsID.RIGHT_CLICK,   # -> EIP-712 signing
            NavInsID.BOTH_CLICK,    # toggle EIP-712 signing ON
        ]
        if also_blind:
            seq += [
                NavInsID.RIGHT_CLICK,  # -> Blind sign 712
                NavInsID.BOTH_CLICK,   # toggle Blind sign 712 ON
            ]
        navigator.navigate(
            seq,
            screen_change_before_first_instruction=False,
            screen_change_after_last_instruction=False,
        )
        return True

    # Touchscreen geometry: the settings page paginates at 2 switches per
    # page on all three targets. EIP-712 / Blind sign 712 live on page 2 with
    # the same Y coordinates as Contract data / Multi-clauses on page 1.
    layouts = {
        DeviceType.STAX:   {"x": 200, "y_row1": 113, "y_row2": 261},
        DeviceType.FLEX:   {"x": 200, "y_row1": 113, "y_row2": 300},
        DeviceType.APEX_P: {"x": 150, "y_row1": 114, "y_row2": 231},
    }
    layout = layouts.get(device.type)
    if layout is None:
        return False
    x, y_row1, y_row2 = layout["x"], layout["y_row1"], layout["y_row2"]

    seq = [
        NavInsID.USE_CASE_HOME_SETTINGS,
        NavInsID.USE_CASE_SETTINGS_NEXT,
        NavIns(NavInsID.TOUCH, (x, y_row1)),
    ]
    if also_blind:
        seq.append(NavIns(NavInsID.TOUCH, (x, y_row2)))
    seq += [
        NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        NavInsID.WAIT_FOR_HOME_SCREEN,
    ]
    navigator.navigate(seq, screen_change_before_first_instruction=False)
    return True


def settingEnables(device: Device, navigator: Navigator) -> None:
    if device.is_nano:
        navigator.navigate([
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ], screen_change_before_first_instruction=False)

    elif device.type == DeviceType.STAX:
        navigator.navigate([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (200, 113)),
            NavIns(NavInsID.TOUCH, (200, 261)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            NavInsID.WAIT_FOR_HOME_SCREEN
        ], screen_change_before_first_instruction=False)
    elif device.type == DeviceType.FLEX:
        navigator.navigate([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (200, 113)),
            NavIns(NavInsID.TOUCH, (200, 300)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            NavInsID.WAIT_FOR_HOME_SCREEN
        ], screen_change_before_first_instruction=False)
    elif device.type == DeviceType.APEX_P:
        navigator.navigate([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (150, 114)),
            NavIns(NavInsID.TOUCH, (150, 231)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            NavInsID.WAIT_FOR_HOME_SCREEN
        ], screen_change_before_first_instruction=False)

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
    """Read lines from the parent Makefile """

    parent = Path(__file__).parent.parent.resolve()
    makefile = f"{parent}/Makefile"
    with open(makefile, "r", encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines

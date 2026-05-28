"""Empirical EIP-712 limit probes.

Streams a series of increasingly-large typed-data shapes through
INS_EIP712_SEND_STRUCT_DEFINITION / INS_EIP712_SEND_STRUCT_IMPL and records
the first APDU that does not return SW_SUCCESS. No INS_SIGN_EIP_712 is ever
issued, so each test is fully synchronous (no UI navigation, no
review_approve).

We rely on the per-function backend scope (see tests/conftest.py) to get a
fresh Speculos session per parametrized N, since the firmware has no
public "tear down the EIP-712 context" APDU.

Probes:

* path depth   -> nested custom structs N levels deep  (MAX_PATH_DEPTH = 16
                  architectural, ~13 practical on Nano due to 8 KB arena)
* array depth  -> single `uint256[][][]...` field      (MAX_ARRAY_DEPTH = 8)
* flat fields  -> N uint256 fields in the primary type (cap target-dependent:
                  24 on Nano, 48 on touchscreen)
* struct count -> N single-field structs in the registry (arena pressure)
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import pytest

from ragger.backend import RaisePolicy
from ragger.bip import pack_derivation_path
from ragger.navigator.navigation_scenario import NavigateWithScenario

from utils import enable_eip712_settings
from vechain_client import VechainClient, Errors, EIP712P2, InsType
from generate_eip712 import build_eip712_apdus

SW_SUCCESS = int(Errors.SW_SUCCESS)
SW_CONDITIONS_NOT_SATISFIED = 0x6985

PATH = "m/44'/818'/0'/0/0"


# ---------------------------------------------------------------------------
# Typed-data builders
# ---------------------------------------------------------------------------

DOMAIN = {"name": "Limits", "version": "1", "chainId": 100009}
DOMAIN_TYPES = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
]


def _typed_path_depth(n: int) -> Dict[str, Any]:
    """n nested custom structs: L0{ L1 next; } ... L{n-1}{ uint256 value; }"""
    types: Dict[str, Any] = {"EIP712Domain": DOMAIN_TYPES}
    for i in range(n):
        if i == n - 1:
            types[f"L{i}"] = [{"name": "value", "type": "uint256"}]
        else:
            types[f"L{i}"] = [{"name": "next", "type": f"L{i+1}"}]

    def build_msg(depth: int) -> Dict[str, Any]:
        if depth == n - 1:
            return {"value": 1}
        return {"next": build_msg(depth + 1)}

    return {
        "domain": DOMAIN,
        "types": types,
        "primaryType": "L0",
        "message": build_msg(0),
    }


def _typed_array_depth(n: int) -> Dict[str, Any]:
    """Single uint256[][...n levels...] field, 1 element per level."""
    value: Any = 1
    for _ in range(n):
        value = [value]
    return {
        "domain": DOMAIN,
        "types": {
            "EIP712Domain": DOMAIN_TYPES,
            "Root": [{"name": "data", "type": "uint256" + "[]" * n}],
        },
        "primaryType": "Root",
        "message": {"data": value},
    }


def _typed_flat_fields(n: int) -> Dict[str, Any]:
    fields = [{"name": f"f{i:02d}", "type": "uint256"} for i in range(n)]
    return {
        "domain": DOMAIN,
        "types": {"EIP712Domain": DOMAIN_TYPES, "Many": fields},
        "primaryType": "Many",
        "message": {f"f{i:02d}": i for i in range(n)},
    }


def _typed_struct_count(n: int) -> Dict[str, Any]:
    """Registry holds n single-field structs S0..S{n-1}; only S0 is used."""
    types: Dict[str, Any] = {"EIP712Domain": DOMAIN_TYPES}
    for i in range(n):
        types[f"S{i}"] = [{"name": "v", "type": "uint256"}]
    types["Root"] = [{"name": "first", "type": "S0"}]
    return {
        "domain": DOMAIN,
        "types": types,
        "primaryType": "Root",
        "message": {"first": {"v": 1}},
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stream(client: VechainClient, typed_data: Dict[str, Any]) -> Optional[int]:
    """Stream every DEFINITION + IMPL APDU. Return the first non-SW_SUCCESS
    status word seen, or None if every APDU was accepted."""
    defs, impls = build_eip712_apdus(typed_data)
    for p2, body in defs:
        r = client.exchange(InsType.INS_EIP712_SEND_STRUCT_DEF, 0x00, p2, body)
        if r.status != SW_SUCCESS:
            return r.status
    for p1, p2, body in impls:
        r = client.exchange(InsType.INS_EIP712_SEND_STRUCT_IMPL, p1, p2, body)
        if r.status != SW_SUCCESS:
            return r.status
    return None


def _setup(scenario_navigator: NavigateWithScenario) -> VechainClient:
    backend = scenario_navigator.backend
    if not enable_eip712_settings(backend.device, scenario_navigator.navigator,
                                  also_blind=False):
        pytest.skip("EIP-712 settings nav not implemented for this device")
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    return VechainClient(backend)


# ---------------------------------------------------------------------------
# Path depth
# ---------------------------------------------------------------------------
# Architectural hard cap: MAX_PATH_DEPTH = 16 (src/eip712/path.h, aligned with
# LedgerHQ/app-ethereum). The root struct itself counts as depth 1.
#
# On Nano (NanoS+/NanoX) APP_MEM_BUFFER_SIZE = 8 KB (vs 16 KB on touchscreen,
# see Makefile). Each nested custom struct level allocates a fresh cx_sha3_t
# (~200 bytes + arena header) for the hash context stack, plus the type
# registry entry, so the arena runs out around depth 14 — well before the
# architectural cap of 16. Empirically depths 1..13 succeed, 14+ return
# SWO_INCORRECT_DATA (0x6A80) from `push_new_hash_depth` -> APP_MEM_CALLOC
# failure that bubbles up to `eip712_dispatch.c`.

def _practical_path_depth_cap(scenario_navigator: NavigateWithScenario) -> int:
    return 13 if scenario_navigator.backend.device.is_nano else 16


@pytest.mark.parametrize("n,architectural_ok", [
    (1,  True),
    (8,  True),
    (15, True),
    (16, True),
    (17, False),
    (20, False),
])
def test_eip712_limit_path_depth(scenario_navigator: NavigateWithScenario,
                                 n: int, architectural_ok: bool) -> None:
    client = _setup(scenario_navigator)
    sw = _stream(client, _typed_path_depth(n))
    print(f"[path_depth] n={n} sw={sw if sw is None else hex(sw)}")
    practical_cap = _practical_path_depth_cap(scenario_navigator)
    expect_ok = architectural_ok and n <= practical_cap
    if expect_ok:
        assert sw is None, f"depth={n}: expected SW_SUCCESS, got 0x{sw:04X}"
    else:
        assert sw is not None, f"depth={n}: expected failure, all APDUs passed"


# ---------------------------------------------------------------------------
# Array depth
# ---------------------------------------------------------------------------
# Hard limit: MAX_ARRAY_DEPTH = 8 (src/eip712/path.h, aligned with
# LedgerHQ/app-ethereum). Single field typed as uint256[]...[].

@pytest.mark.parametrize("n,expect_ok", [
    (1, True),
    (4, True),
    (7, True),
    (8, True),
    (9, False),
    (10, False),
])
def test_eip712_limit_array_depth(scenario_navigator: NavigateWithScenario,
                                  n: int, expect_ok: bool) -> None:
    client = _setup(scenario_navigator)
    sw = _stream(client, _typed_array_depth(n))
    print(f"[array_depth] n={n} sw={sw if sw is None else hex(sw)}")
    if expect_ok:
        assert sw is None, f"array depth={n}: expected SW_SUCCESS, got 0x{sw:04X}"
    else:
        assert sw is not None, f"array depth={n}: expected failure, all APDUs passed"


# ---------------------------------------------------------------------------
# Flat field count (display pairs UI budget)
# ---------------------------------------------------------------------------
# EIP712_MAX_DISPLAY_PAIRS caps how many key/value pairs the review screen
# can show. Streaming itself is never refused — ui_712_finalize_field
# silently fails to register pairs above the cap — but the sign handler
# refuses INS_SIGN_EIP_712 with SWO_CONDITIONS_NOT_SATISFIED (0x6985)
# when `display_overflow` was set. This prevents the WYSIWYS hazard of
# approving a partially-displayed typed-data message.
#
# The cap is target-dependent: 48 on touchscreen targets (Stax/Flex/Apex P),
# 24 on Nano (see src/eip712/eip712_common.h).

def _display_cap(scenario_navigator: NavigateWithScenario) -> int:
    return 24 if scenario_navigator.backend.device.is_nano else 48


@pytest.mark.parametrize("n", [1, 16, 24, 25, 48, 49, 80])
def test_eip712_limit_flat_fields_stream(scenario_navigator: NavigateWithScenario,
                                         n: int) -> None:
    """Streaming the type+impl never fails — the display cap is only
    enforced at sign time. See test_eip712_limit_flat_fields_sign_refused."""
    client = _setup(scenario_navigator)
    sw = _stream(client, _typed_flat_fields(n))
    print(f"[flat_fields stream] n={n} sw={sw if sw is None else hex(sw)}")
    assert sw is None, f"flat n={n}: streaming must succeed; got 0x{sw:04X}"


@pytest.mark.parametrize("n", [25, 49, 80])
def test_eip712_limit_flat_fields_sign_refused(scenario_navigator: NavigateWithScenario,
                                               n: int) -> None:
    """When n > EIP712_MAX_DISPLAY_PAIRS the sign handler must refuse
    BEFORE entering the async review flow, so the host sees a synchronous
    SWO_CONDITIONS_NOT_SATISFIED (0x6985)."""
    client = _setup(scenario_navigator)
    cap = _display_cap(scenario_navigator)
    if n <= cap:
        pytest.skip(f"n={n} fits in the device cap of {cap}, refuse not expected")

    sw = _stream(client, _typed_flat_fields(n))
    assert sw is None, f"flat n={n}: streaming must succeed; got 0x{sw:04X}"

    rapdu = client.exchange(InsType.INS_SIGN_EIP_712, 0x00,
                            EIP712P2.EIP712_P2_V1,
                            pack_derivation_path(PATH))
    print(f"[flat_fields sign] n={n} cap={cap} sign_sw=0x{rapdu.status:04X}")
    assert rapdu.status == SW_CONDITIONS_NOT_SATISFIED, (
        f"flat n={n}: expected 0x6985 (display_overflow), got 0x{rapdu.status:04X}")


# ---------------------------------------------------------------------------
# Struct count (arena pressure)
# ---------------------------------------------------------------------------
# No documented hard cap on the number of structs; the registry just consumes
# arena bytes. We probe how many one-field structs we can stuff in before the
# 3072-byte arena runs out.

@pytest.mark.parametrize("n", [16, 64, 128, 192, 256])
def test_eip712_limit_struct_count(scenario_navigator: NavigateWithScenario,
                                   n: int) -> None:
    """Informational probe: never asserts a specific failure, just reports
    which N still fits inside the 3 KB arena. The last N printing
    `sw=None` is the empirical maximum number of registry entries the
    current build supports. Empirically 96 still fit; 256 should exhaust
    the arena.
    """
    client = _setup(scenario_navigator)
    sw = _stream(client, _typed_struct_count(n))
    print(f"[struct_count] n={n} sw={sw if sw is None else hex(sw)}")

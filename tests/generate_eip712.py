"""Translate an EIP-712 typed-data dict into the APDU sequence expected by the
Ledger VeChain app (INS 0x1A SEND_STRUCT_DEFINITION + INS 0x1C
SEND_STRUCT_IMPLEMENTATION). Phase 3 supports atomic + dynamic types, fixed-
size and dynamic arrays, and nested custom structs.

This is the host-side counterpart of `src/eip712/typed_data.c`,
`src/eip712/path.c` and `src/eip712/field_hash.c`. The encoding rules are
identical to LedgerHQ/app-ethereum so the same SDK tools and tests apply.
"""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Tuple

# TypeDesc bit layout (matches src/eip712/typed_data.h)
TYPE_ARRAY_BIT = 0x80
TYPE_SIZE_BIT = 0x40
TYPE_CUSTOM = 0
TYPE_INT = 1
TYPE_UINT = 2
TYPE_ADDRESS = 3
TYPE_BOOL = 4
TYPE_STRING = 5
TYPE_FIXED_BYTES = 6
TYPE_DYNAMIC_BYTES = 7

# Array level kinds (matches e_array_type in typed_data.h)
ARRAY_DYNAMIC = 0
ARRAY_FIXED_SIZE = 1

_PRIMITIVE_RE = re.compile(r"^(int|uint|bytes)(\d+)?$")
_ARRAY_RE = re.compile(r"^(.*?)((?:\[\d*\])+)$")


def _split_array_levels(type_str: str) -> Tuple[str, List[Tuple[int, int]]]:
    """Split "uint256[3][]" into ("uint256", [(ARRAY_FIXED_SIZE,3),(ARRAY_DYNAMIC,0)])."""
    m = _ARRAY_RE.match(type_str)
    if not m:
        return type_str, []
    base = m.group(1)
    suffix = m.group(2)
    levels: List[Tuple[int, int]] = []
    for raw in re.findall(r"\[(\d*)\]", suffix):
        if raw == "":
            levels.append((ARRAY_DYNAMIC, 0))
        else:
            levels.append((ARRAY_FIXED_SIZE, int(raw)))
    return base, levels


def _classify_type(base: str) -> Tuple[int, bool, int]:
    if base == "address":
        return TYPE_ADDRESS, False, 0
    if base == "bool":
        return TYPE_BOOL, False, 0
    if base == "string":
        return TYPE_STRING, False, 0
    if base == "bytes":
        return TYPE_DYNAMIC_BYTES, False, 0
    m = _PRIMITIVE_RE.match(base)
    if m:
        kind, size = m.group(1), m.group(2)
        if kind in ("int", "uint"):
            t = TYPE_INT if kind == "int" else TYPE_UINT
            if size is None:
                return t, True, 32
            bits = int(size)
            if bits % 8 != 0 or bits == 0 or bits > 256:
                raise ValueError(f"invalid {base}")
            return t, True, bits // 8
        if kind == "bytes":
            n = int(size) if size else 0
            if n == 0:
                return TYPE_DYNAMIC_BYTES, False, 0
            if n > 32:
                raise ValueError(f"invalid bytesN size {n}")
            return TYPE_FIXED_BYTES, True, n
    return TYPE_CUSTOM, False, 0


def _struct_field_apdu(type_str: str, key: str) -> bytes:
    base, levels = _split_array_levels(type_str)
    kind, has_size, size = _classify_type(base)
    type_desc = kind & 0x0F
    if has_size:
        type_desc |= TYPE_SIZE_BIT
    if levels:
        type_desc |= TYPE_ARRAY_BIT
    out = bytearray([type_desc])
    if kind == TYPE_CUSTOM:
        b = base.encode("utf-8")
        out.append(len(b))
        out += b
    if has_size:
        out.append(size)
    if levels:
        out.append(len(levels))
        for lvl_kind, lvl_size in levels:
            out.append(lvl_kind)
            if lvl_kind == ARRAY_FIXED_SIZE:
                out.append(lvl_size)
    kb = key.encode("utf-8")
    out.append(len(kb))
    out += kb
    return bytes(out)


def build_definition_apdus(types: Dict[str, List[Dict[str, str]]]) -> List[Tuple[int, bytes]]:
    apdus: List[Tuple[int, bytes]] = []
    for struct_name, fields in types.items():
        apdus.append((0x00, struct_name.encode("utf-8")))
        for f in fields:
            apdus.append((0xFF, _struct_field_apdu(f["type"], f["name"])))
    return apdus


def _encode_atomic_value(base: str, value: Any) -> bytes:
    kind, has_size, size = _classify_type(base)
    if kind in (TYPE_INT, TYPE_UINT):
        if isinstance(value, str):
            value = int(value, 0)
        n = size if has_size else 32
        as_bytes = int(value).to_bytes(n, "big", signed=kind == TYPE_INT)
        return as_bytes.lstrip(b"\x00") or b"\x00"
    if kind == TYPE_ADDRESS:
        if isinstance(value, str):
            v = value.lower()
            if v.startswith("0x"):
                v = v[2:]
            return bytes.fromhex(v.zfill(40))
        return bytes(value)
    if kind == TYPE_BOOL:
        return b"\x01" if value else b"\x00"
    if kind == TYPE_STRING:
        return value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if kind == TYPE_DYNAMIC_BYTES:
        if isinstance(value, str):
            v = value
            if v.startswith("0x"):
                v = v[2:]
            return bytes.fromhex(v) if v else b""
        return bytes(value)
    if kind == TYPE_FIXED_BYTES:
        if isinstance(value, str):
            v = value
            if v.startswith("0x"):
                v = v[2:]
            return bytes.fromhex(v).ljust(size, b"\x00")[:size]
        return bytes(value)[:size].ljust(size, b"\x00")
    raise ValueError(f"atomic encoding for {base}")


def _emit_value(types: Dict[str, List[Dict[str, str]]],
                type_str: str,
                value: Any,
                out: List[Tuple[int, int, bytes]]) -> None:
    base, levels = _split_array_levels(type_str)
    if levels:
        # Outermost array level: emit ARRAY APDU with size, then recurse on
        # each element with the remaining levels. A dynamic level uses the
        # actual list length; a fixed level must match.
        head = levels[0]
        rest = levels[1:]
        sub_type = base + "".join(
            "[" + (str(s) if k == ARRAY_FIXED_SIZE else "") + "]" for (k, s) in rest)
        if not isinstance(value, list):
            raise TypeError(f"expected list for array type {type_str}, got {type(value)}")
        size = len(value)
        if head[0] == ARRAY_FIXED_SIZE and size != head[1]:
            raise ValueError(f"fixed array size mismatch: expected {head[1]}, got {size}")
        out.append((0x00, 0x0F, bytes([size & 0xFF])))
        for elem in value:
            _emit_value(types, sub_type, elem, out)
        return

    kind, _, _ = _classify_type(base)
    if kind == TYPE_CUSTOM:
        # Nested custom structs are entered automatically by the device's
        # path_advance() when the next field is of CUSTOM type. The host
        # MUST NOT emit a SEND_STRUCT_IMPL root APDU for nested structs;
        # only for the root EIP712Domain and the primaryType.
        for f in types[base]:
            _emit_value(types, f["type"], value[f["name"]], out)
        return

    encoded = _encode_atomic_value(base, value)
    body = struct.pack(">H", len(encoded)) + encoded
    out.append((0x00, 0xFF, body))


def build_implementation_apdus(types: Dict[str, List[Dict[str, str]]],
                               root_struct: str,
                               value: Dict[str, Any]) -> List[Tuple[int, int, bytes]]:
    """Return a list of (P1, P2, body) tuples for INS_EIP712_SEND_STRUCT_IMPL.

    The first entry sets the root struct (P2=0x00). Following entries push
    each field value, recursively descending into nested custom structs and
    array levels.
    """
    out: List[Tuple[int, int, bytes]] = []
    out.append((0x00, 0x00, root_struct.encode("utf-8")))
    fields = types.get(root_struct)
    if fields is None:
        raise ValueError(f"struct {root_struct} missing in types")
    for f in fields:
        _emit_value(types, f["type"], value[f["name"]], out)
    return out


def build_eip712_apdus(typed_data: Dict[str, Any]) -> Tuple[
        List[Tuple[int, bytes]],
        List[Tuple[int, int, bytes]]]:
    types = typed_data["types"]
    domain_value = typed_data["domain"]
    primary = typed_data["primaryType"]
    message = typed_data["message"]

    defs = build_definition_apdus(types)
    impls: List[Tuple[int, int, bytes]] = []
    impls += build_implementation_apdus(types, "EIP712Domain", domain_value)
    impls += build_implementation_apdus(types, primary, message)
    return defs, impls

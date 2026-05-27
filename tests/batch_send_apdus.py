"""Batch-send a sequence of APDUs to a running Speculos via its REST API.

Reads APDU hex strings (one per line, comments after `#`, blank lines OK)
from stdin or from a file path passed as argv[1], POSTs each to the
Speculos `/apdu` endpoint (default `http://127.0.0.1:5001`), and prints
the response side-by-side.

Examples:
    # from stdin
    cat apdus.txt | python3 tests/batch_send_apdus.py

    # from file
    python3 tests/batch_send_apdus.py tests/sample_apdus.txt

    # different host (e.g. when running inside the container)
    SPECULOS_URL=http://localhost:5000 python3 tests/batch_send_apdus.py f.txt

Each APDU is sent synchronously and the script waits for the response
before sending the next one. The final SIGN APDU will block until the
user accepts/rejects the on-device review screen.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

DEFAULT_URL = os.environ.get("SPECULOS_URL", "http://127.0.0.1:5001")


def post_apdu(base_url: str, hex_data: str, timeout: float = 600.0) -> str:
    body = json.dumps({"data": hex_data}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/apdu",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return payload.get("data", "")


def click(base_url: str, button: str) -> None:
    """Press-and-release one of the device buttons via REST API."""
    body = json.dumps({"action": "press-and-release"}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/button/{button}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


def _read_screen_text(base_url: str) -> str:
    """Read the current device screen as a single string (concat of all text
    boxes), via Speculos `/events` endpoint."""
    req = urllib.request.Request(f"{base_url}/events")
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        obj = json.loads(resp.read().decode("utf-8"))
    parts = []
    for evt in obj.get("events", []):
        t = evt.get("text", "")
        if t:
            parts.append(t)
    return " | ".join(parts)


def get_app_config_flags(base_url: str) -> int:
    """Return the configuration flag byte from INS_GET_APP_CONFIGURATION."""
    resp = post_apdu(base_url, "e006000000")
    return int(resp[:2], 16) if len(resp) >= 4 else 0


def autosetup_settings(base_url: str, enable_blind: bool = True) -> None:
    """If the EIP-712 settings are not yet enabled, drive the device buttons
    via REST API to flip them. Same algorithm as setup_speculos_settings.py
    but inlined here so the batch script is self-contained.
    """
    flags = get_app_config_flags(base_url)
    need_eip712 = (flags & 0x04) == 0
    need_blind = enable_blind and (flags & 0x08) == 0
    if not (need_eip712 or need_blind):
        print(f"[setup] settings already configured (flags=0x{flags:02x})")
        return

    print(f"[setup] flags=0x{flags:02x} -> enabling required EIP-712 switches")
    # Enter Settings menu
    click(base_url, "right")        # home -> settings header
    time.sleep(0.2)
    click(base_url, "both")         # enter settings
    time.sleep(0.2)
    # skip Contract data + Multi-clauses
    click(base_url, "right")
    time.sleep(0.15)
    click(base_url, "right")
    time.sleep(0.15)
    if need_eip712:
        click(base_url, "both")     # toggle EIP-712 signing
        time.sleep(0.2)
    click(base_url, "right")
    time.sleep(0.15)
    if need_blind:
        click(base_url, "both")     # toggle Blind sign 712
        time.sleep(0.2)
    # walk back to home
    for _ in range(8):
        click(base_url, "left")
        time.sleep(0.1)

    after = get_app_config_flags(base_url)
    print(f"[setup] now flags=0x{after:02x}")


def auto_approve_in_background(base_url: str,
                               sign_keyword: str = "Sign typed data",
                               max_steps: int = 20) -> None:
    """In a background thread, walk through the on-device review by polling
    the screen text after each `right` press and pressing `both` as soon as a
    screen contains `sign_keyword`.
    """
    def worker() -> None:
        time.sleep(0.6)  # let the first review screen render
        for _ in range(max_steps):
            try:
                txt = _read_screen_text(base_url)
            except Exception:
                return
            low = txt.lower()
            if sign_keyword.lower() in low:
                click(base_url, "both")
                return
            if "reject" in low or "cancel" in low:
                # overshot
                return
            try:
                click(base_url, "right")
            except Exception:
                return
            time.sleep(0.30)

    threading.Thread(target=worker, daemon=True).start()


def parse_lines(stream) -> list[str]:
    out = []
    for raw in stream:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # tolerate spaces inside the hex
        line = line.replace(" ", "").replace("\t", "")
        out.append(line.lower())
    return out


def main() -> int:
    auto_approve = "--auto-approve" in sys.argv
    do_setup = "--setup" in sys.argv
    enable_blind_setting = "--blind712" in sys.argv or any(
        # auto-enable blind sign when the batch contains a v0 APDU (e00cXX00...)
        a.startswith("e00c") and a[6:8] == "00"
        for a in sys.argv if isinstance(a, str)
    )
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args and args[0] != "-":
        with open(args[0], "r", encoding="utf-8") as f:
            apdus = parse_lines(f)
    else:
        apdus = parse_lines(sys.stdin)

    if not apdus:
        print("no APDUs provided", file=sys.stderr)
        return 2

    # Detect blind-sign requirement directly from the APDU list
    if not enable_blind_setting:
        for a in apdus:
            if a.startswith("e00c") and len(a) >= 8 and a[6:8] == "00":
                enable_blind_setting = True
                break

    if do_setup:
        try:
            autosetup_settings(DEFAULT_URL, enable_blind=enable_blind_setting)
        except Exception as exc:
            print(f"[setup] failed: {exc}", file=sys.stderr)
            return 1

    print(f"sending {len(apdus)} APDU(s) to {DEFAULT_URL}"
          f"{' [auto-approve]' if auto_approve else ''}")
    for i, a in enumerate(apdus, start=1):
        ins = a[2:4] if len(a) >= 4 else "??"
        print(f"\n[{i:02d}/{len(apdus):02d}] INS={ins}  ({len(a)//2} bytes)")
        print(f"  -> {a[:60]}{'...' if len(a) > 60 else ''}")
        t0 = time.time()
        # If this is a SIGN APDU and the user asked for auto-approve, kick off
        # the button-press worker before posting the APDU; the device will
        # show the review screen as soon as the request lands and the worker
        # will dismiss it for us.
        if auto_approve and ins in ("0c", "04", "08", "09"):
            auto_approve_in_background(DEFAULT_URL)
        try:
            resp_hex = post_apdu(DEFAULT_URL, a)
        except urllib.error.URLError as exc:
            print(f"  ERROR: {exc}")
            return 1
        elapsed = time.time() - t0
        sw = resp_hex[-4:].lower() if len(resp_hex) >= 4 else "????"
        print(f"  <- {resp_hex[:120]}{'...' if len(resp_hex) > 120 else ''}")
        print(f"     status={sw}  time={elapsed:.2f}s")
        if sw != "9000":
            print("  STOPPED: non-success status word")
            return 1
    print("\nALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

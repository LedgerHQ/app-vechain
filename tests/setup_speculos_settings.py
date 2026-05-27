"""Drive the Speculos device buttons via REST API to enable the EIP-712
settings without clicking the web UI. Use after every Speculos restart.

Layout of the Nano X home + settings flow (nbgl_useCaseHomeAndSettings):

  page 0: Home                     <-- starting point
  page 1: Settings header          (tap both to enter)
  page 2: Contract data switch
  page 3: Multi-clauses switch
  page 4: EIP-712 signing switch
  page 5: Blind sign 712 switch
  page 6: Info
  page 7: Quit

Usage:
    python3 tests/setup_speculos_settings.py    # enable eip712 + blind712
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

DEFAULT_URL = os.environ.get("SPECULOS_URL", "http://127.0.0.1:5001")


def post(path: str, body: dict, base: str = DEFAULT_URL) -> str:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{base}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return resp.read().decode("utf-8")


def click(button: str) -> None:
    post(f"/button/{button}", {"action": "press-and-release"})
    time.sleep(0.25)


def main() -> int:
    print(f"connecting to {DEFAULT_URL}")
    # Send a probe APDU first so we know the device is responsive.
    body = json.dumps({"data": "e006000000"}).encode("utf-8")
    req = urllib.request.Request(
        f"{DEFAULT_URL}/apdu",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        before = json.loads(resp.read().decode("utf-8"))["data"]
    print(f"before: flags={before[:2]}")

    # Step 1: enter Settings (right -> both)
    click("right")     # home -> settings header
    click("both")      # enter settings list

    # Step 2: skip Contract data (page 2) and Multi-clauses (page 3)
    click("right")     # -> Multi-clauses
    click("right")     # -> EIP-712 signing
    click("both")      # toggle EIP-712 signing ON

    click("right")     # -> Blind sign 712
    click("both")      # toggle Blind sign 712 ON

    # Walk back to home: navigate right past "Info" + "Quit", then the next
    # right wraps; safer to use multiple lefts.
    for _ in range(8):
        click("left")

    # Verify
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        after = json.loads(resp.read().decode("utf-8"))["data"]
    flags = int(after[:2], 16)
    print(f"after:  flags=0x{flags:02x} "
          f"({'eip712 ' if flags & 0x04 else ''}"
          f"{'blind712 ' if flags & 0x08 else ''})")

    if (flags & 0x04) == 0 or (flags & 0x08) == 0:
        print("WARNING: expected eip712 and blind712 to be ON; check the device screen")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

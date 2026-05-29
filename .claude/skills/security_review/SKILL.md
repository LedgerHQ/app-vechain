---
description: "Full-depth security audit of Ledger embedded applications — APDU reachability, trust model, memory safety, cryptographic misuse, clear-signing bypass. Use when the user asks to audit, pentest, find vulnerabilities, security review an embedded Ledger app, or mentions APDU fuzzing, exploit PoC, clear-signing bypass, or embedded firmware security."
applyTo: "**/*"
---

# Ledger Embedded Application Security Review — Complete Methodology

This is a multi-pass security audit methodology purpose-built for Ledger hardware wallet embedded applications (C or Rust). It goes far beyond generic C code review by incorporating the Ledger-specific trust model, APDU attack surface, clear-signing semantics, and the unique constraints of ~24 KB RAM devices.

---

## Phase 0: Reconnaissance & Architecture Mapping

### 0.1 Identify the Application Boundary

```
Task Progress:
- [ ] 0. Recon & architecture mapping
- [ ] 1. Trust model & threat model
- [ ] 2. APDU dispatcher & entry point enumeration
- [ ] 3. Memory & state analysis
- [ ] 4. Vulnerability hunting (multi-category)
- [ ] 5. APDU reachability verification
- [ ] 6. False-positive elimination pass
- [ ] 7. Exploitability classification
- [ ] 8. PoC / sanitizer confirmation
- [ ] 9. Final report generation
```

Before auditing, map the architecture:

1. **Read `ledger_app.toml`** — devices, test directory, app flags
2. **Read `Makefile` / `features.mk`** — which features are compiled, `#define` flags
3. **Identify APDU dispatcher** — usually `src/main.c`, find `apdu_dispatcher` or the `INS_*` switch
4. **Enumerate all INS codes** — build the full table of APDU commands
5. **Identify plugin system** — how plugins are loaded, dispatched, what data they receive
6. **Identify swap/library mode** — does the app expose `library_main()`?

### 0.2 Build the Call Graph (mental or tooling)

For each INS handler, trace the call chain to leaf functions. Priority:

- Handlers that process **variable-length untrusted data** (sign TX, provide info, set plugin)
- Handlers that **display data to the user** (UI formatting)
- Handlers that **derive keys or sign** (cryptographic operations)

---

## Phase 1: Trust Model & Threat Model

### 1.1 Ledger Trust Hierarchy

| Entity                              | Trust Level             | Controls                                   |
| ----------------------------------- | ----------------------- | ------------------------------------------ |
| **Ledger firmware/OS**              | Fully trusted           | SDK syscalls, app isolation                |
| **Exchange app**                    | Trusted (Ledger-signed) | Calls `library_main()` for swap            |
| **PKI certificates**                | Semi-trusted            | Issued by Ledger backend, per-usage scoped |
| **Companion app / host**            | **UNTRUSTED**           | Sends APDUs, can be malicious              |
| **Blockchain data (calldata, RLP)** | **UNTRUSTED**           | Attacker-controlled payload                |

### 1.2 Key Implications

- **APDUs are the primary attack surface.** Any bug reachable only from `library_main()` (Exchange app) is defense-in-depth only — NOT exploitable by external attacker.
- **PKI-gated operations** require a Ledger-issued certificate. Bugs behind PKI checks have reduced exploitability (attacker needs compromised/leaked backend key).
- **RLP/ABI-encoded data is attacker-controlled** — all parsing must be robust.

### 1.3 Attacker Model

The attacker is the **companion app / host** sending APDUs to the device over USB/BLE. They can:

- Send arbitrary APDU sequences (any order, any data)
- Craft malicious RLP transactions
- Provide forged token info (unless PKI-validated)
- Interleave commands to exploit state machines
- **Cannot** call `library_main()` (only Exchange app can)
- **Cannot** forge PKI certificates (unless Ledger infra is compromised)

---

## Phase 2: APDU Dispatcher & Entry Point Enumeration

### 2.1 Map Every INS Handler

For each handler, document:

```
| INS | Name | Handler function | Stateful? | PKI-gated? | User-confirmation? |
```

### 2.2 Classify Entry Points by Risk

**HIGH RISK** (process untrusted variable-length data):

- `INS_SIGN` / `INS_SIGN_TX` — RLP parsing, plugin dispatch
- `INS_SIGN_PERSONAL_MESSAGE` — arbitrary message
- `INS_SIGN_EIP712_MESSAGE` — typed data parsing
- `INS_PROVIDE_*` — token info, NFT metadata, trusted names

**MEDIUM RISK** (simpler parsing, often PKI-gated):

- `INS_SET_PLUGIN` / `INS_SET_EXTERNAL_PLUGIN`
- `INS_PROVIDE_NETWORK_INFO`
- `INS_PROVIDE_TX_SIMULATION`

**LOW RISK** (minimal parsing, no user-facing display):

- `INS_GET_PUBLIC_KEY`
- `INS_GET_APP_CONFIGURATION`
- `INS_GET_CHALLENGE`

---

## Phase 3: Memory & State Analysis

### 3.1 Global State Inventory

Ledger apps use **global static buffers** (no heap in the traditional sense). Map:

- `shared_context.h` / `tmpCtx_t` unions — overlapping state
- `appState` / `appStateType` — current operation discriminant
- Plugin context structs — per-plugin state machines
- EIP-712 context — complex state with multiple allocations

### 3.2 State Machine Coherence

For multi-APDU flows (sign TX, EIP-712):

- Can the attacker **skip steps** (send chunk 3 without chunk 1)?
- Can the attacker **replay steps** (send the same chunk twice)?
- Can the attacker **interleave flows** (start sign TX, then provide token info)?
- Is state **properly cleared on error/abort**?

### 3.3 SDK Memory Pool (`APP_MEM_ALLOC`)

Ledger SDK provides a pool allocator from a static buffer. This is **NOT stdlib malloc**:

- No use-after-free in classical sense (pool is reset between operations)
- OOM returns NULL — check all `mem_alloc` return values
- Pool fragmentation is a concern for complex structures (EIP-712)

---

## Phase 4: Vulnerability Hunting — Multi-Category

### 4.1 Memory Safety

| Pattern                        | Where to look                                                     |
| ------------------------------ | ----------------------------------------------------------------- |
| **OOB read/write**             | RLP parsing, ABI decoding, plugin `provide_parameter`             |
| **Integer overflow/underflow** | Array length fields, counter decrements, `U4BE`/`U2BE`            |
| **Truncation**                 | `uint32_t → uint16_t`, `uint16_t → uint8_t` in length fields      |
| **Unaligned access**           | `*(uint16_t*)&data[offset]` — use byte-by-byte or `U2BE`          |
| **Stack overflow**             | Recursive descent (EIP-712 types, generic TX parser)              |
| **Buffer underrun**            | Decrement before zero-check (`--array_len` when `array_len == 0`) |

### 4.2 Clear-Signing Bypass (THE critical vuln class for wallets)

The attacker's goal is to make the user sign something **different from what's displayed**:

| Pattern                     | Description                                                    |
| --------------------------- | -------------------------------------------------------------- |
| **Hash/length mismatch**    | Displayed message length ≠ hashed length                       |
| **Truncated display**       | Only first N bytes shown, rest signed blindly                  |
| **Wrong address format**    | Hex instead of checksum, truncated BLS key                     |
| **Value overflow**          | uint256 wraps, displayed value < actual value                  |
| **Plugin result overwrite** | `result = OK` after error → display proceeds with corrupt data |
| **Proxy substitution**      | Name for implementation shown for proxy address                |
| **Missing fields**          | Critical fields (chainId, nonce, gas) not displayed            |
| **Blind signing enabled**   | Settings flag allows signing without full display              |

### 4.3 Cryptographic Misuse

| Pattern                          | Impact                                          |
| -------------------------------- | ----------------------------------------------- |
| **Key not cleared**              | Private key material in RAM after use           |
| **Deprecated THROW in crypto**   | Exception path leaks partial state              |
| **Wrong curve/derivation**       | Sign with wrong key                             |
| **Missing structure validation** | Sign attacker-controlled message without prefix |
| **Nonce reuse**                  | Deterministic nonce generation missing          |

### 4.4 APDU Protocol Violations

| Pattern                       | Impact                                                   |
| ----------------------------- | -------------------------------------------------------- |
| **Missing length validation** | `data[offset]` without checking `dataLength >= offset+1` |
| **State confusion**           | Handler doesn't check `appState` matches expected        |
| **Partial init**              | Error mid-flow leaves half-initialized global state      |
| **P1/P2 not validated**       | Unexpected values accepted silently                      |

### 4.5 Plugin-Specific Patterns

Plugins are high-value targets — they process untrusted calldata:

| Pattern                 | Impact                                          |
| ----------------------- | ----------------------------------------------- |
| **Selector collision**  | Plugin handles wrong function                   |
| **Array length trust**  | ABI array length taken at face value → OOB      |
| **State machine skip**  | Missing `next_param` enforcement                |
| **Result overwrite**    | `result = OK` unconditionally after switch/case |
| **Offset manipulation** | ABI offset points outside calldata              |

### 4.6 PKI / Certificate Handling

| Pattern                      | Impact                                                   |
| ---------------------------- | -------------------------------------------------------- |
| **Wrong usage constant**     | Feature accepts certificate meant for different purpose  |
| **Missing chain validation** | Self-signed cert accepted                                |
| **Usage conflation**         | Two features share same `CERTIFICATE_PUBLIC_KEY_USAGE_*` |

---

## Phase 5: APDU Reachability Verification

**This is the critical differentiator from generic code review.**

For EVERY finding rated HIGH or above, trace the COMPLETE path:

```
APDU IN (INS=0xXX, P1, P2, data)
  → dispatcher
    → handler function
      → intermediate calls
        → VULNERABLE CODE
```

### 5.1 Reachability Questions

1. **Which INS code reaches this code?** Follow the call graph backward.
2. **Is there a `library_main()` path only?** If yes → NOT exploitable (Exchange-only).
3. **Are there guards (PKI check, settings flag) before the vulnerable code?**
4. **What state must be set up first?** (prior APDUs needed to reach the state)
5. **Can the attacker actually provide the triggering input via APDU data?**

### 5.2 Reachability Classification

| Category                             | APDU Reachable?       | Exploitability             |
| ------------------------------------ | --------------------- | -------------------------- |
| Direct APDU handler, no guards       | **Yes**               | High                       |
| APDU handler behind PKI check        | **Yes** (reduced)     | Medium (needs cert)        |
| APDU handler behind settings flag    | **Yes** (conditional) | Medium (needs user enable) |
| Only via `library_main()` / Exchange | **No**                | Defense-in-depth only      |
| Requires OOM / impossible state      | **No**                | Theoretical only           |
| Guarded by upstream validation       | **No**                | False positive             |

---

## Phase 6: False-Positive Elimination

### 6.1 Common False-Positive Patterns in Ledger Apps

From experience, these are frequently flagged but NOT real issues:

| False Positive Pattern                     | Why it's not a bug                                         |
| ------------------------------------------ | ---------------------------------------------------------- |
| `APP_MEM_ALLOC` returns → "memory leak"    | SDK pool allocator, reset between operations               |
| `handle_check_address` OOB → "CRITICAL"    | Only callable from Exchange (trusted, Ledger-signed)       |
| RLP length field OOB → "overflow"          | Guarded by incremental `rlp_can_decode()` feed             |
| Recursive EIP-712 types → "stack overflow" | Cycle detection exists via membership check                |
| `shared_context` union → "type confusion"  | `appState` serves as discriminant                          |
| Swap flows missing validation → "bypass"   | Exchange app is trusted                                    |
| `CX_ASSERT` → "crash"                      | Deprecated pattern but intentional abort on crypto failure |
| Plugin `RESULT_ERROR` → "continues"        | Check upstream in caller (`eth_plugin_result_check`)       |

### 6.2 Verification Protocol

For EACH finding, before including in report:

1. **Read the actual source** — not just grep output or function signatures
2. **Check the caller** — what values can it actually pass?
3. **Check guards upstream** — is there a length check 3 lines above?
4. **Trace the state machine** — can this state actually be reached?
5. **Verify the trust model** — who controls this input?

### 6.3 Elimination Criteria

A finding is a **false positive** if ANY of:

- The triggering input is validated/bounded by caller before reaching vulnerable code
- The code path is unreachable from any APDU (only from trusted Exchange app)
- The state required is impossible to reach via normal or malicious APDU sequences
- The "vulnerability" results in **rejection** (not bypass) — feature broken, not security broken
- The allocated buffer is always large enough due to compile-time or SDK guarantees

---

## Phase 7: Exploitability Classification

### 7.1 Severity Levels (Ledger-specific)

| Level           | Criteria                                                                                                                                         | Examples                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------- |
| **🟥 CRITICAL** | Clear-signing bypass with no user interaction needed. User signs something materially different from what's displayed. Arbitrary code execution. | Hash/length desync, value overflow in display      |
| **🟧 HIGH**     | APDU-reachable bug that corrupts display or parsing, but requires specific conditions. State corruption. Logic error in signing flow.            | Integer truncation in msg length, plugin underflow |
| **🟨 WARNING**  | Code quality issue, defense-in-depth concern, or bug not reachable via APDU. Non-exploitable memory issue.                                       | OOB in Exchange-only path, deprecated patterns     |
| **ℹ️ INFO**     | Style, maintainability, or theoretical concern with no security impact.                                                                          | Magic numbers, dead code, over-allocation          |

### 7.2 Exploitability Factors

Rate each confirmed finding on:

- **Attack vector**: APDU (remote via host) vs library_main (trusted only)
- **Complexity**: Single APDU vs multi-step state setup
- **User interaction**: None (transparent) vs requires user approval of corrupt display
- **Impact**: What does the attacker gain? (key leak, wrong address, wrong amount, crash)

---

## Phase 8: PoC / Sanitizer Confirmation

### 8.1 ASan/UBSan Harness

For memory safety findings, write minimal C harnesses:

```c
// test_finding.c
#include "stubs.h"  // minimal SDK stubs
#include "../../src/path/to/target.c"  // include the source directly

int main(void) {
    // Set up minimal state to reach the vulnerable code
    // Call the function with triggering input
    // ASan will detect the OOB/overflow
    return 0;
}
```

Compile: `gcc -fsanitize=address,undefined -O0 -g test.c -o test && ./test`

### 8.2 Python APDU PoC (Ragger/Speculos)

For APDU-reachable findings, write a Ragger test that triggers the bug on Speculos:

```python
"""PoC: Trigger H1 — msg_length truncation via INS 0x08"""
from ragger.backend import SpeculosBackend

def test_msg_length_truncation(backend: SpeculosBackend):
    # Build the malicious APDU
    bip32_path = bytes.fromhex("058000002c8000003c800000000000000000000000")
    msg_length = (0x00010001).to_bytes(4, 'big')  # 65537 → truncated to 1
    message = b"A"  # single byte

    payload = bip32_path + msg_length + message

    # Send INS_SIGN_PERSONAL_MESSAGE, P1=0x00 (first chunk)
    rapdu = backend.exchange(cla=0xE0, ins=0x08, p1=0x00, p2=0x00, data=payload)
    # Observe behavior: hash prefix says "65537" but only 1 byte processed
```

### 8.3 Confirmation Requirements

| Severity | Confirmation needed                       |
| -------- | ----------------------------------------- |
| CRITICAL | Mandatory ASan PoC + APDU PoC on Speculos |
| HIGH     | ASan PoC OR APDU PoC (at least one)       |
| WARNING  | Source-level justification sufficient     |
| INFO     | Observation only                          |

---

## Phase 9: Report Generation

### 9.1 Report Structure

```markdown
# Security Review — [App Name] — Final Report

> **Date**: YYYY-MM-DD
> **Scope**: [files/LOC reviewed]
> **Method**: [phases completed]
> **Verdict**: PASS / FAIL (FAIL if any HIGH or CRITICAL)
> **False positives eliminated**: N/M

## 🟥 CRITICAL (N)

## 🟧 HIGH (N) — all APDU-reachable

## 🟨 WARNING (N)

## ℹ️ INFO (N)

## APDU Exploitability Table

| Finding | INS | Reachable? | Exploitability |

## False Positives Eliminated

| # | Original classification | Reason for elimination |

## Methodology
```

### 9.2 Per-Finding Template

```markdown
### HN. [Short title]

- **File**: [relative path with line link]
- **APDU**: `INS_XXX (0xNN)`, P1=, P2=
- **Exploitability**: High / Medium / Low
- **CWE**: CWE-NNN (Name)

**Description**: [What the bug is, with code snippet]

**PoC APDU**: [Hex bytes to trigger]

**Fix**: [Minimal code change]
```

### 9.3 Verdict Criteria

- **FAIL**: At least one CRITICAL or HIGH finding that is APDU-reachable
- **PASS with observations**: Only WARNING/INFO findings
- **PASS**: No findings (rare for any non-trivial app)

---

## Appendix A: Ledger-Specific CWE Mapping

| CWE                                 | Ledger Context                             |
| ----------------------------------- | ------------------------------------------ |
| CWE-120 (Buffer Overflow)           | RLP/ABI parsing without length check       |
| CWE-125 (OOB Read)                  | Plugin calldata access beyond bounds       |
| CWE-191 (Integer Underflow)         | Array counter decrement without zero check |
| CWE-681 (Incorrect Conversion)      | U4BE → uint16_t truncation                 |
| CWE-457 (Uninitialized)             | Plugin result not set on all paths         |
| CWE-476 (NULL Dereference)          | mem_alloc return unchecked                 |
| CWE-843 (Type Confusion)            | Union access without state check           |
| CWE-347 (Improper Verification)     | PKI usage constant wrong/shared            |
| CWE-345 (Insufficient Verification) | Display data ≠ signed data                 |

## Appendix B: Key Files to Always Review

| Path                                           | Why                                               |
| ---------------------------------------------- | ------------------------------------------------- |
| `src/main.c`                                   | APDU dispatcher — all entry points                |
| `src/apdu_constants.h`                         | INS codes, CLA                                    |
| `src/shared_context.h`                         | Global state, unions                              |
| `src/features/sign_tx/eth_ustream.c`           | RLP parser — most complex parsing                 |
| `src/features/sign_message/cmd_sign_message.c` | Message signing entry                             |
| `src/features/sign_message_eip712/`            | EIP-712 — complex state machine                   |
| `src/plugins/`                                 | All plugins — untrusted calldata handling         |
| `src/swap/`                                    | Exchange interface — trusted but defense-in-depth |
| `src/nbgl/`                                    | Display logic — clear-signing correctness         |
| `src/features/provide_*/`                      | Data provisioning — PKI checks                    |

## Appendix C: Docker Environment for PoC

```bash
# Build for sanitizers (host, not device — for harnesses only)
gcc -fsanitize=address,undefined -O0 -g -I../../src test_poc.c -o test_poc
./test_poc

# Full device test with Speculos
docker run --rm -v $(pwd):/app ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
  bash -c "source /opt/venv/bin/activate && \
           pip install -r tests/ragger/requirements.txt && \
           BOLOS_SDK=\$NANOX_SDK make -j && \
           pytest tests/ragger/ --device nanox -k test_poc"
```

## Appendix D: Common Secure Patterns (Expected in Good Code)

```c
// Length check BEFORE access
if (dataLength < offset + expected_size) {
    return APDU_RESPONSE_INVALID_DATA;
}

// Integer bounds check BEFORE truncation
uint32_t raw = U4BE(data, 0);
if (raw > UINT16_MAX) {
    return APDU_RESPONSE_INVALID_DATA;
}
ctx->length = (uint16_t)raw;

// Array counter check BEFORE decrement
if (context->array_len == 0) {
    context->next_param = NEXT_STATE;
    break;
}
--context->array_len;

// Plugin result on ALL paths
switch (msg->screenIndex) {
    case 0:
        if (error) { msg->result = ETH_PLUGIN_RESULT_ERROR; return; }
        msg->result = ETH_PLUGIN_RESULT_OK;
        break;
    default:
        msg->result = ETH_PLUGIN_RESULT_ERROR;
        break;
}
// NO unconditional result = OK after switch
```

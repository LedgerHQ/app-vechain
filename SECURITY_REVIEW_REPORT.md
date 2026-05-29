# Security Review — VeChain Ledger App — Final Report (rev. 2)

> **Date**: 2026-05-29
> **Scope**: `src/` and `common/` (everything compiled into `app.elf`); ledger SDK out of scope.
> **Method**: Phases 0–9 of `.claude/skills/security_review/SKILL.md`. Re-run after H1/H2 fixes.
> **Verdict**: **FAIL** — one CRITICAL APDU-reachable clear-signing bypass (C1) found in this rev. H1 and H2 from rev. 1 are now fixed and re-verified.
> **False positives eliminated**: 5 / 12 candidates (table at end).

This rev. delivers (a) regression check on the H1/H2 patches, (b) a deeper sweep on areas not covered in rev. 1: dispatcher state machine across `IO_ASYNCH_REPLY`, EIP-712 v0/v1 paths, uint256 helpers, dispatcher error-handling completeness. The new finding C1 is a different bug class from H1/H2 and was not detectable from any single handler in isolation — it is a property of the dispatcher.

---

## Summary

| ID | Severity | Status | INS reachable from | Title |
| -- | -------- | ------ | ------------------ | ----- |
| **C1** | 🟥 CRITICAL | **OPEN** | `0x04`, `0x08`, `0x09`, `0x0C` | Path substitution via APDU interleaving while UI is pending — clear-signing bypass |
| H1 | 🟧 HIGH | ✅ FIXED | `0x08`, `0x09` | OOB read + `uint16_t` underflow on missing 4-byte length — re-verified PASS |
| H2 | 🟧 HIGH | ✅ FIXED | `0x04` | Global-buffer overflow of `fullAmount[50]` / `maxFee[60]` — re-verified PASS |
| W1 | 🟨 WARN  | OPEN | `0x04` | Multi-clause #2+ written through dangling stack pointer to `tmpContent` |
| W2 | 🟨 WARN  | OPEN | `0x04` | Only clause #1 rendered; clauses 2..N signed silently |
| W3 | 🟨 WARN  | ✅ FIXED-as-side-effect | `0x09` | Empty-document signing path — closed by H1 fix |
| I1 | ℹ️ INFO  | partly fixed | all | UB: `byte << 24` on `int`-promoted operands — fixed in `handlers.c`, still present in `vetUtils.c` and `crypto.c` |
| I2 | ℹ️ INFO  | OPEN | EIP-712 v1 | `BYTES_FIX` and `BYTES_DYN` share the `"bytes"` typename |

---

## 🟥 CRITICAL — C1. Path substitution via APDU interleaving while UI is pending

### Finding

The dispatcher in `src/handlers.c::handleApdu` does **not** maintain an `appState`-style discriminant guarding against new sign/parse APDUs while a previous flow is waiting on user UI confirmation (`IO_ASYNCH_REPLY`). Compare upstream `LedgerHQ/app-ethereum`:

```c
// src/shared_context.h
enum {
    APP_STATE_IDLE,
    APP_STATE_SIGNING_TX,
    APP_STATE_SIGNING_MESSAGE,
    APP_STATE_SIGNING_EIP712,
    APP_STATE_SIGNING_EIP7702,
};
extern uint8_t appState;
void reset_app_context(void);
```

The Ledger SDK explicitly delivers new APDUs to the app even while `io_exchange()` is parked on `IO_ASYNCH_REPLY` (verified in `nanos-secure-sdk/src/os_io_seproxyhal.c:1462` — *"An apdu has been received asynchroneously."*). The official I/O documentation only describes how the **stalled response** is held back; nothing in the SDK keeps the host from issuing further commands.

In this app, the four flows that set `IO_ASYNCH_REPLY` (`handleSign`, `handleSignPersonalMessage`, `handleSignCertificate`, `eip712_handle_sign_v0`/`handle_eip712_sign`) all read `tmpCtx.transactionContext.{bip32Path, pathLength}` from the **shared union** at signing time. That union is freely re-written by any subsequent `INS_SIGN*` `P1=FIRST` APDU, **without touching the hash region** (offsets 44..75) when the second flow doesn't reach `CX_LAST`.

### The exploit, step by step

1. **Set up the legitimate flow.**
   Host sends `INS_SIGN P1=FIRST/MORE` for a benign tx#1 to path #1 (`m/44'/818'/0'/0/0`). The device parses the RLP, finalises the blake2b → `tmpCtx.transactionContext.hash = H_tx1`, formats the review strings (`fullAmount`, `maxFee`, `fullAddress`), and calls `ui_display_action_sign_tx_flow()` which sets `*flags |= IO_ASYNCH_REPLY` and returns. `app_main` loops back into `io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, …)`.
2. **Substitute the path while the user is reading the screen.**
   Host now sends `INS_SIGN P1=FIRST` again — this time only the BIP32 path bytes for path #2 (e.g. `m/44'/818'/1'/0/0`) plus a tiny RLP fragment that does **not** complete parsing. `handleSign` enters the `if (p1 == P1_FIRST)` branch:

   ```209:252:src/handlers.c
   void handleSign(uint8_t p1,
                   uint8_t p2,
                   uint8_t workBuffer[static 255],
                   uint16_t dataLength,
                   volatile uint32_t flags[static 1],
                   volatile uint32_t tx[static 1]) {
       UNUSED(tx);
       uint8_t tx_type;
       parserStatus_e txResult;
       uint32_t i;
       uint8_t decimals = DECIMALS_VET;
       uint8_t *ticker = (uint8_t *) TICKER_VET;

       if (p1 == P1_FIRST) {
           memset(&clausesContent, 0, sizeof(clausesContent));
           memset(&clauseContent, 0, sizeof(clauseContent));

           // Extract and parse the BIP32 path
           parseBip32Path(&workBuffer,
                          &dataLength,
                          &tmpCtx.transactionContext.pathLength,
                          tmpCtx.transactionContext.bip32Path);
           dataPresent = false;
           initTx(&displayContext.txFullContext.txContext,
                  &tmpContent.txContent,
                  &displayContext.txFullContext.clausesContext,
                  &clausesContent,
                  &displayContext.txFullContext.clauseContext,
                  &clauseContent,
                  &blake2b,
                  NULL);
   ```

   `parseBip32Path` writes pathLength + bip32Path into `tmpCtx.transactionContext`. The struct layout puts these at offsets 0..43; the `hash[32]` field starts at offset 44 and is **not touched**. `processTx` returns `USTREAM_PROCESSING` (incomplete), the handler `THROW(SWO_SUCCESS)` and returns. The UI is unchanged: `fullAmount`, `maxFee`, `fullAddress` are globals untouched by `handleSign FIRST` for tx#2.

3. **User approves on screen.**
   `io_seproxyhal_touch_tx_ok()` (the callback wired up in step 1) fires:

   ```109:130:src/ui/ui_callback.c
   unsigned int io_seproxyhal_touch_tx_ok() {
       uint32_t tx = 0;
       uint8_t sig_r[SECP256K1_RS_LEN];
       uint8_t sig_s[SECP256K1_RS_LEN];
       uint8_t v = 0;
       int error;

       io_seproxyhal_io_heartbeat();
       // Sign the message
       error = crypto_sign_message(sig_r, sig_s, &v);
   ```

   `crypto_sign_message` reads the hash from `tmpCtx.messageSigningContext.hash` (= `H_tx1`, unchanged) and the path from `tmpCtx.transactionContext.{bip32Path, pathLength}` (= path #2, the attacker's). Result: `sig = ECDSA(H_tx1, derive(path #2))`.

### Impact

The signed transaction body is the benign tx#1 the user reviewed, but the recovered `from` address is account #2 — an account the user owns but did **not** intend to use. Practical scenarios:

- **Wrong-account fund drain**: user has VET in both account #0 and account #1 of the same seed. They review and approve a benign-looking transfer "from #0 to Bob". The device returns a signature recovering to account #1, and account #1 funds Bob.
- **Different chain** (`44'/1'` vs `44'/818'`): same trick across the test/main-net split.
- **Coexistence with EIP-712**: same path-substitution holds against the EIP-712 v0/v1 signing flows because they both read `tmpCtx.transactionContext.bip32Path` at the callback time; `handle_eip712_sign` even goes a step further and overwrites the hash too, enabling the inverse trick (sign EIP-712 hash with account #0's key while the user is reviewing the tx#1 UI).
- **Failed second flow doesn't help the user**: a `THROW(SWO_INCORRECT_DATA)` mid-`handleSign FIRST` (e.g. malformed RLP) wipes `displayContext` but does **not** wipe `tmpCtx`, so the path-substitution survives. The benign tx#1 review remains on screen because `fullAmount`/`maxFee`/`fullAddress` are not in `displayContext`.

### Reproducibility

ASan/UBSan harness — same memory layout as `tmpCtx_t` from `src/handlers.h` — confirms the bug:

```
$ ./poc_state_confusion
[+] Step 1 complete (tx#1 review pending in UI)
  legit path: m/44'/818'/0'/0/0
  H_tx1 set      = 10111213...
[!] Step 3 — at signing time:
  path used  : m/44'/818'/1'/0/0
  hash signed   = 10111213...

VULNERABLE: signed legit H_tx1 with attacker's path.
User reviewed account 0; device used account 1's key.
```

A device-level reproducer for Speculos is straightforward (sketch):

```python
# tests/test_state_confusion_poc.py — RUN ONLY ON SPECULOS
from ragger.backend import SpeculosBackend
from vechain_client import VechainClient, InsType
from ragger.bip import pack_derivation_path

def test_path_substitution(scenario_navigator):
    backend = scenario_navigator.backend
    client  = VechainClient(backend)

    legit_path    = "m/44'/818'/0'/0/0"
    attacker_path = "m/44'/818'/1'/0/0"

    # 1) Legit handleSign FIRST + MORE for tx#1 (use existing helper)
    benign_tx = ...    # legit RLP
    with client.sign_tx(path=legit_path, transaction=benign_tx):
        # 2) UI is now pending. Send INS_SIGN FIRST again with attacker path.
        backend.exchange(cla=0xE0,
                         ins=InsType.INS_SIGN,
                         p1=0x00,           # FIRST
                         p2=0x00,
                         data=pack_derivation_path(attacker_path) + b"\xc0")  # empty list
        # 3) User approves on screen.
        scenario_navigator.review_approve()

    rapdu = client.get_async_response()
    # 4) Recover address from the signature; assert it is the attacker_path
    #    address, not the legit_path one.
    addr = recover_address(rapdu.data, blake2b256(benign_tx))
    assert addr == derive_address(attacker_path)
```

### Recommended fix (sketch)

Add an `appState` discriminant and reset/refuse on cross-flow entries. Minimal patch:

```c
/* src/handlers.h */
typedef enum {
    APP_STATE_IDLE = 0,
    APP_STATE_SIGNING_TX,
    APP_STATE_SIGNING_MESSAGE,
    APP_STATE_SIGNING_CERTIFICATE,
    APP_STATE_SIGNING_EIP712,
    APP_STATE_GET_PUBKEY,
} app_state_e;
extern volatile app_state_e appState;
void reset_app_context(void);

/* src/handlers.c */
volatile app_state_e appState = APP_STATE_IDLE;

void reset_app_context(void) {
    explicit_bzero(&tmpCtx,         sizeof(tmpCtx));
    explicit_bzero(&tmpContent,     sizeof(tmpContent));
    explicit_bzero(&clausesContent, sizeof(clausesContent));
    explicit_bzero(&clauseContent,  sizeof(clauseContent));
    explicit_bzero(&displayContext, sizeof(displayContext));
    explicit_bzero(&blake2b,        sizeof(blake2b));
    explicit_bzero((void *) fullAddress, sizeof(fullAddress));
    explicit_bzero((void *) fullAmount,  sizeof(fullAmount));
    explicit_bzero((void *) maxFee,      sizeof(maxFee));
    appState = APP_STATE_IDLE;
}
```

Then at the top of every signing handler, refuse cross-flow reentry, and reset on legitimate fresh start:

```c
void handleSign(...) {
    if (p1 == P1_FIRST) {
        if (appState != APP_STATE_IDLE && appState != APP_STATE_SIGNING_TX) {
            reset_app_context();
        }
        appState = APP_STATE_SIGNING_TX;
    } else {
        if (appState != APP_STATE_SIGNING_TX) {
            THROW(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        }
    }
    /* … existing body … */
}
```

Set `appState = APP_STATE_IDLE` from the `*_ok` and `*_cancel` UI callbacks (and from `CATCH_OTHER`). Apply the same pattern to `handleSignPersonalMessage`, `handleSignCertificate`, EIP-712 v0/v1 sign, and `handleGetPublicKey`. Crucially, **don't** allow `INS_SIGN_*` `P1_FIRST` while another sign flow is in `APP_STATE_SIGNING_*` waiting on UI — refuse with `SWO_SECURITY_CONDITION_NOT_SATISFIED` until the user dismisses the pending review.

This mirrors what `app-ethereum` does and what every Ledger app SHOULD do.

---

## 🟧 HIGH — H1, H2 (FIXED, re-verified)

### H1. `uint16_t` underflow on the 4-byte length read in `handleSignPersonalMessage` and `handleSignCertificate`

**Status**: ✅ **FIXED** — `src/handlers.c` 581 (`handleSignPersonalMessage` `dataLength < 4`) and 462 (`handleSignCertificate` `dataLength < 5` to also enforce the `'{'` byte). The U4BE composition was rewritten with explicit `(uint32_t)` casts to avoid the I1 UB.

**Re-verification**: `poc_underflow_fixed.c` ASan + UBSan, exit code 0:

```
PASS: patched handler rejected with SWO_INCORRECT_DATA (no OOB read, no underflow)
```

### H2. Global-buffer overflow of `fullAmount[50]` / `maxFee[60]` from a 32-byte clause `value`

**Status**: ✅ **FIXED** — `common/vetDisplay.{c,h}` now expose capacity-aware `bool`-returning functions; `amountToDisplayString` refuses to write when `tickerLength + adjustedAmountLength + 1 > displayStringSize`. `src/handlers.c` 326-355 passes `sizeof(fullAmount)` / `sizeof(maxFee)` and `THROW(SWO_INCORRECT_DATA)` on refusal. No other callers exist (verified by Grep).

**Re-verification**: `poc_amount_overflow_fixed.c` ASan + UBSan, exit code 0:

```
PASS: patched routine rejected (would overflow), fullAmount intact = ''
```

---

## 🟨 WARNING (carry-over)

- **W1**. `processClausesInternal` writes clause #2+ data through a stack pointer (`tmpContent`) whose lifetime ends with the enclosing call. Same recommendation as rev. 1: drop the pseudo-temporary and make all clauses share `firstClause` (the global), since only clause #1 is rendered (W2). Unchanged.
- **W2**. Only clause #1 is shown on the review screen; clauses 2..N are signed silently (gated behind `multiClauseAllowed`). Unchanged.
- **W3**. Empty-document signing reachable when post-LC bytes happen to be `{ … }` — **closed as a side-effect** of the H1 patch (the new `dataLength < 5` check in `handleSignCertificate` makes the OOB read unreachable).

## ℹ️ INFO

- **I1**. The U4BE composition UB (`byte << 24` on `int`-promoted operands) was fixed in `src/handlers.c`. Two leftover sites still need the same cast cleanup:
  - `src/crypto.c:241` (`parseBip32Path` per-component composition)
  - `common/vetUtils.c:84-91` and `108-115` (`rlpDecodeLength` 0xb8..0xbb / 0xf8..0xfb cases)
- **I2**. Unchanged from rev. 1.

---

## APDU Exploitability Table

| Finding | INS | P1 | P2 | Setting required | Reachable | Exploitability | Fix |
| ------- | --- | -- | -- | ---------------- | --------- | -------------- | --- |
| **C1** | `0x04`, `0x08`, `0x09`, `0x0C` | `0x00`/`0x80` | varies | **none** | yes (multi-APDU race) | **HIGH — produces a wrong-account signature for a benign-looking review** | OPEN — see "Recommended fix" above |
| H1 (msg)  | `0x08` | `0x00` | `0x00` | none | yes | High → none | ✅ |
| H1 (cert) | `0x09` | `0x00` | `0x00` | none | yes | High → none | ✅ |
| H2        | `0x04` | `0x00` | `0x00` | none (default-on) | yes | High → none | ✅ |
| W1        | `0x04` | any   | `0x00` | `multiClauseAllowed` | yes | Warning | OPEN |
| W2        | `0x04` | any   | `0x00` | `multiClauseAllowed` | yes | Warning | OPEN |

---

## False Positives Eliminated

| # | Original suspicion | Reason eliminated |
| - | ------------------ | ----------------- |
| 1 | `parseBip32Path` reads `(*pWorkBuffer)[0]` before checking `*dataLength ≥ 1` | Self-correcting via `*dataLength < 1 + *pathLength * 4` check (rev. 1) |
| 2 | `tmpCtx_t` union "type confusion" | Field offsets aligned across variants; dispatcher single-threaded (rev. 1) |
| 3 | `tostring256` writes 78+ chars into 100-byte buffer | Bounded by `offset > outLength - 1` guard (rev. 1) |
| 4 | `set_struct_field` cursor arithmetic | All accesses guarded by `cursor + name_len > length` (rev. 1) |
| 5 | `divmod256` division by zero | All call sites use a constant non-zero divisor (`MAX_GAS_COEF=0xFF`, base ∈ [2,16]) — verified by Grep on call sites |
| – | `path_update` recursion via cyclic struct definitions | Bounded by `MAX_PATH_DEPTH=16`, `path_depth_list_push()` returns false past the limit |

---

## Methodology — what changed since rev. 1

- Re-ran the dispatcher / state-machine sweep that was deferred in rev. 1, with a focused look at every `IO_ASYNCH_REPLY` site and what UI callbacks read from globals at signing time. This produced **C1**.
- Re-ran reachability (Phase 5) on H1/H2 against the patched code; both rejected at the new guards in the relevant ASan/UBSan harnesses.
- Audited `divmod256` for division-by-zero (call-site constant divisors only, FP eliminated) and `path_update` for cycle / unbounded recursion (bounded by `MAX_PATH_DEPTH`, FP eliminated).
- Confirmed Ledger SDK semantics for `IO_ASYNCH_REPLY` from `nanos-secure-sdk/src/os_io_seproxyhal.c` and the official I/O documentation: the SDK delivers asynchronous APDUs to the app while the response to the previous APDU is held back. This is the SDK contract C1 violates.

PoC harnesses live under `/tmp/vechain_poc/`:

```bash
cd /tmp/vechain_poc
gcc -fsanitize=address,undefined -O0 -g poc_underflow.c           -o poc_underflow            # H1 — pre-fix repro (still in tree)
gcc -fsanitize=address,undefined -O0 -g poc_amount_overflow.c     -o poc_amount_overflow      # H2 — pre-fix repro
gcc -fsanitize=address,undefined -O0 -g poc_underflow_fixed.c     -o poc_underflow_fixed      # H1 — post-fix verification
gcc -fsanitize=address,undefined -O0 -g poc_amount_overflow_fixed.c -o poc_amount_overflow_fixed  # H2 — post-fix verification
gcc -fsanitize=address,undefined -O0 -g poc_state_confusion.c     -o poc_state_confusion      # C1 — repro of the path-substitution
```

---

## Recommended next actions

1. **Implement the `appState` discriminant** described in the C1 fix sketch. This is a non-trivial but well-bounded change — every signing handler gets an entry guard and the UI callbacks must reset `appState` to `APP_STATE_IDLE` on both approve and reject. Add a Ragger-on-Speculos test (sketch above) so the regression doesn't slip back in.
2. **Address W1 / W2** by either rendering all clauses in the review or rejecting multi-clause TXs entirely. Today, "multi-clause allowed" silently means "blind-sign clauses 2..N".
3. **Apply I1 cast cleanup** in the two remaining sites (`src/crypto.c`, `common/vetUtils.c`).

#pragma once

unsigned int io_seproxyhal_touch_exit();
unsigned int io_seproxyhal_touch_tx_ok();
unsigned int io_seproxyhal_touch_address_ok();
unsigned int io_seproxyhal_touch_cancel();

/**
 * @brief Sign the precomputed EIP-712 digest stored in
 *        tmpCtx.transactionContext.hash and reply with r||s||v.
 *
 * Used by both the v0 (blind sign) and v1 (clear sign) review flows. Unlike
 * io_seproxyhal_touch_tx_ok() this does not rely on the tmpCtx union
 * aliasing between transactionContext and messageSigningContext.
 */
unsigned int io_seproxyhal_touch_eip712_ok();
